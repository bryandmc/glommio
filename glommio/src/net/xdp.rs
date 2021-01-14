//!
//! # AF_XDP socket implementation
//!
//! [AF_XDP kernel documentation](https://www.kernel.org/doc/html/v4.18/networkingTO/af_xdp.html)

use core::slice;
use std::{
    cell::{RefCell, RefMut},
    cmp,
    collections::VecDeque,
    convert::TryInto,
    ffi::CString,
    io,
    ops::{Index, IndexMut},
    rc::{Rc, Weak},
    slice::SliceIndex,
};
use std::{
    os::unix::prelude::{AsRawFd, IntoRawFd, RawFd},
    ptr,
};

use bitflags::bitflags;
use iou::PollFlags;
use libbpf_sys::{
    xsk_ring_cons, xsk_ring_prod, xsk_socket, xsk_socket_config, xsk_umem, xsk_umem_config,
    XDP_FLAGS_UPDATE_IF_NOEXIST, XDP_USE_NEED_WAKEUP, XSK_RING_CONS__DEFAULT_NUM_DESCS,
    XSK_RING_PROD__DEFAULT_NUM_DESCS, XSK_UMEM__DEFAULT_FLAGS, XSK_UMEM__DEFAULT_FRAME_HEADROOM,
    XSK_UMEM__DEFAULT_FRAME_SIZE,
};
use libc::{MAP_ANONYMOUS, MAP_FAILED, MAP_HUGETLB, MAP_PRIVATE, PROT_READ, PROT_WRITE};

use crate::{error::ReactorErrorKind, parking::Reactor, sys::DmaBuffer, GlommioError, Local};

type Result<T> = std::result::Result<T, GlommioError<()>>;

/// TODO: make this all adjustable / derive-able / whatever
const PAGE_SIZE: u32 = 4096;

const DEFAULT_BATCH_RECV: u64 = 10;

const DEFAULT_BATCH_FILL: u64 = 500;

bitflags! {
    pub struct XdpFlags: u32 {
        const XDP_FLAGS_UPDATE_IF_NOEXIST = libbpf_sys::XDP_FLAGS_UPDATE_IF_NOEXIST;
        const XDP_FLAGS_SKB_MODE = libbpf_sys::XDP_FLAGS_SKB_MODE;
        const XDP_FLAGS_DRV_MODE = libbpf_sys::XDP_FLAGS_DRV_MODE;
        const XDP_FLAGS_HW_MODE = libbpf_sys::XDP_FLAGS_HW_MODE;
        const XDP_FLAGS_REPLACE = libbpf_sys::XDP_FLAGS_REPLACE;
    }
}

bitflags! {
    pub struct XskBindFlags: u16 {
        const XDP_SHARED_UMEM = libbpf_sys::XDP_SHARED_UMEM as u16;
        const XDP_COPY = libbpf_sys::XDP_COPY as u16;
        const XDP_ZEROCOPY = libbpf_sys::XDP_ZEROCOPY as u16;
        const XDP_USE_NEED_WAKEUP = libbpf_sys::XDP_USE_NEED_WAKEUP as u16;
    }
}

/// # AF_XDP socket
///
/// AF_XDP socket for delivering layer 2 frames directly to userspace from very early in
/// the kernel networking stack. So early, it's basically in the drivers code directly
/// and can even operate in a `zero-copy` fashion.
///
/// It operates very differently from a standard socket type. In fact it works a lot more like
/// memory-mapped AF_PACKET capture in that it invovles sharing memory between userspace and the
/// kernel. It does this by passing descriptors back and forth between kernel and userspace over
/// ring-buffers.
///
///
/// # Examples
///
/// ```
///
/// ```
#[derive(Debug)]
pub struct XdpSocket {
    socket: Box<xsk_socket>,
    rx_queue: Box<xsk_ring_cons>,
    tx_queue: Box<xsk_ring_prod>,
    fd: RawFd,
    config: XskSocketConfig,
    umem: Rc<RefCell<Umem>>,
    reactor: Weak<Reactor>,
}

impl XdpSocket {
    /// # create AF_XDP socket
    ///
    /// Delivers L2 frames directly to userspace, depending on settings, directly from the NIC
    /// driver hook. Other times (non-zero-copy mode) by copying it to userspace. This is less
    /// efficient but more widely compatible and works even using the `generic` XDP. This happens
    /// after the allocation of the `skbuff` but uses a common interface, and functions as a good
    /// fallback, that is still generally faster than other methods that are available.
    ///
    /// TODO: Should we just embed the umem in this and pass it config through here?
    /// .... It's notably less flexible, and would be a little strange but might be worth doing.
    ///
    pub fn new(config: XskSocketConfig, umem: Rc<RefCell<Umem>>) -> Result<XdpSocket> {
        let cfg = xsk_socket_config {
            rx_size: config.rx_size,
            tx_size: config.tx_size,
            xdp_flags: config.xdp_flags,
            bind_flags: config.bind_flags,
            libbpf_flags: config.libbpf_flags,
        };
        let tx: Box<xsk_ring_prod> = Default::default();
        let rx: Box<xsk_ring_cons> = Default::default();
        let mut xsk: *mut xsk_socket = std::ptr::null_mut();
        let xsk_ptr: *mut *mut xsk_socket = &mut xsk;
        let if_name_c = CString::new(config.if_name).unwrap();
        let umem_ptr = unsafe { umem.borrow_mut().inner_umem_mut_ptr() };
        let rx_ptr = Box::into_raw(rx);
        let tx_ptr = Box::into_raw(tx);

        let err = unsafe {
            libbpf_sys::xsk_socket__create(
                xsk_ptr,
                if_name_c.as_ptr(),
                config.queue,
                umem_ptr,
                rx_ptr,
                tx_ptr,
                &cfg,
            )
        };
        if err != 0 {
            return Err(io::Error::last_os_error().into());
        }

        let fd = unsafe { libbpf_sys::xsk_socket__fd(xsk) };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }

        unsafe {
            Ok(XdpSocket {
                socket: Box::from_raw(xsk),
                rx_queue: Box::from_raw(rx_ptr),
                tx_queue: Box::from_raw(tx_ptr),
                fd: fd.into_raw_fd(),
                config,
                umem,
                reactor: Rc::downgrade(&Local::get_reactor()),
            })
        }
    }

    /// Consumes descriptors from the RX queue
    fn pop_rx(&mut self, descriptors: &mut [FrameRef]) -> usize {
        let nb = descriptors.len().try_into().unwrap();
        if nb == 0 {
            return 0;
        }
        let mut idx = 0;
        unsafe {
            let count = libbpf_sys::_xsk_ring_cons__peek(self.rx_queue.as_mut(), nb, &mut idx);
            if count == 0 {
                return 0;
            }
            let mut recv_descriptors = vec![];
            for desc in descriptors {
                let rx_descriptor =
                    libbpf_sys::_xsk_ring_cons__rx_desc(self.rx_queue.as_ref(), idx);
                let frame = FrameRef {
                    addr: (*rx_descriptor).addr,
                    len: (*rx_descriptor).len,
                    options: (*rx_descriptor).options,
                };
                recv_descriptors.push(frame);
                desc.addr = (*rx_descriptor).addr;
                desc.len = (*rx_descriptor).len;
                desc.options = (*rx_descriptor).options;
                idx += 1;
            }
            libbpf_sys::_xsk_ring_cons__release(self.rx_queue.as_mut(), count);
            count.try_into().unwrap()
        }
    }

    /// Consumes descriptors from the RX queue
    fn pop_rx_owned(&mut self, batch: u64) -> Vec<FrameRef> {
        let mut idx = 0;
        let mut recv_descriptors = vec![];
        unsafe {
            let count = libbpf_sys::_xsk_ring_cons__peek(self.rx_queue.as_mut(), batch, &mut idx);
            println!("There are {} RX available..", count);
            if count == 0 {
                return recv_descriptors;
            }
            let actual_nb = cmp::min(count, batch) as u32;
            for desc in 0..actual_nb {
                let rx_descriptor =
                    libbpf_sys::_xsk_ring_cons__rx_desc(self.rx_queue.as_ref(), idx);
                let frame = (*rx_descriptor).into();
                dbg!((desc, idx, frame));
                recv_descriptors.push(frame);
                idx += 1;
            }
            libbpf_sys::_xsk_ring_cons__release(self.rx_queue.as_mut(), count);
        }
        recv_descriptors
    }

    fn pop_completion(&mut self, descriptors: &mut [FrameRef]) -> usize {
        let mut umem = self.umem.borrow_mut();
        umem.pop_completion(descriptors)
    }

    /// Adds descriptors to the TX queue
    fn push_tx(&mut self, descriptors: &[FrameRef]) -> usize {
        let nb = descriptors.len().try_into().unwrap();
        if nb == 0 {
            return 0;
        }
        let mut idx = 0;
        unsafe {
            let count = libbpf_sys::_xsk_ring_prod__reserve(self.tx_queue.as_mut(), nb, &mut idx);
            if count == 0 {
                return 0;
            }
            for desc in descriptors {
                let x = libbpf_sys::_xsk_ring_prod__tx_desc(self.tx_queue.as_mut(), idx);
                (*x).addr = desc.addr;
                (*x).len = desc.len;
                (*x).options = desc.options;
                idx += 1;
            }
            libbpf_sys::_xsk_ring_prod__submit(self.tx_queue.as_mut(), count);
            count.try_into().unwrap()
        }
    }

    fn push_fill(&mut self, descriptors: &[FrameRef], umem: &mut RefMut<'_, Umem>) -> usize {
        // let mut umem = self.umem.borrow_mut();
        umem.push_fill(descriptors)
    }

    pub fn fill_descriptors(&mut self, umem: Rc<RefCell<Umem>>) -> usize {
        let mut umem = umem.borrow_mut();
        let free_list = &mut umem.free_list;
        let descriptors: Vec<_> = if free_list.len() > 50 {
            free_list.drain(..DEFAULT_BATCH_FILL as usize).collect()
        } else {
            free_list.drain(..).collect()
        };
        let amt = self.push_fill(&descriptors[..], &mut umem);

        if amt < descriptors.len() {
            for desc in descriptors[amt..].iter().rev() {
                umem.free_list.push_front(*desc);
            }
        }
        amt
    }

    /// Receive frames from the socket.
    /// TODO: finish handling this..
    pub async fn recv(&mut self) -> Result<Vec<FrameBuf>> {
        let umem = self.umem.clone();
        // let filled = self.fill_descriptors(umem.clone());

        // println!("Filled {} descriptors into queue...", filled);
        match self.try_recv(DEFAULT_BATCH_RECV) {
            Some(frames) => {
                println!("Doing sync path!");
                let result: Vec<_> = frames
                    .into_iter()
                    .map(move |frame| frame.get_buffer(umem.clone()))
                    .collect();
                return Ok(result);
            }
            None => {
                // do async stuff here..
                println!("Doing async path!");
                let source = self
                    .reactor
                    .upgrade()
                    .ok_or(GlommioError::ReactorError(
                        ReactorErrorKind::ReactorNotFound,
                    ))?
                    .poll(self.fd.as_raw_fd(), PollFlags::POLLIN);

                let fd = source.collect_rw().await?;
                if let Some(frames) = self.try_recv(DEFAULT_BATCH_RECV) {
                    let result: Vec<_> = frames
                        .into_iter()
                        .map(move |frame| frame.get_buffer(umem.clone()))
                        .collect();
                    return Ok(result);
                }
            }
        }

        Ok(vec![])
    }

    fn try_recv(&mut self, batch: u64) -> Option<Vec<FrameRef>> {
        let umem = self.umem.clone();
        let available = umem.borrow_mut().fill_available();
        if available > 0 {
            // do some reads now
            let read_frames = self.pop_rx_owned(batch);
            if read_frames.is_empty() {
                return None;
            }
            Some(read_frames)
        } else {
            None
        }
    }
}

impl From<libbpf_sys::xdp_desc> for FrameRef {
    fn from(desc: libbpf_sys::xdp_desc) -> Self {
        FrameRef {
            addr: desc.addr,
            len: desc.len,
            options: desc.options,
        }
    }
}

impl From<FrameRef> for libbpf_sys::xdp_desc {
    fn from(frame: FrameRef) -> Self {
        libbpf_sys::xdp_desc {
            addr: frame.addr,
            len: frame.len,
            options: frame.options,
        }
    }
}

/// # UMEM memory region
///
/// UMEM memory for use with AF_XDP socket. Creating this pre-allocated region of memory is required
/// to use AF_XDP. This will be the only pool of memory frames will be written to and shared between
/// the kernel and userspace. This is done by passing ownership back and forth using various queue's.
///
/// The main ingredients to this are:
///   - The actual mmap'd memory region
///   - The `Fill` queue which is used for passing memory to the kernel for receiving frames
///   - The `Completion` queue which is used for regaining memory from the kernel after transmitting
///     packets.
///
/// *Note*: The actual sending and receiving is signalled using the Tx and Rx queues which live with
/// the actual socket structure.
///
/// # Examples
///
/// ```
///
/// ```
#[derive(Debug)]
pub struct Umem {
    umem: Box<xsk_umem>,
    fill_queue: Box<xsk_ring_prod>,
    completion_queue: Box<xsk_ring_cons>,
    memory: MemoryRegion,
    free_list: VecDeque<FrameRef>,
    frames: u32,
    frame_size: u32,
    fd: RawFd,
}

impl Umem {
    /// Create a new UMEM memory region
    ///
    pub fn new(num_descriptors: u32, config: UmemConfig) -> Result<Umem> {
        let mut memory_region = MemoryRegion::new(PAGE_SIZE * num_descriptors, false)?;

        // Unsafe because this requires us to essentially create multiple mutable aliases to the same thing,
        // which is usually frowned upon by the compiler/optimizer and could cause problems but we have
        // no other choice when the 2nd mutable alias is the kernel and we are required to keep access
        // to the memory for our own use. The invariants are kept solely by use of the 4 queues.
        let mem_ptr = unsafe { memory_region.as_mut_ptr() };

        // Create empty producer and consume structures for the fill and completion queues.
        let fq: Box<xsk_ring_prod> = Default::default();
        let cq: Box<xsk_ring_cons> = Default::default();

        let ffi_config: *const _ = &config.into();
        let mut umem: *mut xsk_umem = ptr::null_mut();
        let umem_ptr: *mut *mut xsk_umem = &mut umem;
        let size = num_descriptors as u64 * 4096;
        let fq_ptr = Box::into_raw(fq);
        let cq_ptr = Box::into_raw(cq);

        // Create the actual UMEM
        let err = unsafe {
            libbpf_sys::xsk_umem__create(umem_ptr, mem_ptr, size, fq_ptr, cq_ptr, ffi_config)
        };
        if err != 0 {
            return Err(io::Error::last_os_error().into());
        }
        let umem_box = unsafe { Box::from_raw(umem) };

        // Get the file desrcriptor of the umem
        let fd = unsafe { libbpf_sys::xsk_umem__fd(umem_box.as_ref()) };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }

        let mut descriptors: VecDeque<FrameRef> =
            VecDeque::with_capacity(num_descriptors.try_into()?);
        for i in 0..num_descriptors {
            descriptors.push_back(FrameRef {
                addr: (i as u64) * (config.frame_size as u64),
                len: 0,
                options: 0,
            });
        }

        unsafe {
            Ok(Umem {
                umem: umem_box,
                fill_queue: Box::from_raw(fq_ptr),
                completion_queue: Box::from_raw(cq_ptr),
                memory: memory_region,
                frames: num_descriptors,
                frame_size: PAGE_SIZE,
                fd: fd.into_raw_fd(),
                free_list: descriptors,
            })
        }
    }

    /// Get mutable pointer to inner `xsk_umem` struct.
    ///
    /// # Safety
    ///
    /// This method is used only for getting a mutable pointer to the inner `xsk_uem`
    /// struct which is used for creating an xdp socket. It should not be used for other
    /// reasons.
    unsafe fn inner_umem_mut_ptr(&mut self) -> *mut xsk_umem {
        self.umem.as_mut()
    }

    pub(crate) fn fill_used(&mut self) -> usize {
        self.fill_queue.size as usize
            - unsafe { libbpf_sys::_xsk_prod_nb_free(self.fill_queue.as_mut(), 1) as usize }
    }

    pub(crate) fn fill_available(&mut self) -> usize {
        unsafe { libbpf_sys::_xsk_prod_nb_free(self.fill_queue.as_mut(), 1) as usize }
    }

    pub(crate) fn completions_ready(&mut self) -> usize {
        unsafe { libbpf_sys::_xsk_cons_nb_avail(self.completion_queue.as_mut(), 1) as usize }
    }

    pub(crate) fn pop_completion(&mut self, descriptors: &mut [FrameRef]) -> usize {
        let nb = descriptors.len().try_into().unwrap();
        let mut idx = 0;
        let count = unsafe {
            libbpf_sys::_xsk_ring_cons__peek(self.completion_queue.as_mut(), nb, &mut idx)
        };
        for desc in descriptors.iter_mut() {
            dbg!(nb, idx, count, &desc);
            desc.addr = unsafe {
                *libbpf_sys::_xsk_ring_cons__comp_addr(self.completion_queue.as_mut(), idx)
            };
            desc.len = 0;
            desc.options = 0;
            idx += 1;
            dbg!(&desc);
        }
        unsafe { libbpf_sys::_xsk_ring_cons__release(self.completion_queue.as_mut(), count) };
        count.try_into().unwrap()
    }

    pub(crate) fn push_fill(&mut self, descriptors: &[FrameRef]) -> usize {
        let nb = descriptors.len().try_into().unwrap();
        println!("FillQueue 'nb': {}", nb);
        let mut idx = 0;
        let count =
            unsafe { libbpf_sys::_xsk_ring_prod__reserve(self.fill_queue.as_mut(), nb, &mut idx) };
        dbg!(&nb, &idx, &count);
        if count == 0 {
            return 0;
        }
        for frame in descriptors {
            println!("Filling: {:?}", frame);
            unsafe {
                let f = libbpf_sys::_xsk_ring_prod__fill_addr(self.fill_queue.as_mut(), idx);
                println!(
                    "Setting 'f': {:?} w/ idx: {}, addr: {}",
                    *f, idx, frame.addr
                );
                *f = frame.addr
            };
            idx += 1;
        }
        unsafe { libbpf_sys::_xsk_ring_prod__submit(self.fill_queue.as_mut(), count) };
        println!("Submitted {} items to fill ring..", count);
        count.try_into().unwrap()
    }
}

/// UMEM configuration
///
/// Used for configuring a UMEM instance with various parameters and settings.
#[derive(Debug, Clone, Copy)]
pub struct UmemConfig {
    pub fill_size: u32,
    pub comp_size: u32,
    pub frame_size: u32,
    pub frame_headroom: u32,
    pub flags: u32,
}

impl From<UmemConfig> for xsk_umem_config {
    fn from(config: UmemConfig) -> Self {
        xsk_umem_config {
            fill_size: config.fill_size,
            comp_size: config.comp_size,
            frame_size: config.frame_size,
            frame_headroom: config.frame_headroom,
            flags: config.flags,
        }
    }
}

impl Default for UmemConfig {
    fn default() -> Self {
        UmemConfig {
            fill_size: XSK_RING_CONS__DEFAULT_NUM_DESCS,
            comp_size: XSK_RING_PROD__DEFAULT_NUM_DESCS,
            frame_size: XSK_UMEM__DEFAULT_FRAME_SIZE,
            frame_headroom: XSK_UMEM__DEFAULT_FRAME_HEADROOM,
            flags: XSK_UMEM__DEFAULT_FLAGS,
        }
    }
}

/// FrameRef - reference to individual UMEM frames.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct FrameRef {
    pub addr: u64,
    pub len: u32,
    pub options: u32,
}

impl FrameRef {
    pub fn get_buffer(&self, umem: Rc<RefCell<Umem>>) -> FrameBuf {
        FrameBuf { umem, frame: *self }
    }
}

/// TODO: Figure out a way to make it safe to access these without accidentally
/// having multiple mutable copies or something like that.
#[derive(Debug)]
pub struct FrameBuf {
    umem: Rc<RefCell<Umem>>,
    frame: FrameRef,
}

impl std::ops::Deref for FrameBuf {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        let umem = self.umem.borrow();
        unsafe {
            slice::from_raw_parts(
                umem.memory
                    .as_ptr()
                    .offset(self.frame.addr as isize)
                    .cast::<u8>(),
                self.frame.len as usize,
            )
        }
    }
}

impl std::ops::DerefMut for FrameBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // TODO: We may have to eventually remove the refcell wrapper because it could
        // be too easy to trip on, when we know it's actually probably safe to just give
        // out the slice assuming we don't make multiple ways to access this exact slice.
        let mut umem = self.umem.borrow_mut();
        unsafe {
            slice::from_raw_parts_mut(
                umem.memory
                    .as_mut_ptr()
                    .offset(self.frame.addr as isize)
                    .cast::<u8>(),
                self.frame.len as usize,
            )
        }
    }
}

impl Drop for FrameBuf {
    fn drop(&mut self) {
        println!("Dropping FrameBuf and putting back into free list");
        self.umem.borrow_mut().free_list.push_back(self.frame);
    }
}

/// Xsk socket configuration
///
#[derive(Debug, Clone, Copy)]
pub struct XskSocketConfig {
    pub if_name: &'static str,
    pub tx_size: u32,
    pub rx_size: u32,
    pub queue: u32,
    pub xdp_flags: u32,
    pub bind_flags: u16,
    pub libbpf_flags: u32,
}

impl XskSocketConfig {
    pub fn builder() -> XskSocketConfigBuilder {
        XskSocketConfigBuilder {
            if_name: None,
            tx_size: 2048,
            rx_size: 2048,
            queue: 0,
            xdp_flags: XDP_FLAGS_UPDATE_IF_NOEXIST,
            bind_flags: XDP_USE_NEED_WAKEUP as u16,
            libbpf_flags: 0,
        }
    }
}

/// Xsk socket configuration builder, helper struct.
pub struct XskSocketConfigBuilder {
    if_name: Option<&'static str>,
    tx_size: u32,
    rx_size: u32,
    queue: u32,
    xdp_flags: u32,
    bind_flags: u16,
    libbpf_flags: u32,
}

impl XskSocketConfigBuilder {
    /// set which interface the socket is for
    ///
    pub fn if_name(self, name: &'static str) -> XskSocketConfigBuilder {
        XskSocketConfigBuilder {
            if_name: Some(name),
            ..self
        }
    }
    /// Size of the tx ring.
    pub fn tx_size(self, tx_size: u32) -> XskSocketConfigBuilder {
        XskSocketConfigBuilder { tx_size, ..self }
    }

    /// Size of the rx ring.
    pub fn rx_size(self, rx_size: u32) -> XskSocketConfigBuilder {
        XskSocketConfigBuilder { rx_size, ..self }
    }

    /// Which queue to attach to.
    pub fn queue(self, queue: u32) -> XskSocketConfigBuilder {
        XskSocketConfigBuilder { queue, ..self }
    }

    /// What `XDP` flags to use when setting up the socket
    pub fn xdp_flags(self, xdp_flags: XdpFlags) -> XskSocketConfigBuilder {
        XskSocketConfigBuilder {
            xdp_flags: xdp_flags.bits(),
            ..self
        }
    }

    /// What `bind` flags to use when setting up the socket
    pub fn bind_flags(self, bind_flags: XskBindFlags) -> XskSocketConfigBuilder {
        XskSocketConfigBuilder {
            bind_flags: bind_flags.bits(),
            ..self
        }
    }

    /// What `libbpf` flags to use when setting up the socket
    pub fn libbpf_flags(self, libbpf_flags: u32) -> XskSocketConfigBuilder {
        XskSocketConfigBuilder {
            libbpf_flags,
            ..self
        }
    }

    /// Build the actual socket config
    pub fn build(self) -> XskSocketConfig {
        XskSocketConfig {
            if_name: self.if_name.unwrap(),
            tx_size: self.tx_size,
            rx_size: self.rx_size,
            queue: self.queue,
            xdp_flags: self.xdp_flags,
            bind_flags: self.bind_flags,
            libbpf_flags: self.libbpf_flags,
        }
    }
}

/// Memory-mapped region of memory
///
#[derive(Debug)]
pub struct MemoryRegion {
    len: u32,
    mem_ptr: ptr::NonNull<u8>,
}

impl MemoryRegion {
    pub fn new(bytes: u32, use_huge_pages: bool) -> Result<Self> {
        if bytes % PAGE_SIZE != 0 {
            panic!(
                "WARNING: Given a length that is not divisible by {} (current page size)",
                PAGE_SIZE
            );
        }
        let prot = PROT_READ | PROT_WRITE;
        let file = -1;
        let offset = 0;
        let mut flags = MAP_ANONYMOUS | MAP_PRIVATE;

        // Huge pages allocation, vs regular allocated pages.
        if use_huge_pages {
            flags |= MAP_HUGETLB;
        }

        // Assuming 64-bit architecure to u64 -> usize should work
        let len_usize: usize = bytes
            .try_into()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let mem_ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len_usize,
                prot,
                flags,
                file,
                offset as libc::off_t,
            )
        };

        if mem_ptr == MAP_FAILED {
            Err(io::Error::last_os_error().into())
        } else {
            // We wanna make sure we have a good pointer here so we don't have to worry about it again
            // later, and it helps with optimizations, supposedly.
            if let Some(mem_ptr) = ptr::NonNull::new(mem_ptr.cast::<u8>()) {
                return Ok(MemoryRegion {
                    len: bytes,
                    mem_ptr,
                });
            }
            Err(io::Error::new(io::ErrorKind::Other, "Invalid pointer returned by mmap").into())
        }
    }

    /// Return a mutable pointer to the beginning of the memory region
    ///
    /// # Safety
    ///
    /// Returns a mutable pointer that should ONLY be used to pass to `libbpf_sys::xsk_umem__create`
    /// and can guaranteed to be valid (non-null), but only prevents aliasing by using various queues to
    /// pass ownership to and from the kernel (and ourselves). This is still marked unsafe because it is
    /// not safe to just blindly pass, keep, mutate multiple pointers that are created by this function.
    unsafe fn as_mut_ptr(&mut self) -> *mut libc::c_void {
        self.mem_ptr.as_ptr() as _
    }

    unsafe fn as_ptr(&self) -> *const libc::c_void {
        self.mem_ptr.as_ptr() as _
    }
}

impl<T> Index<T> for MemoryRegion
where
    T: SliceIndex<[u8]>,
{
    type Output = T::Output;

    fn index(&self, index: T) -> &Self::Output {
        unsafe { slice::from_raw_parts(self.mem_ptr.as_ptr(), self.len as usize).index(index) }
    }
}

impl<T> IndexMut<T> for MemoryRegion
where
    T: SliceIndex<[u8]>,
{
    fn index_mut(&mut self, index: T) -> &mut Self::Output {
        unsafe {
            slice::from_raw_parts_mut(self.mem_ptr.as_ptr(), self.len as usize).index_mut(index)
        }
    }
}

#[cfg(test)]
mod tests {
    use etherparse::SlicedPacket;
    use std::time::Duration;

    use crate::{LocalExecutor, LocalExecutorBuilder};

    use super::*;

    #[test]
    fn af_xdp_recv() -> Result<()> {
        let mut builder = LocalExecutorBuilder::default();
        let local = builder
            .name("main")
            .pin_to_cpu(0)
            .spin_before_park(Duration::from_secs(1))
            .make()?;

        local.run(async move {
            let config = UmemConfig::default();
            let mut umem = Rc::new(RefCell::new(Umem::new(1024, config).unwrap()));
            let sock_config = XskSocketConfig::builder()
                .if_name("veth1")
                .queue(0)
                .bind_flags(XskBindFlags::XDP_USE_NEED_WAKEUP)
                .xdp_flags(XdpFlags::XDP_FLAGS_DRV_MODE)
                .rx_size(2048)
                .tx_size(2048)
                .build();

            let mut socket = XdpSocket::new(sock_config, umem.clone()).unwrap();
            let resp = socket.fill_descriptors(umem);
            println!("Filled {} into fill ring..", resp);
            loop {
                let amt = socket.recv().await;
                let bufs = amt.unwrap();
                if !bufs.is_empty() {
                    for b in bufs {
                        let packet = SlicedPacket::from_ethernet(&b[..]);
                        dbg!(packet, b.len());
                    }
                }
            }
        });

        Ok(())
    }

    #[test]
    fn umem_queue_count() -> Result<()> {
        let mut umem = Umem::new(10, UmemConfig::default())?;
        let available = umem.fill_available();
        let len = umem.fill_used();
        dbg!(available, len);
        assert_eq!(len, 0);
        assert_eq!(available, UmemConfig::default().fill_size as usize);

        let fill_slice: Vec<_> = umem.free_list.drain(..10).collect();
        let amt = umem.push_fill(&fill_slice);
        assert_eq!(amt, 10);

        let available = umem.fill_available();
        let len = umem.fill_used();
        dbg!(available, len);
        assert_eq!(len, 10);
        assert_eq!(available, (UmemConfig::default().fill_size - 10) as usize);

        let ready = umem.completions_ready();
        dbg!(ready);
        assert_eq!(ready, 0);

        Ok(())
    }

    #[test]
    fn xdp_socket_rx() -> Result<()> {
        let config = UmemConfig::default();
        let mut umem = Rc::new(RefCell::new(Umem::new(1024, config)?));
        let sock_config = XskSocketConfig::builder()
            .if_name("veth1")
            .queue(0)
            .bind_flags(XskBindFlags::empty())
            .xdp_flags(XdpFlags::XDP_FLAGS_DRV_MODE)
            .rx_size(2048)
            .tx_size(2048)
            .build();

        let mut socket = XdpSocket::new(sock_config, umem.clone())?;
        dbg!(&socket);

        let mut small_fill: Vec<_> = umem.borrow_mut().free_list.drain(..10).collect();
        let amt = socket.push_fill(&small_fill, &mut umem.borrow_mut());
        let got = socket.pop_rx(&mut small_fill[..amt]);
        let actual: VecDeque<_> = small_fill.drain(..got).collect();
        dbg!(actual);
        Ok(())
    }

    #[test]
    fn construct_xdp_socket() -> Result<()> {
        let config = UmemConfig::default();
        let umem = Rc::new(RefCell::new(Umem::new(1024, config)?));
        let sock_config = XskSocketConfig::builder()
            .if_name("veth1")
            .queue(0)
            .bind_flags(XskBindFlags::XDP_USE_NEED_WAKEUP)
            .xdp_flags(XdpFlags::XDP_FLAGS_DRV_MODE | XdpFlags::XDP_FLAGS_UPDATE_IF_NOEXIST)
            .rx_size(2048)
            .tx_size(2048)
            .build();

        let socket = XdpSocket::new(sock_config, umem)?;
        dbg!(socket);
        Ok(())
    }

    #[test]
    fn construct_umem() -> Result<()> {
        let config = UmemConfig::default();
        let umem = Umem::new(1024, config)?;
        dbg!(umem);

        Ok(())
    }

    #[test]
    fn slice_index_memory_region() {
        let mut mm = MemoryRegion::new(4096 * 10, false).unwrap();
        let just_two = &mm[..2];
        let mutable_range = &mut mm[1..8];
    }

    #[test]
    fn slice_index_memory_region_mut() {
        let mut mm = MemoryRegion::new(4096 * 10, false).unwrap();
        let mutable_range = &mut mm[1..8];
        mutable_range.copy_from_slice(b"abcdefg");
        let output = &mm[1..8];
        assert_eq!(output, b"abcdefg");
        assert_eq!(mm[..].len(), 4096 * 10);
    }
}
