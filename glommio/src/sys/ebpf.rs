//!
//! eBpf low level utilities and integration.
//!
//! Primarily uses libbpf (via libbpf_sys crate) to build AF_XDP support into
//! Glommio.

use bitflags::bitflags;
use core::{fmt, slice};
use libc::{MAP_ANONYMOUS, MAP_FAILED, MAP_HUGETLB, MAP_PRIVATE, PROT_READ, PROT_WRITE};
use std::{
    cell::{Cell, RefCell},
    cmp::{self, Ordering},
    collections::VecDeque,
    convert::TryInto,
    ffi::CString,
    io,
    mem::ManuallyDrop,
    net::Ipv4Addr,
    ops::{self, Index, IndexMut},
    os::unix::prelude::{IntoRawFd, RawFd},
    ptr,
    rc::{Rc, Weak},
    slice::SliceIndex,
};

use libbpf_sys::{
    xsk_ring_cons, xsk_ring_prod, xsk_socket, xsk_socket_config, xsk_umem, xsk_umem_config,
    XDP_FLAGS_UPDATE_IF_NOEXIST, XDP_USE_NEED_WAKEUP, XSK_RING_CONS__DEFAULT_NUM_DESCS,
    XSK_RING_PROD__DEFAULT_NUM_DESCS, XSK_UMEM__DEFAULT_FLAGS, XSK_UMEM__DEFAULT_FRAME_HEADROOM,
    XSK_UMEM__DEFAULT_FRAME_SIZE,
};

use crate::{log_queue_counts, parking::Reactor, GlommioError, Local};

use super::Source;

type Result<T> = std::result::Result<T, GlommioError<()>>;

const PAGE_SIZE: u32 = 4096;

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
/// AF_XDP socket for delivering layer 2 frames directly to userspace from very
/// early in the kernel networking stack. So early, it's basically in the
/// drivers code directly and can even operate in a `zero-copy` fashion.
///
/// It operates very differently from a standard socket type. In fact it works a
/// lot more like memory-mapped AF_PACKET capture in that it invovles sharing
/// memory between userspace and the kernel. It does this by passing descriptors
/// back and forth between kernel and userspace over ring-buffers.
#[derive(Debug)]
pub struct XskSocketDriver {
    socket: Box<xsk_socket>,
    rx_queue: Box<xsk_ring_cons>,
    tx_queue: Box<xsk_ring_prod>,
    config: XskSocketConfig,
    umem: Rc<RefCell<Umem>>,
    reactor: Weak<Reactor>,
    fd: RawFd,
}

pub(crate) type Arena = Vec<*const libbpf_sys::xdp_desc>;

impl XskSocketDriver {
    pub(crate) fn new(config: XskSocketConfig, umem: Rc<RefCell<Umem>>) -> Result<XskSocketDriver> {
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
            println!("Failed to create socket..");
            return Err(io::Error::from_raw_os_error(-err).into());
        }

        let fd = unsafe { libbpf_sys::xsk_socket__fd(xsk) };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }

        unsafe {
            Ok(XskSocketDriver {
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

    pub(crate) fn consume_rx_unsafe(
        &mut self,
        arena: &mut Arena,
        batch_size: u64,
    ) -> Option<usize> {
        if batch_size == 0 {
            return None;
        }
        let mut idx = 0;
        unsafe {
            let count =
                libbpf_sys::_xsk_ring_cons__peek(self.rx_queue.as_mut(), batch_size, &mut idx);
            if count == 0 {
                return None;
            }
            let count_usize = count.try_into().unwrap();
            for _ in 0..count_usize {
                let rx_descriptor =
                    libbpf_sys::_xsk_ring_cons__rx_desc(self.rx_queue.as_ref(), idx);
                arena.push(rx_descriptor);
                idx += 1;
            }
            libbpf_sys::_xsk_ring_cons__release(self.rx_queue.as_mut(), count);
            Some(count.try_into().unwrap())
        }
    }

    pub(crate) fn consume_rx_owned(&mut self, batch: u64) -> Vec<FrameRef> {
        log_queue_counts!(self.rx_queue, "RX");
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
                let frame: FrameRef = (*rx_descriptor).into();
                // println!(
                //     "Consuming descriptor: '{}' (index: {}, frame len: {})",
                //     frame.addr, idx, frame.len
                // );
                recv_descriptors.push(frame);
                idx += 1;
            }
            libbpf_sys::_xsk_ring_cons__release(self.rx_queue.as_mut(), count);
        }
        recv_descriptors
    }

    pub(crate) fn produce_tx(&mut self, descriptors: &mut [FrameRef]) -> usize {
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
                (*x).addr = desc.addr.get();
                (*x).len = desc.len.get();
                (*x).options = desc.options.get();
                desc.in_queue = true;
                idx += 1;
            }
            libbpf_sys::_xsk_ring_prod__submit(self.tx_queue.as_mut(), count);
            count.try_into().unwrap()
        }
    }

    pub(crate) fn produce_tx_queued(
        &mut self,
        descriptors: &mut Vec<FrameBuf>,
    ) -> (usize, Option<Vec<Option<Source>>>) {
        log_queue_counts!(self.tx_queue, "TX");

        let nb = descriptors.len().try_into().unwrap();
        if nb == 0 {
            return (0, None);
        }
        let mut idx = 0;
        unsafe {
            let mut attempted_nb = nb;
            let mut retries = 0;
            let count = loop {
                let free_space =
                    libbpf_sys::_xsk_prod_nb_free(self.tx_queue.as_mut(), attempted_nb);
                println!(
                    "TX queue free slots: {}. (attempted: {}, retry: {})",
                    free_space, attempted_nb, retries
                );

                if free_space == 0 {
                    return (0, None);
                }

                let inner_count = libbpf_sys::_xsk_ring_prod__reserve(
                    self.tx_queue.as_mut(),
                    attempted_nb as u64,
                    &mut idx,
                );
                if inner_count == 0 && retries < 10 && attempted_nb != 0 {
                    attempted_nb /= 2;
                    retries += 1;
                    continue;
                }
                break inner_count;
            };
            // let count = libbpf_sys::_xsk_ring_prod__reserve(self.tx_queue.as_mut(), nb,
            // &mut idx);
            println!("Have room for {} entries in the TX queue", count);
            if count == 0 {
                return (0, None);
            }
            let pending = &mut self.umem.borrow_mut().pending_completions;
            let usable_descriptors = descriptors.drain(..(count as usize));

            for desc in usable_descriptors {
                let x = libbpf_sys::_xsk_ring_prod__tx_desc(self.tx_queue.as_mut(), idx);
                {
                    let fr = &desc.inner.frame;
                    (*x).addr = fr.addr.get();
                    (*x).len = fr.len.get();
                    (*x).options = fr.options.get();
                    // fr.in_queue = true;
                }
                pending.push_back(desc);
                idx += 1;
            }
            libbpf_sys::_xsk_ring_prod__submit(self.tx_queue.as_mut(), count);
            if count > 0 && self.tx_needs_wakeup() {
                let mut sources = vec![];
                let r = 0..((count / 16) + 1);
                dbg!(r);
                for i in 0..((count / 16) + 1) {
                    sources.push(self.kick_tx());
                }
                return (count.try_into().unwrap(), Some(sources));
            }
            (count.try_into().unwrap(), None)
        }
    }

    pub(crate) fn tx_needs_wakeup(&self) -> bool {
        unsafe { libbpf_sys::_xsk_ring_prod__needs_wakeup(self.tx_queue.as_ref()) != 0 }
    }

    pub(crate) fn fill_needs_wakeup(&self) -> bool {
        unsafe {
            libbpf_sys::_xsk_ring_prod__needs_wakeup(self.umem.borrow().fill_queue.as_ref()) != 0
        }
    }

    pub(crate) fn kick_tx(&self) -> Option<Source> {
        Some(self.reactor.upgrade()?.kick_tx(self.fd))
    }

    pub(crate) fn rx_count(&mut self) -> usize {
        unsafe {
            libbpf_sys::_xsk_cons_nb_avail(self.rx_queue.as_mut(), self.rx_queue.size) as usize
        }
    }

    pub(crate) fn rx_count_cached(&self) -> usize {
        (self.rx_queue.cached_prod - self.rx_queue.cached_cons) as usize
    }

    pub(crate) fn tx_count(&mut self) -> usize {
        unsafe {
            (self.tx_queue.size
                - libbpf_sys::_xsk_prod_nb_free(self.tx_queue.as_mut(), self.tx_queue.size) as u32)
                as usize
        }
    }

    pub(crate) fn tx_count_cached(&self) -> usize {
        (self.tx_queue.size - (self.tx_queue.cached_cons - self.tx_queue.cached_prod)) as usize
    }

    pub(crate) fn reactor(&self) -> &Weak<Reactor> {
        &self.reactor
    }

    pub(crate) fn fd(&self) -> &RawFd {
        &self.fd
    }
}

impl Drop for XskSocketDriver {
    fn drop(&mut self) {
        unsafe {
            println!("Dropping AF_XDP socket (fd: {}) ...", self.fd);
            libbpf_sys::xsk_socket__delete(self.socket.as_mut());
        }
    }
}

pub struct Umem {
    umem: Box<xsk_umem>,
    fill_queue: Box<xsk_ring_prod>,
    completion_queue: Box<xsk_ring_cons>,
    pub(crate) memory: RefCell<MemoryRegion>,

    pub(crate) free_list: RefCell<VecDeque<FrameRef>>,
    pub(crate) pending_completions: VecDeque<FrameBuf>,
    frames: u32,
    frame_size: u32,
    fd: RawFd,
    fill_threshold: u32,
    completions_threshold: u32,
}

impl Umem {
    pub fn new(num_descriptors: u32, config: xsk_umem_config) -> Result<Umem> {
        let mut memory_region = MemoryRegion::new(PAGE_SIZE * num_descriptors, false)?;
        dbg!(&memory_region);

        let mem_ptr = unsafe { memory_region.as_mut_ptr() };

        // Create empty producer and consume structures for the fill and completion
        // queues.
        let fq: Box<xsk_ring_prod> = Default::default();
        let cq: Box<xsk_ring_cons> = Default::default();

        let ffi_config: *const _ = &config;
        let mut umem: *mut xsk_umem = ptr::null_mut();
        let umem_ptr: *mut *mut xsk_umem = &mut umem;
        let size = num_descriptors as u64 * 4096;
        let fq_ptr = Box::into_raw(fq);
        let cq_ptr = Box::into_raw(cq);

        // Create the actual UMEM
        dbg!(unsafe { *ffi_config });
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
                addr: Cell::new((i as u64) * (config.frame_size as u64)),
                len: Cell::new(0),
                options: Cell::new(0),
                in_queue: false,
            });
        }
        println!("Created free_list with {} entries.", descriptors.len());

        unsafe {
            Ok(Umem {
                umem: umem_box,
                fill_queue: Box::from_raw(fq_ptr),
                completion_queue: Box::from_raw(cq_ptr),
                memory: RefCell::new(memory_region),
                frames: num_descriptors,
                frame_size: PAGE_SIZE,
                fd: fd.into_raw_fd(),
                free_list: RefCell::new(descriptors),

                // Allocated with a full capacity of 5000 because (hopefully) it won't need to grow
                // beyond that, and so that we aren't constantly reallocating or allocating.
                pending_completions: VecDeque::with_capacity(5000),

                // Threshold is half the full size
                fill_threshold: config.fill_size / 2,

                // Threshold for when to reap completions
                completions_threshold: 0,
            })
        }
    }

    pub(crate) fn frames(&self) -> u32 {
        self.frames
    }

    pub(crate) fn frame_size(&self) -> u32 {
        self.frame_size
    }

    unsafe fn inner_umem_mut_ptr(&mut self) -> *mut xsk_umem {
        self.umem.as_mut()
    }

    pub(crate) fn completions_ready(&mut self) -> usize {
        unsafe {
            libbpf_sys::_xsk_cons_nb_avail(
                self.completion_queue.as_mut(),
                self.completion_queue.size,
            ) as usize
        }
    }

    pub(crate) fn completions_ready_cached(&mut self) -> usize {
        unsafe {
            libbpf_sys::_xsk_cons_nb_avail(
                self.completion_queue.as_mut(),
                self.completion_queue.size,
            );
        }
        let consumer = self.completion_queue.cached_cons;
        let producer = self.completion_queue.cached_prod;
        dbg!(consumer, producer);
        (producer - consumer) as usize
    }

    pub(crate) fn maybe_consume_completions(&mut self) -> Option<usize> {
        let completions = self.completions_ready();
        if completions > 0 {
            println!("There are {} completions ready..", completions);
            if completions > (self.completions_threshold as usize) {
                let consumed = self.consume_completions_queue(completions as u64);
                dbg!(consumed, self.pending_completions.len());
                if consumed < self.pending_completions.len() {
                    self.pending_completions.drain(..consumed);
                    return Some(consumed);
                }
            }
        }
        None
    }

    pub(crate) fn consume_completions(&mut self, descriptors: &mut [FrameRef]) -> usize {
        let nb = descriptors.len().try_into().unwrap();
        let mut idx = 0;
        let count = unsafe {
            libbpf_sys::_xsk_ring_cons__peek(self.completion_queue.as_mut(), nb, &mut idx)
        };
        println!(
            "There are {} entries in completion queue. Idx: {}",
            count, idx
        );
        for desc in descriptors.iter_mut() {
            let addr = unsafe {
                *libbpf_sys::_xsk_ring_cons__comp_addr(self.completion_queue.as_mut(), idx)
            };
            println!("Computing address for {} = {}", desc.addr.get(), addr);
            desc.addr.set(addr);
            desc.len.set(0);
            desc.options.set(0);
            idx += 1;
        }
        unsafe { libbpf_sys::_xsk_ring_cons__release(self.completion_queue.as_mut(), count) };
        count.try_into().unwrap()
    }

    pub(crate) fn consume_completions_queue(&mut self, size_hint: u64) -> usize {
        log_queue_counts!(self.completion_queue, "COMPLETION");
        let nb = self.pending_completions.len() as u64;
        let mut idx = 0;
        let count = unsafe {
            libbpf_sys::_xsk_ring_cons__peek(self.completion_queue.as_mut(), size_hint, &mut idx)
        };
        let mut i = 0;
        for _ in 0..count {
            match self.pending_completions.pop_back() {
                Some(desc) => {
                    let addr = unsafe {
                        *libbpf_sys::_xsk_ring_cons__comp_addr(self.completion_queue.as_mut(), idx)
                    };
                    {
                        let mut descriptor = &desc.inner;
                        descriptor.frame.addr.set(addr);
                        descriptor.frame.len.set(0);
                        descriptor.frame.options.set(0);
                        idx += 1;
                    }

                    let frame = desc.inner.frame.clone();
                    self.free_list.borrow_mut().push_back(frame);
                    i += 1;
                    let x = ManuallyDrop::new(desc);
                }
                None => {
                    println!("********** ERROR **********");
                    println!("pending: {}", self.pending_completions.len());
                }
            }
        }
        println!("Going to release {} entries..", i);
        unsafe { libbpf_sys::_xsk_ring_cons__release(self.completion_queue.as_mut(), i) };
        i as usize
    }

    pub(crate) fn maybe_fill_descriptors(&mut self) -> Option<usize> {
        let fill_qty = self.fill_count();
        if fill_qty < (self.fill_threshold as usize) {
            println!(
                "Fill quantity: {}, self.fill_threshold: {}",
                fill_qty, self.fill_threshold
            );
            let count = (self.fill_queue.size as usize) - fill_qty;
            println!("Fill is less than threshold, filling: {}", count);
            return Some(self.fill_descriptors(count));
        }
        None
    }

    pub(crate) fn fill_descriptors(&mut self, mut amt: usize) -> usize {
        log_queue_counts!(self.fill_queue, "FILL");
        println!("Going to attempt to fill {} descriptors..", amt);
        let mut idx = 0;
        let count = loop {
            let count = unsafe {
                libbpf_sys::_xsk_ring_prod__reserve(self.fill_queue.as_mut(), amt as u64, &mut idx)
            };
            if count == 0 {
                amt /= 2;
                continue;
            } else {
                break count;
            }
        };

        let max = std::cmp::min(self.free_list.borrow().len(), count as usize);
        let mut d = self.free_list.borrow_mut();
        let descriptors = d.drain(..max as usize);
        dbg!((idx, count, amt, descriptors.len(), max));

        if count == 0 {
            return 0;
        }
        for frame in descriptors {
            unsafe {
                let f = libbpf_sys::_xsk_ring_prod__fill_addr(self.fill_queue.as_mut(), idx);
                *f = frame.addr.get()
            };
            idx += 1;
        }
        // Actually submit "count" entries to the fill ring.
        unsafe { libbpf_sys::_xsk_ring_prod__submit(self.fill_queue.as_mut(), count) };
        count.try_into().unwrap()
    }

    pub(crate) fn fill_count(&mut self) -> usize {
        let max = self.fill_queue.size;
        unsafe {
            (max - libbpf_sys::_xsk_prod_nb_free(self.fill_queue.as_mut(), max) as u32) as usize
        }
    }

    pub(crate) fn fill_count_cached(&self) -> usize {
        (self.fill_queue.size - (self.fill_queue.cached_cons - self.fill_queue.cached_prod))
            as usize
    }
}

impl Drop for Umem {
    fn drop(&mut self) {
        unsafe {
            println!(
                "Dropping UMEM (fd: {}) region of size: {}..",
                self.fd, self.frames
            );
            let resp = libbpf_sys::xsk_umem__delete(self.umem.as_mut());
            if resp < 0 {
                let err = io::Error::from_raw_os_error(-resp);
                dbg!(&err);
            }
        }
    }
}

impl fmt::Debug for Umem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Umem")
            .field("umem", &self.umem)
            .field("fill_queue", &self.fill_queue)
            .field("completion_queue", &self.completion_queue)
            .field("memory", &self.memory)
            .field("free_list", &"[ .. ]")
            .field("pending_completions", &"[ .. ]")
            .field("frames", &self.frames)
            .field("frame_size", &self.frame_size)
            .field("fd", &self.fd)
            .field("fill_threshold", &self.fill_threshold)
            .field("completions_threshold", &self.completions_threshold)
            .finish()
    }
}

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

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct FrameRef {
    pub(crate) addr: Cell<u64>,
    pub(crate) len: Cell<u32>,
    pub(crate) options: Cell<u32>,
    pub(crate) in_queue: bool,
}

impl FrameRef {
    pub fn get_buffer(self, umem: Rc<RefCell<Umem>>) -> FrameBuf {
        FrameBuf {
            inner: Rc::new(InnerBuf { umem, frame: self }),
        }
    }
}

#[derive(Debug)]
pub struct MemoryRegion {
    len: u32,
    mem_ptr: ptr::NonNull<u8>,
}

impl MemoryRegion {
    pub(crate) fn new(bytes: u32, use_huge_pages: bool) -> Result<Self> {
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
            println!("USING HUGE PAGES!!");
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
            // We wanna make sure we have a good pointer here so we don't have to worry
            // about it again later, and it helps with optimizations,
            // supposedly.
            if let Some(mem_ptr) = ptr::NonNull::new(mem_ptr.cast::<u8>()) {
                return Ok(MemoryRegion {
                    len: bytes,
                    mem_ptr,
                });
            }
            Err(io::Error::new(io::ErrorKind::Other, "Invalid pointer returned by mmap").into())
        }
    }

    pub(crate) unsafe fn as_mut_ptr(&mut self) -> *mut libc::c_void {
        self.mem_ptr.as_ptr() as _
    }

    pub(crate) unsafe fn as_ptr(&self) -> *const libc::c_void {
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

#[derive(Debug)]
struct Inner {
    umem: ptr::NonNull<Umem>,
    // frame: *const libbpf_sys::xdp_desc,
    frame: FrameRef,
    refcount: Cell<u16>,
}

#[derive(Debug)]
pub struct Buf {
    inner: ptr::NonNull<Inner>,
}

impl Buf {
    unsafe fn new<F>(umem: ptr::NonNull<Umem>, frame: F) -> Buf
    where
        F: Into<Option<FrameRef>>,
    {
        let f: Option<_> = frame.into();
        let frame = f.unwrap_or(FrameRef {
            addr: 0.into(),
            len: 0.into(),
            options: 0.into(),
            in_queue: false,
        });
        let inner = Box::new(Inner {
            umem,
            frame,
            refcount: Cell::new(1),
        });
        Buf {
            inner: ptr::NonNull::new_unchecked(Box::into_raw(inner)),
        }
    }
}

impl Clone for Buf {
    fn clone(&self) -> Self {
        unsafe {
            (*self.inner.as_ptr())
                .refcount
                .set((*self.inner.as_ptr()).refcount.get() + 1)
        };
        Buf { inner: self.inner }
    }
}

impl Drop for Buf {
    fn drop(&mut self) {
        unsafe {
            self.inner
                .as_ref()
                .refcount
                .set(self.inner.as_ref().refcount.get() - 1);
            println!(
                "Decremented refcount to: {}",
                self.inner.as_ref().refcount.get()
            );

            if self.inner.as_ref().refcount.get() == 0 {
                let frame = self.inner.as_ref().frame.clone();
                println!("Actually dropping: {:#?}", self.inner.as_ref());
                self.inner
                    .as_mut()
                    .umem
                    .as_mut()
                    .free_list
                    .borrow_mut()
                    .push_back(frame);
                println!(
                    "Free list len: {}",
                    self.inner.as_mut().umem.as_mut().free_list.borrow().len()
                );
            }
        }
    }
}

/// TODO: Figure out a way to make it safe to access these without accidentally
/// having multiple mutable copies or something like that.
pub struct FrameBuf {
    pub(crate) inner: Rc<InnerBuf>,
}

impl FrameBuf {
    pub fn frame_addr(&self) -> u64 {
        self.inner.frame.addr.get()
    }

    pub fn set_frame_addr(&mut self, addr: u64) {
        self.inner.frame.addr.set(addr);
    }

    pub fn frame_len(&self) -> u32 {
        self.inner.frame.len.get()
    }

    pub fn set_frame_len(&mut self, len: u32) {
        self.inner.frame.len.set(len);
    }

    pub fn frame_options(&self) -> u32 {
        self.inner.frame.options.get()
    }

    pub fn set_frame_options(&mut self, options: u32) {
        self.inner.frame.options.set(options);
    }

    pub fn mac_dst(&self) -> &[u8] {
        &self[..6]
    }

    pub fn mac_dst_mut(&mut self) -> &mut [u8] {
        &mut self[..6]
    }

    /// L2 MAC source slice
    pub fn mac_src(&self) -> &[u8] {
        &self[6..12]
    }

    /// Mutable L2 MAC source slice
    pub fn mac_src_mut(&mut self) -> &mut [u8] {
        &mut self[6..12]
    }

    /// The ethertype of the frame
    pub fn ether_type_raw(&self) -> u16 {
        let arr: [u8; 2] = self[12..14].try_into().unwrap();
        u16::from_be_bytes(arr)
    }

    pub fn ether_type(&self) -> EtherType {
        match self.ether_type_raw() {
            0x0800 => EtherType::Ipv4,
            0x86dd => EtherType::Ipv6,
            0x0806 => EtherType::Arp,
            0x0842 => EtherType::WakeOnLan,
            0x8100 => EtherType::VlanTaggedFrame,
            0x88A8 => EtherType::ProviderBridging,
            0x9100 => EtherType::VlanDoubleTaggedFrame,
            et => {
                eprintln!("Invalid ethertype value! Got: {}", et);
                EtherType::Arp
            }
        }
    }

    /// Mutable access to the ethertype
    pub fn set_ether_type(&mut self, ether_type: u16) {
        let arr = ether_type.to_be_bytes();
        self[12..14].copy_from_slice(&arr);
    }

    pub fn ip_header_len(&self) -> u8 {
        (self[14] & 0b00001111) * 4
    }

    pub fn ip_tos(&self) -> u8 {
        self[15]
    }

    pub fn ip_total_size(&self) -> &[u8] {
        &self[16..18]
    }

    pub fn ip_identification(&self) -> &[u8] {
        &self[18..20]
    }

    pub fn ip_fragment_offset(&self) -> &[u8] {
        &self[20..22]
    }

    pub fn ip_ttl(&self) -> u8 {
        self[22]
    }

    pub fn ip_protocol(&self) -> u8 {
        self[23]
    }

    pub fn ip_checksum(&self) -> &[u8] {
        &self[24..26]
    }

    pub fn ip_src_raw(&self) -> &[u8] {
        &self[26..30]
    }

    pub fn ip_src(&self) -> Ipv4Addr {
        u32::from_be_bytes(self.ip_src_raw().try_into().unwrap()).into()
    }

    pub fn ip_src_mut(&mut self) -> &mut [u8] {
        &mut self[26..30]
    }

    pub fn set_ip_src(&mut self, ip: Ipv4Addr) {
        let ip_le: u32 = ip.into();
        self.ip_src_mut().copy_from_slice(&ip_le.to_be_bytes());
    }

    pub fn ip_dst_raw(&self) -> &[u8] {
        &self[30..34]
    }

    pub fn ip_dst(&self) -> Ipv4Addr {
        u32::from_be_bytes(self.ip_dst_raw().try_into().unwrap()).into()
    }

    pub fn ip_dst_mut(&mut self) -> &mut [u8] {
        &mut self[30..34]
    }

    pub fn set_ip_dst(&mut self, ip: Ipv4Addr) {
        let ip_le: u32 = ip.into();
        self.ip_dst_mut().copy_from_slice(&ip_le.to_be_bytes());
    }

    pub fn ip_options(&self) -> &[u8] {
        &self[34..38]
    }

    pub fn calculate_ipv4_csum(&mut self) {
        let ip_header = &self[14..(14 + self.ip_header_len()) as usize];
        let mut result = 0xffffu32;

        for idx in 0..(self.ip_header_len() / 2) {
            if idx == 6 {
                println!(
                    "Skipping idx {} with slice value: {:#0X?}",
                    idx,
                    &ip_header[2 * (idx as usize)..(2 * idx as usize) + 2]
                );
                continue;
            }
            println!(
                "Calculating idx {} with slice value: {:#0X?}",
                idx,
                &ip_header[2 * (idx as usize)..(2 * idx as usize) + 2]
            );

            let sixteen_chunk = u16::from_be_bytes(
                ip_header[2 * (idx as usize)..(2 * idx as usize) + 2]
                    .try_into()
                    .unwrap(),
            );
            result += sixteen_chunk as u32;

            if result > 0xffff {
                println!("Result greater than 0xFFFF! Subtracting that amount.");
                result -= 0xffff;
            }
            println!("iteration: {}, result: {:#0X?}", idx, result);
        }

        dbg!(&ip_header, ip_header.len(),);
        self[24..26].copy_from_slice(&(!result as u16).to_be_bytes());
        println!(
            "Slice: {:0x?}, checksum: {:#0X?}",
            &self[14..(14 + self.ip_header_len()) as usize],
            self.ip_checksum()
        );
    }
}

impl fmt::Debug for FrameBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrameBuf")
            .field("inner", &self.inner)
            .finish()
    }
}

impl fmt::Debug for InnerBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InnerBuf")
            .field("frame", &self.frame)
            .field("umem", &self.umem)
            .finish()
    }
}

// impl Clone for FrameBuf {
//     fn clone(&self) -> Self {
//         FrameBuf {
//             inner: self.inner.clone(),
//         }
//     }
// }

///Ether type enum present in ethernet II header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EtherType {
    Ipv4 = 0x0800,
    Ipv6 = 0x86dd,
    Arp = 0x0806,
    WakeOnLan = 0x0842,
    VlanTaggedFrame = 0x8100,
    ProviderBridging = 0x88A8,
    VlanDoubleTaggedFrame = 0x9100,
}

pub(crate) struct InnerBuf {
    pub(crate) umem: Rc<RefCell<Umem>>,
    pub(crate) frame: FrameRef,
}

impl ops::Deref for FrameBuf {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        let inner = &self.inner;
        // println!("Before Deref for frame: {:?}", inner.frame);
        let umem = inner.umem.borrow();
        unsafe {
            slice::from_raw_parts(
                umem.memory
                    .as_ptr()
                    .offset(inner.frame.addr.get() as isize)
                    .cast::<u8>(),
                inner.frame.len.get() as usize,
            )
        }
    }
}

impl ops::DerefMut for FrameBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // TODO: We may have to eventually remove the refcell wrapper because it could
        // be too easy to trip on, when we know it's actually probably safe to just give
        // out the slice assuming we don't make multiple ways to access this exact
        // slice.
        let inner = &self.inner;
        // println!("Before DerefMut for frame: {:?}", inner.frame);
        let mut umem = inner.umem.borrow_mut();

        let res = unsafe {
            slice::from_raw_parts_mut(
                umem.memory
                    .borrow_mut()
                    .as_mut_ptr()
                    .offset(inner.frame.addr.get() as isize)
                    .cast::<u8>(),
                inner.frame.len.get() as usize,
            )
        };
        // println!(
        //     "After (but still borrowed) DerefMut for frame: {:?}",
        //     inner.frame
        // );
        res
    }
}

impl Drop for FrameBuf {
    fn drop(&mut self) {
        let copied = self.inner.frame.clone();
        println!("Dropping FrameBuf: {:?}", copied);
        self.inner
            .umem
            .borrow_mut()
            .free_list
            .borrow_mut()
            .push_back(copied);
    }
}

/// Xsk socket configuration
#[derive(Debug, Clone, Copy)]
pub struct XskSocketConfig {
    pub(crate) if_name: &'static str,
    pub(crate) tx_size: u32,
    pub(crate) rx_size: u32,
    pub(crate) queue: u32,
    pub(crate) xdp_flags: u32,
    pub(crate) bind_flags: u16,
    pub(crate) libbpf_flags: u32,
}

impl XskSocketConfig {
    /// Creates a builder
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
#[derive(Debug)]
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

impl From<XskSocketConfig> for xsk_socket_config {
    fn from(original: XskSocketConfig) -> Self {
        xsk_socket_config {
            rx_size: original.rx_size,
            tx_size: original.tx_size,
            libbpf_flags: original.libbpf_flags,
            xdp_flags: original.xdp_flags,
            bind_flags: original.bind_flags,
        }
    }
}

impl From<libbpf_sys::xdp_desc> for FrameRef {
    fn from(desc: libbpf_sys::xdp_desc) -> Self {
        FrameRef {
            addr: Cell::new(desc.addr),
            len: Cell::new(desc.len),
            options: Cell::new(desc.options),
            in_queue: false,
        }
    }
}

impl From<FrameRef> for libbpf_sys::xdp_desc {
    fn from(frame: FrameRef) -> Self {
        libbpf_sys::xdp_desc {
            addr: frame.addr.get(),
            len: frame.len.get(),
            options: frame.options.get(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use etherparse::SlicedPacket;
    use nix::poll::PollFd;
    use std::{
        process::{Child, Stdio},
        sync::Arc,
        time::Duration,
    };

    use crate::LocalExecutorBuilder;
    use lazy_static::lazy_static;
    use std::sync::Mutex;

    use super::*;

    lazy_static! {
        pub static ref XDP_LOCK: Arc<Mutex<()>> = Arc::new(Mutex::new(()));
    }

    #[test]
    fn frame_buf_drop_requeue() {
        let umem = Rc::new(RefCell::new(
            Umem::new(10, UmemConfig::default().into()).unwrap(),
        ));
        let ptr = Rc::into_raw(umem);

        let mut fb = FrameBuf {
            inner: Rc::new(InnerBuf {
                umem: unsafe { Rc::from_raw(ptr) },
                frame: FrameRef {
                    addr: Cell::new(0),
                    len: Cell::new(42),
                    options: Cell::new(0),
                    in_queue: false,
                },
            }),
        };

        let inner = unsafe { &*ptr };
        let pending = &inner.borrow().pending_completions;
    }

    #[test]
    fn frame_buf_ip_header_csum() {
        let umem = Rc::new(RefCell::new(
            Umem::new(10, UmemConfig::default().into()).unwrap(),
        ));
        let mut fb = FrameBuf {
            inner: Rc::new(InnerBuf {
                umem,
                frame: FrameRef {
                    addr: Cell::new(0),
                    len: Cell::new(42),
                    options: Cell::new(0),
                    in_queue: false,
                },
            }),
        };
        fb[16..].copy_from_slice(b"abcdefghijklmnopqrstuvwxyz");
        fb[14] = 0x45;
        let out = fb.ip_header_len();
        dbg!(out);
        fb.calculate_ipv4_csum();
    }

    #[test]
    #[cfg_attr(not(feature = "xdp"), ignore)]
    fn af_xdp_umem_produce_fill() -> Result<()> {
        let _guard = XDP_LOCK.lock().unwrap_or_else(|x| x.into_inner());
        let umem = Rc::new(RefCell::new(Umem::new(10, UmemConfig::default().into())?));
        dbg!(
            &umem,
            &umem.borrow().free_list,
            &umem.borrow().free_list.borrow().len(),
        );
        let qty = umem.borrow_mut().fill_descriptors(5);
        assert_eq!(qty, 5);
        dbg!(&umem.borrow().free_list);
        assert_eq!(umem.borrow().free_list.borrow().len(), 5);
        dbg!(
            umem.borrow().fill_queue.cached_prod,
            unsafe { *umem.borrow().fill_queue.producer },
            umem.borrow().fill_queue.cached_cons,
            unsafe { *umem.borrow().fill_queue.consumer },
        );
        unsafe {
            let count = libbpf_sys::_xsk_prod_nb_free(umem.borrow_mut().fill_queue.as_mut(), 10);
            dbg!(&count);
            dbg!(umem.borrow().fill_queue.size - count as u32);
        }
        dbg!(
            umem.borrow().fill_queue.cached_prod,
            unsafe { *umem.borrow().fill_queue.producer },
            umem.borrow().fill_queue.cached_cons,
            unsafe { *umem.borrow().fill_queue.consumer },
        );

        let fill_len = umem.borrow_mut().fill_count();
        dbg!(fill_len);
        assert_eq!(fill_len, 5);

        let fill_len_cached = umem.borrow_mut().fill_count_cached();
        dbg!(fill_len_cached);
        let pack = SlicedPacket::from_ethernet(&[]).unwrap();
        assert_eq!(fill_len_cached, 5);
        Ok(())
    }

    pub(crate) fn run_ping_command() -> Child {
        std::process::Command::new("ip")
            .stdout(Stdio::null())
            .args(&[
                "netns", "exec", "test", "ping", "-c", "40", "-i", "0.1", "10.1.0.2",
            ])
            .spawn()
            .unwrap()
    }

    pub(crate) fn run_udp_traffic_command() -> Child {
        std::process::Command::new("ip")
            .stdout(Stdio::null())
            .args(&[
                "netns", "exec", "test", "nping", "--udp", "-c", "1000000", "--rate", "1000000",
                "10.1.0.2",
            ])
            .spawn()
            .unwrap()
    }

    const NUM_DESCRIPTORS: u32 = 10240;

    #[test]
    #[cfg_attr(not(feature = "xdp"), ignore)]
    fn af_xdp_tx() -> Result<()> {
        let _guard = XDP_LOCK.lock().unwrap_or_else(|x| x.into_inner());
        let config = UmemConfig::default();
        let umem = Rc::new(RefCell::new(Umem::new(NUM_DESCRIPTORS, config.into())?));
        let sock_config = XskSocketConfig::builder()
            .if_name("veth1")
            .queue(0)
            .bind_flags(XskBindFlags::empty())
            .xdp_flags(XdpFlags::XDP_FLAGS_DRV_MODE)
            .rx_size(2048)
            .tx_size(2048)
            .build();

        let builder = LocalExecutorBuilder::default();
        let local = builder
            .name("main")
            .pin_to_cpu(0)
            .spin_before_park(Duration::from_secs(1))
            .make()?;

        let mut child = run_ping_command();

        local.run(async move {
            crate::timer::sleep(Duration::from_secs(1)).await;
            let mut socket = XskSocketDriver::new(sock_config, umem.clone()).unwrap();
            umem.borrow_mut().fill_descriptors(50);
            let rx = socket.consume_rx_owned(20);
            crate::timer::sleep(Duration::from_secs(4)).await;
            let res = nix::poll::poll(
                &mut [PollFd::new(socket.fd, nix::poll::PollFlags::POLLIN)],
                -1,
            );
            let available = socket.rx_count();
            assert!(available >= 20);
            let cached_avail = socket.rx_count_cached();
            dbg!(available, cached_avail);
            let mut rx = socket.consume_rx_owned(50);
            let after_available = socket.rx_count();
            let tx_count = socket.tx_count();
            let tx_count_cached = socket.tx_count_cached();
            dbg!(&rx, after_available, tx_count, tx_count_cached);

            // assert stuff
            assert_eq!(tx_count_cached, 0);
            assert_eq!(tx_count, 0);
            assert_eq!(after_available, 0);
            assert!(rx.len() >= available);
            let rx_len = rx.len();

            const SEND_COUNT: usize = 12;
            let produced = socket.produce_tx(&mut rx[..SEND_COUNT]);
            dbg!(&produced);
            if socket.tx_needs_wakeup() {
                let source = socket.kick_tx().unwrap();
                let amt = source.collect_rw().await;
                dbg!(&source, &amt);
            }
            let ready = socket.umem.borrow_mut().completions_ready();
            assert_eq!(ready, SEND_COUNT);
            unsafe {
                let count_cached = socket.umem.borrow().completion_queue.cached_prod
                    - socket.umem.borrow().completion_queue.cached_cons;
                assert_eq!(count_cached, SEND_COUNT as u32);
                let count = *socket.umem.borrow().completion_queue.producer
                    - *socket.umem.borrow().completion_queue.consumer;
                assert_eq!(count, SEND_COUNT as u32);
                dbg!(&count_cached, &count, &ready);
            }

            let mut in_queue = vec![];
            let buffers: VecDeque<_> = rx
                .into_iter()
                .filter_map(|x| {
                    if !x.in_queue {
                        return Some(x.get_buffer(umem.clone()));
                    }
                    println!("IN QUEUE: {:?}", x);
                    in_queue.push(x);
                    None
                })
                .collect();

            let res = umem.borrow_mut().consume_completions(&mut in_queue);

            println!(
                "END.. in_queue.len(): {}, consumed_completions: {}",
                in_queue.len(),
                res
            );

            in_queue.iter_mut().for_each(|x| {
                x.in_queue = false;
            });

            let queue_len = in_queue.len();
            for frame in in_queue {
                socket
                    .umem
                    .borrow_mut()
                    .free_list
                    .borrow_mut()
                    .push_back(frame);
            }
            println!(
                "Free list len: {}",
                socket.umem.borrow().free_list.borrow().len()
            );
            let fill_count = socket.umem.borrow_mut().fill_count();
            let free_list_len = socket.umem.borrow().free_list.borrow().len();
            let total = fill_count + free_list_len - queue_len;
            dbg!(
                fill_count,
                buffers.len(),
                free_list_len,
                queue_len,
                total,
                NUM_DESCRIPTORS
            );
            assert_eq!(total, NUM_DESCRIPTORS as usize);
            assert!(buffers.len() + queue_len == rx_len);
            dbg!(buffers.len() + queue_len, rx_len, total, fill_count);
        });
        child.kill().unwrap();
        Ok(())
    }

    #[test]
    #[cfg_attr(not(feature = "xdp"), ignore)]
    fn af_xdp_rx() -> Result<()> {
        let _guard = XDP_LOCK.lock().unwrap_or_else(|x| x.into_inner());
        let config = UmemConfig::default();
        let umem = Rc::new(RefCell::new(Umem::new(NUM_DESCRIPTORS, config.into())?));
        let sock_config = XskSocketConfig::builder()
            .if_name("veth1")
            .queue(0)
            .bind_flags(XskBindFlags::empty())
            .xdp_flags(XdpFlags::XDP_FLAGS_DRV_MODE)
            .rx_size(2048)
            .tx_size(2048)
            .build();

        let builder = LocalExecutorBuilder::default();
        let local = builder
            .name("main")
            .pin_to_cpu(0)
            .spin_before_park(Duration::from_secs(1))
            .make()?;

        // Run the network traffic. In this case ping in the other network namespace.
        let mut child = run_ping_command();

        local.run(async move {
            crate::timer::sleep(Duration::from_secs(1)).await;
            let mut socket = XskSocketDriver::new(sock_config, umem.clone()).unwrap();
            umem.borrow_mut().fill_descriptors(50);
            let rx = socket.consume_rx_owned(20);
            crate::timer::sleep(Duration::from_secs(4)).await;
            let res = nix::poll::poll(
                &mut [PollFd::new(socket.fd, nix::poll::PollFlags::POLLIN)],
                -1,
            );
            let available = socket.rx_count();
            assert!(available >= 20);

            // Check a bunch of the queue counts
            let cached_avail = socket.rx_count_cached();
            dbg!(available, cached_avail);

            // Actually consume some RX frames. At most will get 50 of them.
            let rx = socket.consume_rx_owned(50);
            let after_available = socket.rx_count();
            let tx_count = socket.tx_count();
            let tx_count_cached = socket.tx_count_cached();
            dbg!(&rx, after_available, tx_count, tx_count_cached);

            // assert stuff
            assert_eq!(tx_count_cached, 0);
            assert_eq!(tx_count, 0);
            assert_eq!(after_available, 0);
            assert!(rx.len() >= available);
        });

        child.kill().unwrap();
        Ok(())
    }

    #[test]
    #[cfg_attr(not(feature = "xdp"), ignore)]
    fn af_xdp_construct_xdp_socket() -> Result<()> {
        let _guard = XDP_LOCK.lock().unwrap_or_else(|x| x.into_inner());
        let config = UmemConfig::default();
        let umem = Rc::new(RefCell::new(Umem::new(NUM_DESCRIPTORS, config.into())?));
        let sock_config = XskSocketConfig::builder()
            .if_name("veth1")
            .queue(0)
            .bind_flags(XskBindFlags::XDP_USE_NEED_WAKEUP)
            .xdp_flags(XdpFlags::XDP_FLAGS_DRV_MODE | XdpFlags::XDP_FLAGS_UPDATE_IF_NOEXIST)
            .rx_size(2048)
            .tx_size(2048)
            .build();

        let builder = LocalExecutorBuilder::default();
        let local = builder
            .name("main")
            .pin_to_cpu(0)
            .spin_before_park(Duration::from_secs(1))
            .make()?;

        local.run(async move {
            let socket = XskSocketDriver::new(sock_config, umem).unwrap();
            dbg!(socket);
        });
        Ok(())
    }

    #[test]
    #[cfg_attr(not(feature = "xdp"), ignore)]
    fn construct_umem() -> Result<()> {
        let _guard = XDP_LOCK.lock().unwrap_or_else(|x| x.into_inner());
        let config = UmemConfig::default();
        let umem = Umem::new(NUM_DESCRIPTORS, config.into())?;
        dbg!(umem);

        Ok(())
    }

    #[test]
    #[cfg_attr(not(feature = "xdp"), ignore)]
    fn slice_index_memory_region() {
        let mut mm = MemoryRegion::new(4096 * 100, true).unwrap();
        let just_two = &mm[..2];
        let mutable_range = &mut mm[1..8];
        dbg!(&mutable_range);

        std::thread::sleep(Duration::from_secs(10));
    }

    #[test]
    #[cfg_attr(not(feature = "xdp"), ignore)]
    fn slice_index_memory_region_mut() {
        let mut mm = MemoryRegion::new(4096 * 10, false).unwrap();
        let mutable_range = &mut mm[1..8];
        mutable_range.copy_from_slice(b"abcdefg");
        let output = &mm[1..8];
        assert_eq!(output, b"abcdefg");
        assert_eq!(mm[..].len(), 4096 * 10);
    }

    #[derive(Debug)]
    enum SomeADT {
        First(usize),
        Second,
        Third(u8, u16),
    }

    #[derive(Debug)]
    struct HugePagesStruct {
        a: usize,
        b: String,
        c: SomeADT,
    }

    #[test]
    #[cfg_attr(not(feature = "xdp"), ignore)]
    fn create_huge_page_struct() {
        // let mut b = Box::new(String::new());
        // let x = b.as_mut_ptr();
        // isboxcopy(x);

        let prot = PROT_READ | PROT_WRITE;
        let file = -1;
        let offset = 0;
        let mut flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB;

        let mem_ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                std::mem::size_of::<HugePagesStruct>(),
                prot,
                flags,
                file,
                offset as libc::off_t,
            )
        };

        dbg!(mem_ptr);
        if mem_ptr.is_null() {
            panic!("NULL POINTER!");
        }
        unsafe {
            std::ptr::write(
                mem_ptr.cast::<HugePagesStruct>(),
                HugePagesStruct {
                    a: 0,
                    b: "basic string..".to_string(),
                    c: SomeADT::Third(10, 100),
                },
            )
        };
        let hps = unsafe { Box::from_raw(mem_ptr.cast::<HugePagesStruct>()) };
        dbg!(mem_ptr, &hps);
        std::thread::sleep(Duration::from_secs(10));
        let munmap = Box::into_raw(hps);
        unsafe { libc::munmap(munmap.cast(), std::mem::size_of::<HugePagesStruct>()) };
    }
}
