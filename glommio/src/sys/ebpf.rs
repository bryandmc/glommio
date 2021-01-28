//!
//! eBpf low level utilities and integration.
//!
//! Primarily uses libbpf (via libbpf_sys crate) to build AF_XDP support into Glommio.
//!
//!

use bitflags::bitflags;
use core::{fmt, slice};
use libc::{MAP_ANONYMOUS, MAP_FAILED, MAP_HUGETLB, MAP_PRIVATE, PROT_READ, PROT_WRITE};
use std::{
    cell::{Cell, RefCell},
    cmp,
    collections::{HashSet, VecDeque},
    convert::TryInto,
    ffi::CString,
    io,
    ops::{Index, IndexMut},
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

/// TODO: make this all adjustable / derive-able / whatever
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
// AF_XDP socket for delivering layer 2 frames directly to userspace from very early in
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
pub struct XskSocketDriver {
    socket: Box<xsk_socket>,
    rx_queue: Box<xsk_ring_cons>,
    tx_queue: Box<xsk_ring_prod>,
    config: XskSocketConfig,
    umem: Rc<RefCell<Umem>>,
    reactor: Weak<Reactor>,
    fd: RawFd,
}

impl XskSocketDriver {
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

        dbg!(umem_ptr);
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

    /// Consumes descriptors from the RX queue
    pub(crate) fn consume_rx(&mut self, descriptors: &mut [FrameRef]) -> usize {
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
            let count_usize = count.try_into().unwrap();
            for desc in descriptors.iter_mut().take(count_usize) {
                let rx_descriptor =
                    libbpf_sys::_xsk_ring_cons__rx_desc(self.rx_queue.as_ref(), idx);
                desc.addr = (*rx_descriptor).addr;
                desc.len = (*rx_descriptor).len;
                desc.options = (*rx_descriptor).options;
                idx += 1;
            }
            libbpf_sys::_xsk_ring_cons__release(self.rx_queue.as_mut(), count);
            count_usize
        }
    }

    /// Consumes descriptors from the RX queue
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
                println!(
                    "Consuming descriptor: '{}' (index: {}, frame len: {})",
                    frame.addr, idx, frame.len
                );
                recv_descriptors.push(frame);
                idx += 1;
            }
            libbpf_sys::_xsk_ring_cons__release(self.rx_queue.as_mut(), count);
        }
        recv_descriptors
    }

    /// Adds descriptors to the TX queue
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
                (*x).addr = desc.addr;
                (*x).len = desc.len;
                (*x).options = desc.options;
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
                // println!(
                //     "TX QUEUE: consumer: {}, producer: {}. Cached: ( consumer: {}, producer: {} )",
                //     *self.tx_queue.consumer,
                //     *self.tx_queue.producer,
                //     self.tx_queue.cached_cons,
                //     self.tx_queue.cached_cons
                // );
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
            // let count = libbpf_sys::_xsk_ring_prod__reserve(self.tx_queue.as_mut(), nb, &mut idx);
            println!("Have room for {} entries in the TX queue", count);
            if count == 0 {
                return (0, None);
            }
            let pending = &mut self.umem.borrow_mut().pending_completions;
            let usable_descriptors = descriptors.drain(..(count as usize));

            for desc in usable_descriptors {
                let x = libbpf_sys::_xsk_ring_prod__tx_desc(self.tx_queue.as_mut(), idx);
                {
                    let fr = &mut desc.inner.borrow_mut().frame;
                    (*x).addr = fr.addr;
                    (*x).len = fr.len;
                    (*x).options = fr.options;
                    fr.in_queue = true;
                }
                pending.push_back(desc);
                idx += 1;
            }
            libbpf_sys::_xsk_ring_prod__submit(self.tx_queue.as_mut(), count);
            if count > 0 && self.tx_needs_wakeup() {
                println!("Count: {}", count);
                let mut sources = vec![];
                let r = 0..((count / 16) + 1);
                dbg!(r);
                for i in 0..((count / 16) + 1) {
                    println!("Kicking for the {}/{} time.", i + 1, ((count / 16) + 2));
                    sources.push(self.kick_tx());
                }
                return (count.try_into().unwrap(), Some(sources));
            }
            (count.try_into().unwrap(), None)
        }
    }

    pub(crate) fn tx_needs_wakeup(&self) -> bool {
        unsafe {
            let need_wakeup = libbpf_sys::_xsk_ring_prod__needs_wakeup(self.tx_queue.as_ref());
            println!("Need wakeup == {}", need_wakeup);
            need_wakeup != 0
        }
    }

    pub(crate) fn fill_needs_wakeup(&self) -> bool {
        unsafe {
            let need_wakeup =
                libbpf_sys::_xsk_ring_prod__needs_wakeup(self.umem.borrow().fill_queue.as_ref());
            println!("Need wakeup == {}", need_wakeup);
            need_wakeup != 0
        }
    }

    pub(crate) fn kick_tx(&self) -> Option<Source> {
        Some(self.reactor.upgrade()?.kick_tx(self.fd))
    }

    pub(crate) fn kick_tx_sync(&self) -> Option<Source> {
        Some(
            self.reactor
                .upgrade()?
                .kick_tx_sync(self.fd, self.socket.as_ref())
                .ok()?,
        )
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
pub struct Umem {
    umem: Box<xsk_umem>,
    fill_queue: Box<xsk_ring_prod>,
    completion_queue: Box<xsk_ring_cons>,
    memory: MemoryRegion,
    pub(crate) free_list: VecDeque<FrameRef>,
    // free_set: HashSet<FrameRef>,
    pub(crate) pending_completions: VecDeque<FrameBuf>,
    frames: u32,
    frame_size: u32,
    fd: RawFd,
    fill_threshold: u32,
    completions_threshold: u32,
}

impl Umem {
    /// Create a new UMEM memory region
    ///
    pub fn new(num_descriptors: u32, config: xsk_umem_config) -> Result<Umem> {
        let mut memory_region = MemoryRegion::new(PAGE_SIZE * num_descriptors, true)?;
        dbg!(&memory_region);
        // Unsafe because this requires us to essentially create multiple mutable aliases to the same thing,
        // which is usually frowned upon by the compiler/optimizer and could cause problems but we have
        // no other choice when the 2nd mutable alias is the kernel and we are required to keep access
        // to the memory for our own use. The invariants are kept solely by use of the 4 queues.
        let mem_ptr = unsafe { memory_region.as_mut_ptr() };

        // Create empty producer and consume structures for the fill and completion queues.
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
            // unsafe { *ffi_config }.fill_size = 10_000;
            // unsafe { *ffi_config }.comp_size = 10_000;
            libbpf_sys::xsk_umem__create(umem_ptr, mem_ptr, size, fq_ptr, cq_ptr, ffi_config)
        };

        if err != 0 {
            println!("Returning early!");
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
                in_queue: false,
            });
        }
        println!("Created free_list with {} entries.", descriptors.len());

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
                pending_completions: VecDeque::new(),
                fill_threshold: config.fill_size / 2,
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

    pub(crate) fn completions_ready(&mut self) -> usize {
        unsafe {
            let avail = libbpf_sys::_xsk_cons_nb_avail(
                self.completion_queue.as_mut(),
                self.completion_queue.size,
            ) as usize;
            let consumer = *self.completion_queue.consumer;
            let producer = *self.completion_queue.producer;
            // dbg!(avail, consumer, producer);
            // (producer - consumer) as usize

            avail
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
            println!("Computing address for {} = {}", desc.addr, addr);
            desc.addr = addr;
            desc.len = 0;
            desc.options = 0;
            idx += 1;
        }
        unsafe { libbpf_sys::_xsk_ring_cons__release(self.completion_queue.as_mut(), count) };
        count.try_into().unwrap()
    }

    pub(crate) fn consume_completions_slice(&mut self, descriptors: &mut [FrameBuf]) -> usize {
        let nb = descriptors.len().try_into().unwrap();
        let mut idx = 0;
        let count = unsafe {
            libbpf_sys::_xsk_ring_cons__peek(self.completion_queue.as_mut(), nb, &mut idx)
        };
        println!(
            "There are {} entries in completion queue. Idx: {}, nb: {}",
            count, idx, nb
        );
        if count > 0 {
            for desc in descriptors.iter_mut() {
                let addr = unsafe {
                    *libbpf_sys::_xsk_ring_cons__comp_addr(self.completion_queue.as_mut(), idx)
                };
                let mut fr = desc.inner.borrow_mut();
                println!("Computing address for {} = {}", fr.frame.addr, addr);
                fr.frame.addr = addr;
                fr.frame.len = 0;
                fr.frame.options = 0;
                idx += 1;
            }
            unsafe { libbpf_sys::_xsk_ring_cons__release(self.completion_queue.as_mut(), count) };
        }
        count.try_into().unwrap()
    }

    pub(crate) fn consume_completions_queue(&mut self, size_hint: u64) -> usize {
        log_queue_counts!(self.completion_queue, "COMPLETION");
        let nb = self.pending_completions.len() as u64;
        let mut idx = 0;
        let count = unsafe {
            libbpf_sys::_xsk_ring_cons__peek(self.completion_queue.as_mut(), size_hint, &mut idx)
        };
        println!(
            "There are {} entries in completion queue ({}). Idx: {}",
            count, nb, idx
        );
        let mut i = 0;
        for _ in 0..count {
            if let Some(desc) = self.pending_completions.pop_back() {
                let addr = unsafe {
                    *libbpf_sys::_xsk_ring_cons__comp_addr(self.completion_queue.as_mut(), idx)
                };
                {
                    let mut descriptor = desc.inner.borrow_mut();
                    println!("Computing address for {} = {}", descriptor.frame.addr, addr);
                    descriptor.frame.addr = addr;
                    descriptor.frame.len = 0;
                    descriptor.frame.options = 0;
                    idx += 1;
                }
                let frame = FrameRef {
                    ..desc.inner.borrow().frame
                };
                let before = self.free_list.len();
                println!(
                    "Pushing '{:?}' onto free list. Len before: {}",
                    frame, before
                );
                self.free_list.push_back(frame);
                i += 1;
                println!("... after len: {}", self.free_list.len());
            } else {
                println!("********** ERROR **********");
                println!("pending: {}", self.pending_completions.len());
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

        let max = std::cmp::min(self.free_list.len(), count as usize);
        let descriptors = self.free_list.drain(..max as usize);
        dbg!((idx, count, amt, descriptors.len(), max));

        if count == 0 {
            return 0;
        }
        for frame in descriptors {
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

/// UMEM configuration
///
/// Used for configuring a UMEM instance with various parameters and settings.
#[derive(Debug, Clone, Copy)]
pub struct UmemConfig {
    /// Fill ring size for the UMEM. Defaults to 2048.
    pub fill_size: u32,

    /// The Completion ring size for the UMEM. Defaults to 2048.
    pub comp_size: u32,

    /// The default frame size, usually equal to a page (usually 4096 bytes)
    pub frame_size: u32,

    /// Headroom to the frame. Defaults to 0. Keep in mind it actually seems to
    /// give 256 bytes of headroom, even when set to 0 and adds whatever you set
    /// here to that 256.. That headroom is actually useful for adding encapsulation
    /// headers to the frame without having to re-allocate / re-write the frame.
    pub frame_headroom: u32,

    /// Flags for the UMEM. Defaults to 0.
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
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct FrameRef {
    /// The starting address of the frame
    pub(crate) addr: u64,
    /// The length of the frame inside the UMEM region
    pub(crate) len: u32,
    /// Options for the frame
    pub(crate) options: u32,

    pub(crate) in_queue: bool,
}

impl FrameRef {
    /// Get the underlying FrameBuf for this FrameRef
    pub fn get_buffer(self, umem: Rc<RefCell<Umem>>) -> FrameBuf {
        FrameBuf {
            inner: Rc::new(RefCell::new(InnerBuf { umem, frame: self })),
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

/// TODO: Figure out a way to make it safe to access these without accidentally
/// having multiple mutable copies or something like that.
pub struct FrameBuf {
    pub(crate) inner: Rc<RefCell<InnerBuf>>,
}

impl FrameBuf {
    /// L2 MAC destination slice
    pub fn mac_dst(&self) -> &[u8] {
        &self[..6]
    }

    /// Mutable access to L2 MAC destination slice
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
    pub fn ether_type(&self) -> u16 {
        let arr: [u8; 2] = self[12..14].try_into().unwrap();
        u16::from_be_bytes(arr)
    }

    /// Mutable access to the ethertype
    pub fn set_ether_type(&mut self, ether_type: u16) {
        let arr = ether_type.to_be_bytes();
        self[12..14].copy_from_slice(&arr);
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

impl Clone for FrameBuf {
    fn clone(&self) -> Self {
        FrameBuf {
            inner: self.inner.clone(),
        }
    }
}

pub(crate) struct InnerBuf {
    umem: Rc<RefCell<Umem>>,
    pub(crate) frame: FrameRef,
}

impl std::ops::Deref for FrameBuf {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        let inner = self.inner.borrow();
        let mut umem = inner.umem.borrow();
        unsafe {
            slice::from_raw_parts(
                umem.memory
                    .as_ptr()
                    .offset(inner.frame.addr as isize)
                    .cast::<u8>(),
                inner.frame.len as usize,
            )
        }
    }
}

impl std::ops::DerefMut for FrameBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // TODO: We may have to eventually remove the refcell wrapper because it could
        // be too easy to trip on, when we know it's actually probably safe to just give
        // out the slice assuming we don't make multiple ways to access this exact slice.
        let inner = self.inner.borrow_mut();
        let mut umem = inner.umem.borrow_mut();
        unsafe {
            slice::from_raw_parts_mut(
                umem.memory
                    .as_mut_ptr()
                    .offset(inner.frame.addr as isize)
                    .cast::<u8>(),
                inner.frame.len as usize,
            )
        }
    }
}

// impl Drop for InnerBuf {
//     fn drop(&mut self) {
//         println!("Dropping FrameBuf and putting back into free list");
//         let copied = FrameRef {
//             addr: self.frame.addr,
//             len: self.frame.len,
//             options: self.frame.options,
//             in_queue: false,
//         };
//         println!("FRAME: {:?}", copied);
//         self.umem.borrow_mut().free_list.push_back(copied);
//         println!(
//             "FREE LIST LENGTH: {}",
//             self.umem.borrow_mut().free_list.len()
//         );
//     }
// }

/// Xsk socket configuration
///
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
            addr: desc.addr,
            len: desc.len,
            options: desc.options,
            in_queue: false,
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

#[cfg(test)]
pub(crate) mod tests {
    use etherparse::SlicedPacket;
    use nix::poll::PollFd;
    use std::{
        process::{Child, Stdio},
        sync::Arc,
        time::Duration,
    };

    use crate::{LocalExecutor, LocalExecutorBuilder};
    use lazy_static::lazy_static;
    use std::sync::Mutex;

    use super::*;

    lazy_static! {
        pub static ref XDP_LOCK: Arc<Mutex<()>> = Arc::new(Mutex::new(()));
    }

    #[test]
    #[cfg_attr(not(feature = "xdp"), ignore)]
    fn af_xdp_umem_produce_fill() -> Result<()> {
        let guard = XDP_LOCK.lock().unwrap_or_else(|x| x.into_inner());
        let umem = Rc::new(RefCell::new(Umem::new(10, UmemConfig::default().into())?));
        dbg!(
            &umem,
            &umem.borrow().free_list,
            &umem.borrow().free_list.len(),
        );
        let qty = umem.borrow_mut().fill_descriptors(5);
        assert_eq!(qty, 5);
        dbg!(&umem.borrow().free_list);
        assert_eq!(umem.borrow().free_list.len(), 5);
        dbg!(
            umem.borrow().fill_queue.cached_prod,
            unsafe { *umem.borrow().fill_queue.producer },
            umem.borrow().fill_queue.cached_cons,
            unsafe { *umem.borrow().fill_queue.consumer },
        );
        unsafe {
            let count = libbpf_sys::_xsk_prod_nb_free(umem.borrow_mut().fill_queue.as_mut(), 10);
            dbg!(&count);
            dbg!((umem.borrow().fill_queue.size - count as u32));
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
                "netns", "exec", "test", "nping", "--udp", "-c", "1000000", "--rate", "10000",
                "10.1.0.2",
            ])
            .spawn()
            .unwrap()
    }

    const NUM_DESCRIPTORS: u32 = 10240;

    #[test]
    #[cfg_attr(not(feature = "xdp"), ignore)]
    fn af_xdp_tx() -> Result<()> {
        let guard = XDP_LOCK.lock().unwrap_or_else(|x| x.into_inner());
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
            // Let the ping command initially work by not engaging the xdp socket, s/t it sends at
            // full speed. This won't happen if it starts and the xdp socket just swallows the initial
            // frames
            crate::timer::sleep(Duration::from_secs(1)).await;

            // Create / engage the xdp socket
            let mut socket = XskSocketDriver::new(sock_config, umem.clone()).unwrap();

            // Fill descriptors so we can recieve frames
            umem.borrow_mut().fill_descriptors(50);

            // make an initial non-blocking, zero syscall attempt to recv frames.. usually won't receive any
            let rx = socket.consume_rx_owned(20);

            // Let some frames get sent for 4 seconds..
            crate::timer::sleep(Duration::from_secs(4)).await;
            let res = nix::poll::poll(
                &mut [PollFd::new(socket.fd, nix::poll::PollFlags::POLLIN)],
                -1,
            );
            let available = socket.rx_count();
            // @HACK Just picking 20 as a safe number that should be easy to satisfy in these conditions..
            // Usually does ~30 but wanna leave some room for a few to not make it.
            assert!(available >= 20);

            // Check a bunch of the queue counts
            let cached_avail = socket.rx_count_cached();
            dbg!(available, cached_avail);

            // Actually consume some RX frames. At most will get 50 of them.
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
                socket.umem.borrow_mut().free_list.push_back(frame);
            }
            println!("Free list len: {}", socket.umem.borrow().free_list.len());
            let fill_count = socket.umem.borrow_mut().fill_count();
            let free_list_len = socket.umem.borrow().free_list.len();
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
        let guard = XDP_LOCK.lock().unwrap_or_else(|x| x.into_inner());
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
            // Let the ping command initially work by not engaging the xdp socket, s/t it sends at
            // full speed. This won't happen if it starts and the xdp socket just swallows the initial
            // frames
            crate::timer::sleep(Duration::from_secs(1)).await;

            // Create / engage the xdp socket
            let mut socket = XskSocketDriver::new(sock_config, umem.clone()).unwrap();

            // Fill descriptors so we can recieve frames
            umem.borrow_mut().fill_descriptors(50);

            // make an initial non-blocking, zero syscall attempt to recv frames.. usually won't receive any
            let rx = socket.consume_rx_owned(20);

            // Let some frames get sent for 4 seconds..
            crate::timer::sleep(Duration::from_secs(4)).await;
            let res = nix::poll::poll(
                &mut [PollFd::new(socket.fd, nix::poll::PollFlags::POLLIN)],
                -1,
            );
            let available = socket.rx_count();
            // @HACK Just picking 20 as a safe number that should be easy to satisfy in these conditions..
            // Usually does ~30 but wanna leave some room for a few to not make it.
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
        let guard = XDP_LOCK.lock().unwrap_or_else(|x| x.into_inner());
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
        let guard = XDP_LOCK.lock().unwrap_or_else(|x| x.into_inner());
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
}
