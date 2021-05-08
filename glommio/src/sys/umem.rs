//!
//! Umem - uniform memory region, used for af_xdp socket

use core::{fmt, slice};
use std::{
    borrow::BorrowMut,
    cell::Cell,
    cmp,
    collections::VecDeque,
    convert::TryInto,
    io,
    io::prelude::*,
    marker::PhantomData,
    net::Ipv4Addr,
    ops::{self, Index, IndexMut, Range},
    os::unix::io::{AsRawFd, RawFd},
    ptr,
    slice::SliceIndex,
};

use libbpf_sys::{
    xsk_ring_cons, xsk_ring_prod, xsk_umem, xsk_umem_config, XSK_RING_CONS__DEFAULT_NUM_DESCS,
    XSK_RING_PROD__DEFAULT_NUM_DESCS, XSK_UMEM__DEFAULT_FLAGS, XSK_UMEM__DEFAULT_FRAME_HEADROOM,
    XSK_UMEM__DEFAULT_FRAME_SIZE,
};
use libc::{MAP_ANONYMOUS, MAP_FAILED, MAP_HUGETLB, MAP_PRIVATE, PROT_READ, PROT_WRITE};

use crate::GlommioError;

type Result<T> = std::result::Result<T, GlommioError<()>>;

const PAGE_SIZE: u32 = 4096;

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct FrameRef {
    pub(crate) addr: Cell<u64>,
    pub(crate) len: Cell<u32>,
    pub(crate) options: Cell<u32>,
}

pub struct Umem<'umem> {
    umem: Box<xsk_umem>,
    fill_queue: Box<libbpf_sys::xsk_ring_prod>,
    completion_queue: Box<libbpf_sys::xsk_ring_cons>,
    frames: u32,
    frame_size: u32,
    fd: RawFd,
    config: UmemConfig,

    memory: MemoryRegion,
    free_frames: VecDeque<Box<FrameRef>>,
    filled_frames: VecDeque<Box<FrameRef>>,
    __lifetime: PhantomData<&'umem ()>,
}

impl<'umem> Umem<'umem> {
    pub fn new(config: impl Into<UmemConfig>) -> Result<Umem<'umem>> {
        let config: UmemConfig = config.into();
        let huge = config.use_huge_pages;
        let num_descriptors = config.num_descriptors;
        let ffi_config: xsk_umem_config = config.into();
        let mut memory_region = MemoryRegion::new(PAGE_SIZE * num_descriptors, huge)?;
        tracing::trace!("Memory region: {:#?}", &memory_region);
        let mem_ptr = unsafe { memory_region.as_mut_ptr() };

        // Create empty producer and consume structures for the fill and completion
        // queues.
        let fq: Box<xsk_ring_prod> = Default::default();
        let cq: Box<xsk_ring_cons> = Default::default();

        let ffi_config = ptr::addr_of!(ffi_config);
        let mut umem: *mut xsk_umem = ptr::null_mut();
        let umem_ptr = ptr::addr_of_mut!(umem);
        let size = num_descriptors as u64 * 4096;
        let fq_ptr = Box::into_raw(fq);
        let cq_ptr = Box::into_raw(cq);

        // Create the actual UMEM
        tracing::trace!("FFI config: {:#?}", unsafe { *ffi_config });
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

        let mut descriptors: VecDeque<Box<FrameRef>> =
            VecDeque::with_capacity(num_descriptors.try_into()?);
        for i in 0..num_descriptors {
            descriptors.push_back(Box::new(FrameRef {
                addr: Cell::new((i as u64) * (config.frame_size as u64)),
                len: Cell::new(0),
                options: Cell::new(0),
            }));
        }
        tracing::debug!("Created free_list with {} entries.", descriptors.len());

        unsafe {
            Ok(Umem {
                umem: umem_box,
                fill_queue: Box::from_raw(fq_ptr),
                completion_queue: Box::from_raw(cq_ptr),
                frames: num_descriptors,
                frame_size: 4096,
                fd: fd.as_raw_fd(),
                memory: memory_region,
                free_frames: descriptors,
                config,

                /// Filled frames (frames put into fill queue). We don't want to
                /// ever allocate during the operation of the socket so we make
                /// the ringbuf the size of the number of descriptors. This is
                /// inherently somewhat wasteful but luckily each element is
                /// only a pointer size.
                filled_frames: VecDeque::with_capacity(num_descriptors.try_into()?),
                __lifetime: Default::default(),
            })
        }
    }

    pub fn memory(&self) -> &MemoryRegion {
        &self.memory
    }

    pub fn memory_mut(&mut self) -> &mut MemoryRegion {
        &mut self.memory
    }

    pub fn from_ref(&mut self, rref: Box<FrameRef>) -> Option<FrameBuf<'umem>> {
        let memory_root_ptr = unsafe { self.memory.as_mut_ptr() };
        let mem_ptr = unsafe {
            memory_root_ptr
                .offset(rref.addr.get() as isize)
                .cast::<u8>()
        };
        let mptr = match ptr::NonNull::new(mem_ptr) {
            Some(mptr) => mptr,
            None => {
                tracing::warn!("Invalid pointer, cannot turn into NonNull..");
                return None;
            } // bail out here, and we'll filter them out
        };
        let this = ptr::addr_of_mut!(*self);
        let x = Inner {
            data: Buf {
                ptr: mptr,
                len: rref.len.get() as usize,
            },
            frame: unsafe { ptr::NonNull::new_unchecked(Box::into_raw(rref)) },
            ref_cnt: 1.into(),
            umem: this,
        };
        let inner_ptr = Box::into_raw(Box::new(x));
        let iptr = match ptr::NonNull::new(inner_ptr) {
            Some(iptr) => iptr,
            None => {
                tracing::warn!("Invalid pointer, cannot turn into NonNull, removing..");
                return None;
            } // bail out here, and we'll filter them out
        };

        Some(FrameBuf {
            ptr: iptr,
            phantom: Default::default(),
        })
    }

    pub fn alloc(&mut self, frames: impl Into<Option<usize>>) -> Vec<FrameBuf<'umem>> {
        let frame_size = self.frame_size;
        let drained: Vec<_> = self
            .free_frames
            .drain(..frames.into().unwrap_or(1))
            .collect();

        let filtered: Vec<_> = drained
            .into_iter()
            .filter_map(|rref| self.from_ref(rref))
            .map(|buf| {
                let inner = unsafe { buf.ptr.as_ref().frame.as_ref() };
                inner.len.set(frame_size);
                buf
            })
            .collect();

        tracing::debug!(
            "'Allocated' {} frames from UMEM fd #{} ({:?})..",
            filtered.len(),
            self.fd,
            self.umem
        );
        filtered
    }

    pub fn umem_ptr(&mut self) -> *mut libbpf_sys::xsk_umem {
        self.umem.as_mut() as _
    }

    pub fn fq(&self) -> &libbpf_sys::xsk_ring_prod {
        self.fill_queue.as_ref()
    }

    pub fn fq_mut(&mut self) -> &mut libbpf_sys::xsk_ring_prod {
        self.fill_queue.as_mut()
    }

    pub fn cq(&self) -> &libbpf_sys::xsk_ring_cons {
        self.completion_queue.as_ref()
    }

    pub fn cq_mut(&mut self) -> &mut libbpf_sys::xsk_ring_cons {
        self.completion_queue.as_mut()
    }

    pub fn fill_frames(&mut self, mut amt: usize) -> usize {
        log_queue_counts!(self.fill_queue, "FILL");
        tracing::trace!("Going to attempt to fill {} descriptors..", amt);
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

        let max = cmp::min(self.free_frames.len(), count as usize);
        let descriptors = self.free_frames.drain(..max as usize);
        dbg!((idx, count, amt, descriptors.len(), max));

        if max == 0 {
            return 0;
        }
        for frame in descriptors {
            unsafe {
                let f = libbpf_sys::_xsk_ring_prod__fill_addr(self.fill_queue.as_mut(), idx);
                *f = frame.addr.get();
                tracing::debug!("Filling frame: {:?}, with addr: {:?}", frame, f);
                assert_eq!(*f, frame.addr.get());
            };
            idx += 1;
            self.filled_frames.push_back(frame);
        }
        // Actually submit "count" entries to the fill ring.
        unsafe { libbpf_sys::_xsk_ring_prod__submit(self.fill_queue.as_mut(), count) };
        tracing::debug!("Submitted {} frames to fill ring..", count);
        count.try_into().unwrap()
    }

    pub(crate) fn filled_frames(&self) -> &VecDeque<Box<FrameRef>> {
        &self.filled_frames
    }

    pub(crate) fn filled_frames_mut(&mut self) -> &mut VecDeque<Box<FrameRef>> {
        &mut self.filled_frames
    }

    pub(crate) fn free_frames_mut(&mut self) -> &mut VecDeque<Box<FrameRef>> {
        &mut self.free_frames
    }

    pub(crate) fn free_frames(&self) -> &VecDeque<Box<FrameRef>> {
        &self.free_frames
    }

    /// Safety: This should be safe, despite having to coerce a shared reference
    /// to a mutable pointer. Technically the "mutation" would be updating the
    /// cached count so I think it should be OK.
    pub(crate) fn fill_count(&self) -> usize {
        (self.config.fill_size
            - unsafe {
                libbpf_sys::_xsk_prod_nb_free(
                    self.fill_queue.as_ref() as *const _ as *mut _,
                    self.frames,
                ) as u32
            }) as usize
    }

    /// Safety: This should be safe, despite having to coerce a shared reference
    /// to a mutable pointer. Technically the "mutation" would be updating the
    /// cached count so I think it should be OK.
    pub(crate) fn completions(&self) -> usize {
        unsafe {
            libbpf_sys::_xsk_cons_nb_avail(
                self.completion_queue.as_ref() as *const _ as *mut _,
                self.config.comp_size,
            ) as usize
        }
    }
}

impl<'umem> fmt::Debug for Umem<'umem> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Umem")
            .field("umem", &self.umem)
            .field("fill_queue", &self.fill_queue)
            .field("completion_queue", &self.completion_queue)
            .field("frames", &self.frames)
            .field("frame_size", &self.frame_size)
            .field("fd", &self.fd)
            .field("memory", unsafe { &self.memory.as_ptr() })
            .field("free_frames[len]", &self.free_frames.len())
            .finish()
    }
}

impl<'umem> Drop for Umem<'umem> {
    fn drop(&mut self) {
        unsafe {
            tracing::trace!(
                "Dropping UMEM (fd: {}) region of size: {}..",
                self.fd,
                self.frames
            );
            let resp = libbpf_sys::xsk_umem__delete(self.umem.as_mut());
            if resp < 0 {
                let err = io::Error::from_raw_os_error(-resp);
                tracing::error!("Error: {}", &err);
            }
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

#[derive(Debug, Clone, Copy)]
pub struct UmemConfig {
    pub fill_size: u32,
    pub comp_size: u32,
    pub frame_size: u32,
    pub frame_headroom: u32,
    pub flags: u32,
    pub num_descriptors: u32,
    pub use_huge_pages: bool,
}

#[derive(Debug)]
pub struct UmemBuilder {
    fill_size: u32,
    comp_size: u32,
    frame_size: u32,
    frame_headroom: u32,
    flags: u32,
    num_descriptors: u32,
    use_huge_pages: bool,
}

impl UmemBuilder {
    pub fn new(num_descriptors: u32) -> UmemBuilder {
        UmemBuilder {
            fill_size: XSK_RING_CONS__DEFAULT_NUM_DESCS,
            comp_size: XSK_RING_PROD__DEFAULT_NUM_DESCS,
            frame_size: XSK_UMEM__DEFAULT_FRAME_SIZE,
            frame_headroom: XSK_UMEM__DEFAULT_FRAME_HEADROOM,
            flags: XSK_UMEM__DEFAULT_FLAGS,
            num_descriptors,
            use_huge_pages: false,
        }
    }

    pub fn fill_queue_size(self, fill_size: u32) -> Self {
        UmemBuilder { fill_size, ..self }
    }

    pub fn completion_queue_size(self, comp_size: u32) -> Self {
        UmemBuilder { comp_size, ..self }
    }

    pub fn frame_size(self, frame_size: u32) -> Self {
        UmemBuilder { frame_size, ..self }
    }

    pub fn frame_headroom(self, frame_headroom: u32) -> Self {
        UmemBuilder {
            frame_headroom,
            ..self
        }
    }

    pub fn flags(self, flags: u32) -> Self {
        UmemBuilder { flags, ..self }
    }

    pub fn use_huge_pages(self, use_huge_pages: bool) -> Self {
        UmemBuilder {
            use_huge_pages,
            ..self
        }
    }

    pub fn build<'umem>(self) -> Result<Umem<'umem>> {
        Umem::new(self)
    }
}

impl From<UmemBuilder> for UmemConfig {
    fn from(builder: UmemBuilder) -> Self {
        UmemConfig {
            fill_size: builder.fill_size,
            comp_size: builder.comp_size,
            frame_size: builder.frame_size,
            frame_headroom: builder.frame_headroom,
            flags: builder.flags,
            num_descriptors: XSK_RING_CONS__DEFAULT_NUM_DESCS * 2,
            use_huge_pages: false,
        }
    }
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
            num_descriptors: XSK_RING_CONS__DEFAULT_NUM_DESCS * 2,
            use_huge_pages: false,
        }
    }
}

/// TODO: Figure out a way to make it safe to access these without accidentally
/// having multiple mutable copies or something like that.
///
/// Currently you can have multiple mutable 'handles' to the same underlying
/// frame. The reference counting makes this safe from a destructor/drop side
/// but still makes it possible to have two of those copies being mutated at
/// once. It's hard to know how to resolve this without losing mutability
/// altogether, or without runtime checks that might be overly costly.
#[derive(Debug)]
pub struct FrameBuf<'umem> {
    ptr: ptr::NonNull<Inner<'umem>>,
    phantom: PhantomData<&'umem ()>,
}

impl<'umem> Drop for FrameBuf<'umem> {
    fn drop(&mut self) {
        let ptr = self.ptr.as_ptr();
        if !ptr.is_null() {
            unsafe {
                let inner = &*ptr;
                let count = inner.ref_cnt.replace(inner.ref_cnt.get() - 1) - 1;
                tracing::trace!("[DROP] Refcount: {}, obj: {:?}", count, inner);
                if count == 0 {
                    let frame = (*ptr).frame;
                    let framebox = Box::from_raw(frame.as_ptr());
                    let queue = &mut (*inner.umem).borrow_mut().free_frames;
                    queue.push_back(framebox);
                }
            }
        }
    }
}

impl<'umem> Clone for FrameBuf<'umem> {
    fn clone(&self) -> Self {
        let ptr = self.ptr.as_ptr();
        match unsafe { ptr.as_ref() } {
            Some(inner) => {
                inner.ref_cnt.set(inner.ref_cnt.get() + 1);
                FrameBuf {
                    ptr: self.ptr, // ptr::NonNull::new_unchecked(ptr),
                    phantom: Default::default(),
                }
            }
            None => {
                panic!(
                    "Invalid inner pointer! Pointer is null or incorrect: {:?}",
                    ptr
                );
            }
        }
    }
}

impl<'umem> FrameBuf<'umem> {
    const MAC_DST: Range<usize> = 0..6;
    const MAC_SRC: Range<usize> = 6..12;
    const ETHER_TYPE: Range<usize> = 12..14;
    const IP_SIZE: Range<usize> = 16..18;
    const IP_IDENTIFICATION: Range<usize> = 18..20;
    const IP_FRAGMENT_OFFSET: Range<usize> = 20..22;
    const IP_CHECKSUM: Range<usize> = 24..26;
    const IP_SRC: Range<usize> = 26..30;
    const IP_DST: Range<usize> = 30..34;
    const IP_OPTIONS: Range<usize> = 34..38;

    pub(crate) fn ptr_mut(&mut self) -> *mut Inner<'umem> {
        self.ptr.as_ptr()
    }

    pub(crate) fn buf(&self) -> &Buf {
        &unsafe { self.ptr.as_ref() }.data
    }

    pub(crate) fn buf_mut(&mut self) -> &mut Buf {
        &mut unsafe { self.ptr.as_mut() }.data
    }

    /// TODO: remove option
    pub fn frame_addr(&self) -> Option<u64> {
        Some(unsafe { self.ptr.as_ref().frame.as_ref() }.addr.get())
    }

    /// Can fail, if frame pointer is null.
    pub fn set_frame_addr(&mut self, addr: u64) {
        let inner = unsafe { self.ptr.as_ref().frame.as_ref() };
        inner.addr.set(addr);
        unsafe {
            let ptr = self
                .ptr
                .as_mut()
                .umem
                .as_mut()
                .unwrap()
                .memory_mut()
                .as_mut_ptr();
            self.buf_mut().set_ptr(ptr.offset(addr as isize).cast());
        }
    }

    pub fn frame_len(&self) -> u32 {
        unsafe { self.ptr.as_ref().frame.as_ref() }.len.get()
    }

    /// Can fail, if frame pointer is null.
    pub fn set_frame_len(&mut self, len: u32) {
        let inner = unsafe { self.ptr.as_ref().frame.as_ref() };
        inner.len.set(len);
        unsafe { self.ptr.as_mut() }.data.set_len(len as usize);
    }

    /// TODO: remove option
    pub fn frame_options(&self) -> Option<u32> {
        Some(unsafe { self.ptr.as_ref().frame.as_ref() }.options.get())
    }

    pub fn set_frame_options(&mut self, options: u32) {
        unsafe { self.ptr.as_ref().frame.as_ref() }
            .options
            .set(options);
    }

    pub fn mac_dst(&self) -> &[u8] {
        &self[Self::MAC_DST]
    }

    pub fn mac_dst_mut(&mut self) -> &mut [u8] {
        &mut self[Self::MAC_DST]
    }

    /// L2 MAC source slice
    pub fn mac_src(&self) -> &[u8] {
        &self[Self::MAC_SRC]
    }

    /// Mutable L2 MAC source slice
    pub fn mac_src_mut(&mut self) -> &mut [u8] {
        &mut self[Self::MAC_SRC]
    }

    /// The ethertype of the frame
    pub fn ether_type_raw(&self) -> u16 {
        let arr: [u8; 2] = self[Self::ETHER_TYPE].try_into().unwrap();
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
        self[Self::ETHER_TYPE].copy_from_slice(&arr);
    }

    pub fn ip_header_len(&self) -> u8 {
        (self[14] & 0b00001111) * 4
    }

    pub fn ip_tos(&self) -> u8 {
        self[15]
    }

    pub fn ip_total_size(&self) -> &[u8] {
        &self[Self::IP_SIZE]
    }

    pub fn ip_identification(&self) -> &[u8] {
        &self[Self::IP_IDENTIFICATION]
    }

    pub fn ip_fragment_offset(&self) -> &[u8] {
        &self[Self::IP_FRAGMENT_OFFSET]
    }

    pub fn ip_ttl(&self) -> u8 {
        self[22]
    }

    pub fn ip_protocol(&self) -> u8 {
        self[23]
    }

    pub fn ip_checksum(&self) -> &[u8] {
        &self[Self::IP_CHECKSUM]
    }

    pub fn ip_src_raw(&self) -> &[u8] {
        &self[Self::IP_SRC]
    }

    pub fn ip_src(&self) -> Ipv4Addr {
        u32::from_be_bytes(self.ip_src_raw().try_into().unwrap()).into()
    }

    pub fn ip_src_mut(&mut self) -> &mut [u8] {
        &mut self[Self::IP_SRC]
    }

    pub fn set_ip_src(&mut self, ip: Ipv4Addr) {
        let ip_le: u32 = ip.into();
        self.ip_src_mut().copy_from_slice(&ip_le.to_be_bytes());
    }

    pub fn ip_dst_raw(&self) -> &[u8] {
        &self[Self::IP_DST]
    }

    pub fn ip_dst(&self) -> Ipv4Addr {
        u32::from_be_bytes(self.ip_dst_raw().try_into().unwrap()).into()
    }

    pub fn ip_dst_mut(&mut self) -> &mut [u8] {
        &mut self[Self::IP_DST]
    }

    pub fn set_ip_dst(&mut self, ip: Ipv4Addr) {
        let ip_le: u32 = ip.into();
        self.ip_dst_mut().copy_from_slice(&ip_le.to_be_bytes());
    }

    pub fn ip_options(&self) -> &[u8] {
        &self[Self::IP_OPTIONS]
    }

    pub fn calculate_ipv4_csum(&mut self) {
        let csum = checksum(&self[14..(14 + self.ip_header_len()) as usize]);
        self[Self::IP_CHECKSUM].copy_from_slice(&csum.to_be_bytes());
    }

    pub(crate) unsafe fn frame_ptr(&mut self) -> *mut FrameRef {
        unsafe { self.ptr.as_mut() }.frame.as_ptr()
    }
}

pub(crate) struct UdpPacket<'umem> {
    frame: FrameBuf<'umem>,
}

impl UdpPacket<'_> {
    const SRC: Range<usize> = 34..36;
    const DST: Range<usize> = 36..38;
    const LEN: Range<usize> = 38..40;
    const CSUM: Range<usize> = 40..42;

    pub(crate) fn new(frame: FrameBuf<'_>) -> UdpPacket<'_> {
        assert!(frame.frame_len() >= 42);
        assert_eq!(frame.ip_protocol(), 17);
        UdpPacket { frame }
    }

    pub(crate) fn src_port(&self) -> u16 {
        self.extract_u16(Self::SRC)
    }

    pub(crate) fn set_src_port(&mut self, src: u16) {
        self.insert_u16(src, Self::SRC);
    }

    pub(crate) fn dst_port(&self) -> u16 {
        self.extract_u16(Self::DST)
    }

    pub(crate) fn set_dst_port(&mut self, dst: u16) {
        self.insert_u16(dst, Self::DST);
    }

    pub(crate) fn len(&self) -> u16 {
        self.extract_u16(Self::LEN)
    }

    pub(crate) fn set_len(&mut self, len: u16) {
        self.insert_u16(len, Self::LEN);
    }

    pub(crate) fn checksum(&self) -> u16 {
        self.extract_u16(Self::CSUM)
    }

    pub(crate) fn set_checksum(&mut self, checksum: u16) {
        self.insert_u16(checksum, Self::CSUM);
    }

    fn extract_u16(&self, range: Range<usize>) -> u16 {
        let data = &self.frame[range];
        u16::from_be_bytes(data.try_into().unwrap())
    }

    fn insert_u16(&mut self, val: u16, range: Range<usize>) {
        self.frame[range].copy_from_slice(&val.to_be_bytes());
    }
}

fn read_u16_be<IO: Read>(mut cursor: IO) -> Result<u16> {
    let mut buf = [0u8; 2];
    cursor.read_exact(&mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

/// Calculate the checksum for an IPv4 packet.
pub fn checksum(buffer: &[u8]) -> u16 {
    use std::io::Cursor;

    let mut result = 0xffffu32;
    let mut buffer = Cursor::new(buffer);

    while let Ok(value) = read_u16_be(&mut buffer) {
        // Skip checksum field.
        if buffer.position() == 12 {
            continue;
        }

        result += u32::from(value);

        if result > 0xffff {
            result -= 0xffff;
        }
    }

    !result as u16
}

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

#[derive(Debug)]
pub(crate) struct Inner<'umem> {
    data: Buf,
    pub(crate) frame: ptr::NonNull<FrameRef>,
    ref_cnt: Cell<usize>,
    umem: *mut Umem<'umem>,
}

#[derive(Debug)]
pub(crate) struct Buf {
    ptr: ptr::NonNull<u8>,
    len: usize,
}

impl Buf {
    pub(crate) fn set_len(&mut self, len: usize) {
        self.len = len;
    }

    pub(crate) fn set_ptr(&mut self, ptr: *mut u8) {
        self.ptr = unsafe { ptr::NonNull::new_unchecked(ptr) };
    }
}

impl<'umem> ops::Deref for Buf {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe { slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl<'umem> ops::DerefMut for Buf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl<'umem> ops::Deref for FrameBuf<'umem> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe { &self.ptr.as_ref().data }
    }
}

impl<'umem> ops::DerefMut for FrameBuf<'umem> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut self.ptr.as_mut().data }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr::NonNull;

    #[test]
    #[cfg_attr(not(feature = "xdp"), ignore)]
    fn create_um() {
        tracing_subscriber::fmt()
            .with_env_filter("glommio=trace")
            .with_thread_names(true)
            .init();
        tracing::info!("Logging started...");

        // for frame in frames {}
        let (outer, ptr) = {
            let mut um = Umem::new(UmemBuilder::new(100)).unwrap();
            let x = &um as *const Umem<'_>;
            let frames = um.alloc(10);
            assert_eq!(frames.len(), 10);
            let frame = &frames[0];
            let frame_cloned = frame.clone();
            let ip = frame_cloned.ip_dst();
            let csum = frame_cloned.ip_checksum();
            tracing::debug!("IP: {:#?}, checksum: {:#?}", ip, csum);
            let extended_lifetime_frame = frame.clone();
            let slice = &extended_lifetime_frame[..100];
            (frames, x)
        };

        drop(outer);
        unsafe {
            let y = &*ptr;
            dbg!(y.memory(), y.fd);
        }
    }

    struct Y;

    struct X {
        inner: NonNull<Y>,
    }

    impl Drop for X {
        fn drop(&mut self) {
            println!("Dropping X..");
        }
    }

    impl Drop for Y {
        fn drop(&mut self) {
            println!("Dropping Y..");
        }
    }

    #[test]
    fn test_logging() {
        tracing_subscriber::fmt()
            .with_env_filter("glommio=trace")
            .init();
        tracing::info!("LOGGING WORKS");
        tracing::trace!("TRACE LEVEL");
        tracing::debug!("DEBUG LEVEL");
    }

    #[test]
    fn test_nonnull_drop() {
        unsafe {
            let x = X {
                inner: NonNull::new_unchecked(Box::into_raw(Box::new(Y {}))),
            };

            let a = Box::into_raw(Box::new(String::from("Some string data here..")));
            let cell = Cell::new(a);
            let inner = cell.get();
            dbg!(cell, inner);
        }
    }
}