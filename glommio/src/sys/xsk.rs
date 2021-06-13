//!
//! xsk.rs - low leve AF_XDP socket support

use std::{
    borrow::Borrow,
    cell::{Cell, RefCell, UnsafeCell},
    collections::VecDeque,
    convert::TryInto,
    ffi::CString,
    io, mem,
    os::unix::prelude::{IntoRawFd, RawFd},
    ptr::{self, addr_of},
    rc::Rc,
    time::Duration,
};

use crate::{parking, ref_cnt, Local};
use bitflags::bitflags;
use nix::sys::socket::SetSockOpt;

use super::{
    add_source,
    umem::{self, Umem},
    Source, UringCommon,
};

use crate::GlommioError;

const SO_PREFER_BUSY_POLL: i32 = 69;
const SO_BUSY_POLL_BUDGET: i32 = 70;
const SO_BUSY_POLL: i32 = libc::SO_BUSY_POLL;
const SO_ATTACH_REUSEPORT_EBPF: i32 = libc::SO_ATTACH_REUSEPORT_EBPF;

type Result<T> = std::result::Result<T, GlommioError<()>>;

/// TODO: figure out defaults
const FILL_LINE_DEFAULT: usize = 1024;
const FILL_COUNT_DEFAULT: usize = 1024;

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

/// QueueId for identifying which NIC queue the socket is bound to
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct QueueId(pub u32);

impl From<u32> for QueueId {
    fn from(from: u32) -> Self {
        QueueId(from)
    }
}

/// Wrapper structure to combine the different elements into a unified "reactor"
/// type for managing af_xdp sockets.
#[derive(Debug)]
pub struct Reactor {
    inner: RefCell<InnerReactor>,
}

#[derive(Debug)]
struct InnerReactor {
    mempool: Option<umem::MemPool>,
    socket: Option<Socket>,
    rx_packet_buffers: RefCell<VecDeque<umem::FrameBuf>>,
    tx_packet_buffers: RefCell<VecDeque<umem::FrameBuf>>,
    fill_line: Cell<usize>,
    fill_count: Cell<usize>,
}

impl Reactor {
    /// Creates a new XDP reactor
    pub fn new(mempool: Option<umem::MemPool>) -> Reactor {
        Reactor {
            inner: RefCell::new(InnerReactor {
                mempool,
                socket: None,
                rx_packet_buffers: RefCell::new(VecDeque::with_capacity(1024)),
                tx_packet_buffers: RefCell::new(VecDeque::with_capacity(1024)),
                fill_line: Cell::new(FILL_LINE_DEFAULT),
                fill_count: Cell::new(FILL_COUNT_DEFAULT),
            }),
        }
    }

    /// Get the registered mempool, if one exists
    pub(crate) fn mempool(&self) -> Option<umem::MemPool> {
        self.inner.borrow().mempool.clone()
    }

    /// Get the registered socket, if one exists
    pub(crate) fn socket(&self) -> Option<Socket> {
        self.inner.borrow().socket.clone()
    }

    /// Register a memory pool (UMEM)
    pub(crate) fn register_mempool(&self, mempool: umem::MemPool) {
        self.inner.borrow_mut().mempool = Some(mempool);
    }

    /// Register an AF_XDP socket using the provided config as it's definition
    pub(crate) fn register_socket(&self, config: XskConfig) -> Result<Socket> {
        let mut inner = self.inner.borrow_mut();
        if let Some(ref mpool) = inner.mempool {
            let new_socket = ref_cnt!(XskSocketDriver::new(config, mpool.clone())?);
            inner.socket = Some(new_socket.clone());
            return Ok(new_socket);
        }

        todo!("Setup error type for xdp reactor");
    }

    /// The current order of operations:
    ///   - reap recv
    ///   - dispatch tx
    ///   - reap completions
    ///   - refill fill
    pub(crate) fn poll_io(&self, max_run_duration: Duration) -> Result<()> {
        let now = std::time::Instant::now();
        let uring_reactor = Local::get_reactor();

        loop {
            let queue = (*uring_reactor.sys.latency_ring.borrow_mut()).submission_queue();
            let recvd = self.poll_rx()?;
            let sources = self.dispatch_tx();
            for source in sources {
                add_source(&source, queue.clone());
            }
            let completed = self.reap_completions()?;
            self.refill();
            let elapsed = now.elapsed();
            if elapsed > max_run_duration {
                return Ok(());
            }
        }
    }

    pub(crate) fn poll_rx(&self) -> Result<usize> {
        let inner = self.inner.borrow_mut();
        if let Some(ref socket) = inner.socket {
            let read: usize = unsafe {
                socket
                    .borrow_mut()
                    .consume_rx_pool(&mut inner.rx_packet_buffers.borrow_mut())
            }
            .try_into()?;
            return Ok(read);
        }
        Ok(0)
    }

    pub(crate) fn dispatch_tx(&self) -> Vec<Source> {
        let inner = self.inner.borrow_mut();
        let mut sources = vec![];

        if let Some(ref socket) = inner.socket {
            let isempty = inner.tx_packet_buffers.borrow().is_empty();
            let mut produced = 0;
            if !isempty {
                produced = socket
                    .borrow_mut()
                    .produce_tx_pool(&mut inner.tx_packet_buffers.borrow_mut());
            }
            if (**socket).borrow().tx_needs_wakeup() {
                sources = socket.borrow_mut().kick_tx(produced);
            }
        }
        sources
    }

    fn reap_completions(&self) -> Result<usize> {
        let inner = self.inner.borrow_mut();
        if let Some(ref socket) = inner.socket {
            let completions = socket.borrow_mut().consume_completions()?;
            return Ok(completions);
        }
        Ok(0)
    }

    fn refill(&self) {
        let inner = self.inner.borrow_mut();
        if let Some(ref mempool) = inner.mempool {
            let fill_count = (**mempool).borrow().fill_count();
            if fill_count < inner.fill_line.get() {
                mempool.borrow_mut().fill_frames(inner.fill_count.get());
            }
        }
    }

    pub(crate) fn stage_tx_descriptors(&self, frames: &mut VecDeque<umem::FrameBuf>) {
        let inner = self.inner.borrow();
        let mut tx_buffers = inner.tx_packet_buffers.borrow_mut();
        while let Some(frame) = frames.pop_front() {
            tx_buffers.push_back(frame);
        }
    }

    pub(crate) fn recv_packets(&self) -> VecDeque<umem::FrameBuf> {
        let drained: VecDeque<_> = self
            .inner
            .borrow_mut()
            .rx_packet_buffers
            .borrow_mut()
            .drain(..1024)
            .collect();
        drained
    }
}

/// XDP socket type alias for a "shared" XskSocketDriver that's wrapped in the
/// Rc+RefCell which seems to be the only easy way to do this but hopefully we
/// can find a design that doesn't require this in the future (without delving
/// into unsafe pointer stuff).
pub type Socket = Rc<RefCell<XskSocketDriver>>;

/// XskSocketDriver
///
/// XDP driver based on the AF_XDP socket type on linux
#[derive(Debug)]
pub struct XskSocketDriver {
    socket: Box<libbpf_sys::xsk_socket>,
    rx_queue: Box<libbpf_sys::xsk_ring_cons>,
    tx_queue: Box<libbpf_sys::xsk_ring_prod>,
    config: XskConfig,
    umem: Rc<RefCell<Umem>>,
    queue: QueueId,
    fd: RawFd,

    /// Incomplete frames - frames that have been put into the TX
    /// queue but have not yet been completed / reaped from the
    /// completion queue. Also uses max num_descriptors s/t we never
    /// allocate during the operation of the socket.
    incomplete_frames: VecDeque<Box<umem::FrameRef>>,
}

impl XskSocketDriver {
    pub(crate) fn new(config: XskConfig, umem: Rc<RefCell<Umem>>) -> Result<XskSocketDriver> {
        tracing::debug!(
            "Creating new xdp socket using config: {:?}, with umem: {:?}",
            config,
            umem
        );
        let tx: Box<libbpf_sys::xsk_ring_prod> = Default::default();
        let rx: Box<libbpf_sys::xsk_ring_cons> = Default::default();
        let mut xsk: *mut libbpf_sys::xsk_socket = std::ptr::null_mut();
        let xsk_ptr: *mut *mut libbpf_sys::xsk_socket = ptr::addr_of_mut!(xsk);
        let if_name_c = CString::new(config.if_name).unwrap();
        let queue = config.queue;
        let umem_ptr = unsafe { umem.borrow_mut().umem_ptr() };
        tracing::debug!("UMEM ptr: {:?}", umem_ptr);
        let rx_ptr = Box::into_raw(rx);
        let tx_ptr = Box::into_raw(tx);
        let busy_poll = config.busy_poll;
        let cfg = config.into();
        let err = unsafe {
            libbpf_sys::xsk_socket__create(
                xsk_ptr,
                if_name_c.as_ptr(),
                queue,
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

        let socket = unsafe {
            XskSocketDriver {
                socket: Box::from_raw(xsk),
                rx_queue: Box::from_raw(rx_ptr),
                tx_queue: Box::from_raw(tx_ptr),
                fd: fd.into_raw_fd(),
                queue: QueueId(queue),
                config,
                umem,
                incomplete_frames: VecDeque::with_capacity(1024), // TODO: size this correctly
            }
        };

        // TODO: we don't care about this response at the moment but we .. should?
        let _ = match busy_poll {
            BusyPoll::Enable(budget) => socket.set_busy_poll(budget)?,
            BusyPoll::Disable => false,
        };

        Ok(socket)
    }

    pub(crate) fn tx_needs_wakeup(&self) -> bool {
        unsafe { libbpf_sys::_xsk_ring_prod__needs_wakeup(self.tx_queue.as_ref()) != 0 }
    }

    pub(crate) fn kick_tx(&self, frame_count: usize) -> Vec<Source> {
        let mut sources = vec![];
        for _ in 0..kick_iterations(frame_count) {
            let source = self.reactor().kick_tx(self.fd);
            sources.push(source);
        }
        sources
    }

    /// It's unclear if this is worthwhile or not..
    pub(crate) fn fill_needs_wakeup(&self) -> bool {
        unsafe { libbpf_sys::_xsk_ring_prod__needs_wakeup((*self.umem).borrow().fq()) != 0 }
    }

    pub(crate) fn reactor(&self) -> Rc<parking::Reactor> {
        Local::get_reactor()
    }

    pub(crate) fn fd(&self) -> &RawFd {
        &self.fd
    }

    pub(crate) fn tx_count(&self) -> usize {
        unsafe {
            (self.tx_queue.size
                - libbpf_sys::_xsk_prod_nb_free(
                    self.tx_queue.as_ref() as *const _ as *mut _,
                    self.tx_queue.size,
                ) as u32) as usize
        }
    }

    pub(crate) fn tx_count_cached(&self) -> usize {
        (self.tx_queue.size - (self.tx_queue.cached_cons - self.tx_queue.cached_prod)) as usize
    }

    /// Safety: This should be safe, despite having to coerce a shared reference
    /// to a mutable pointer. Technically the "mutation" would be updating the
    /// cached count so I think it should be OK.
    pub(crate) fn rx_count(&self) -> usize {
        unsafe {
            libbpf_sys::_xsk_cons_nb_avail(
                self.rx_queue.as_ref() as *const _ as *mut _,
                self.rx_queue.size,
            ) as usize
        }
    }

    pub(crate) fn rx_count_cached(&self) -> usize {
        (self.rx_queue.cached_prod - self.rx_queue.cached_cons) as usize
    }

    pub(crate) fn consume_rx(&mut self) -> Vec<umem::FrameBuf> {
        log_queue_counts!(self.rx_queue, "RX");
        let mut borrowed_umem = self.umem.borrow_mut();
        let filled_frames = unsafe { borrowed_umem.filled_frames_mut() };
        if filled_frames.is_empty() {
            return vec![];
        }
        let mut idx = 0;
        unsafe {
            let count = libbpf_sys::_xsk_ring_cons__peek(
                self.rx_queue.as_mut(),
                filled_frames.len().try_into().unwrap_or(0),
                &mut idx,
            );
            if count == 0 {
                return vec![];
            }
            let count_usize: usize = count.try_into().unwrap();
            let drained: Vec<_> = filled_frames.drain(..count_usize).collect();
            tracing::debug!("[before] Drained len: {}", drained.len());
            let output: Vec<_> = drained
                .into_iter()
                .filter_map(|rref| borrowed_umem.from_ref(rref))
                .map(|mut rref| {
                    let rx_descriptor =
                        libbpf_sys::_xsk_ring_cons__rx_desc(self.rx_queue.as_ref(), idx);
                    tracing::debug!("RX descriptor: {:#?}", &*rx_descriptor);
                    rref.set_frame_addr((*rx_descriptor).addr);
                    rref.set_frame_len((*rx_descriptor).len);
                    rref.set_frame_options((*rx_descriptor).options);
                    idx += 1;
                    rref
                })
                .collect();
            tracing::debug!("[after] Drained len: {}", output.len());
            libbpf_sys::_xsk_ring_cons__release(self.rx_queue.as_mut(), count);
            output
        }
    }

    /// UNSAFE -- currently uses unsafe casts and needs to be reworked to verify
    /// safety
    pub(crate) unsafe fn consume_rx_pool(
        &mut self,
        packet_buf: &mut VecDeque<umem::FrameBuf>,
    ) -> u64 {
        log_queue_counts!(self.rx_queue, "RX");
        let borrowed_umem = self.umem.borrow_mut();

        // TODO: this is very unsafe and needs to be reworked to not require a bunch of
        // terrible casts
        let filled_frames = unsafe { borrowed_umem.filled_frames_mut() };
        if filled_frames.is_empty() {
            return 0;
        }
        let mut idx = 0;
        let mut count = 0;
        unsafe {
            count = libbpf_sys::_xsk_ring_cons__peek(
                self.rx_queue.as_mut(),
                filled_frames.len().try_into().unwrap_or(0),
                &mut idx,
            );
            if count == 0 {
                return 0;
            }
            let count_usize: usize = count.try_into().unwrap();
            filled_frames
                .drain(..count_usize)
                .filter_map(|frame| borrowed_umem.from_ref(frame))
                .for_each(|mut frame| {
                    let rx_descriptor =
                        libbpf_sys::_xsk_ring_cons__rx_desc(self.rx_queue.as_ref(), idx);
                    tracing::debug!("RX descriptor: {:#?}", &*rx_descriptor);
                    frame.set_frame_addr((*rx_descriptor).addr);
                    frame.set_frame_len((*rx_descriptor).len);
                    frame.set_frame_options((*rx_descriptor).options);
                    idx += 1;
                    packet_buf.push_back(frame);
                });
            tracing::debug!("Drained len: {}", idx);
            libbpf_sys::_xsk_ring_cons__release(self.rx_queue.as_mut(), count);
        }
        count
    }

    pub(crate) fn produce_tx(&mut self, bufs: &mut Vec<umem::FrameBuf>) -> usize {
        log_queue_counts!(self.tx_queue, "TX");
        let nb = bufs.len().try_into().unwrap();
        if nb == 0 {
            return 0;
        }
        let mut idx = 0;
        unsafe {
            let count = libbpf_sys::_xsk_ring_prod__reserve(self.tx_queue.as_mut(), nb, &mut idx);
            if count == 0 {
                return 0;
            }

            // siphon off some to put into tx ring and then hold in incomplete ring
            // TODO: figure out if this is safe / won't leak memory.. seems correct but
            // needs more analysis
            let drained = bufs.drain(..count as usize).map(mem::ManuallyDrop::new);
            for mut desc in drained {
                let x = libbpf_sys::_xsk_ring_prod__tx_desc(self.tx_queue.as_mut(), idx);
                (*x).addr = desc.frame_addr().unwrap();
                (*x).len = desc.frame_len();
                (*x).options = desc.frame_options().unwrap();
                idx += 1;
                let frame_ptr = desc.frame_ptr();
                self.incomplete_frames.push_back(Box::from_raw(frame_ptr));
            }
            libbpf_sys::_xsk_ring_prod__submit(self.tx_queue.as_mut(), count);
            count.try_into().unwrap()
        }
    }

    pub(crate) fn produce_tx_pool(&mut self, bufs: &mut VecDeque<umem::FrameBuf>) -> usize {
        log_queue_counts!(self.tx_queue, "TX");
        let nb = bufs.len().try_into().unwrap();
        if nb == 0 {
            return 0;
        }
        let mut idx = 0;
        unsafe {
            let count = libbpf_sys::_xsk_ring_prod__reserve(self.tx_queue.as_mut(), nb, &mut idx);
            if count == 0 {
                return 0;
            }

            // siphon off some to put into tx ring and then hold in incomplete ring
            // TODO: figure out if this is safe / won't leak memory.. seems correct but
            // needs more analysis
            let drained = bufs.drain(..count as usize).map(mem::ManuallyDrop::new);
            for mut desc in drained {
                let x = libbpf_sys::_xsk_ring_prod__tx_desc(self.tx_queue.as_mut(), idx);
                (*x).addr = desc.frame_addr().unwrap();
                (*x).len = desc.frame_len();
                (*x).options = desc.frame_options().unwrap();
                idx += 1;
                let frame_ptr = desc.frame_ptr();
                self.incomplete_frames.push_back(Box::from_raw(frame_ptr));
            }
            libbpf_sys::_xsk_ring_prod__submit(self.tx_queue.as_mut(), count);
            count.try_into().unwrap()
        }
    }

    pub(crate) fn consume_completions(&mut self) -> Result<usize> {
        let mut umem = self.umem.borrow_mut();
        let cq = umem.cq_mut();
        log_queue_counts!(cq, "COMPLETIONS");
        let incompletions = &mut self.incomplete_frames;
        let inc_len = incompletions.len();
        let nb = inc_len.try_into()?;

        let mut idx = 0;
        let count = unsafe { libbpf_sys::_xsk_ring_cons__peek(umem.cq_mut(), nb, &mut idx) };
        println!(
            "There are {} entries in completion queue. Idx: {}",
            count, idx
        );
        let count_usize = count.try_into()?;
        let drain = incompletions.drain(..count_usize);
        for desc in drain {
            let addr = unsafe { *libbpf_sys::_xsk_ring_cons__comp_addr(umem.cq_mut(), idx) };
            println!("Computing address for {} = {}", desc.addr.get(), addr);
            desc.addr.set(addr);
            desc.len.set(0);
            desc.options.set(0);
            idx += 1;
            tracing::debug!(
                "Moving completion (addr: {:?}) from incompletions[{}] -> free_frames[{}]: {:?}",
                addr,
                inc_len - idx as usize,
                umem.free_frames().len(),
                desc
            );
            umem.free_frames_mut().push_back(desc);
        }
        unsafe { libbpf_sys::_xsk_ring_cons__release(umem.cq_mut(), count) };
        Ok(count_usize)
    }

    pub(crate) fn completions(&self) -> usize {
        (*self.umem).borrow().completions()
    }

    pub(crate) fn set_busy_poll(&self, budget: i32) -> Result<bool> {
        set_sockopt(self.fd, SO_PREFER_BUSY_POLL, 1)?;
        set_sockopt(self.fd, SO_BUSY_POLL, 20)?;
        set_sockopt(self.fd, SO_BUSY_POLL_BUDGET, budget)?;
        Ok(true)
    }

    pub(crate) fn queue(&self) -> &QueueId {
        &self.queue
    }
}

impl Drop for XskSocketDriver {
    fn drop(&mut self) {
        unsafe {
            tracing::debug!("Dropping AF_XDP socket (fd: {}) ...", self.fd);
            libbpf_sys::xsk_socket__delete(self.socket.as_mut());
        }
    }
}

/// Socket config structure
#[derive(Debug, Clone, Copy)]
pub struct XskConfig {
    /// Interface name
    pub if_name: &'static str,
    /// TX ring size
    pub tx_size: u32,
    /// RX ring size
    pub rx_size: u32,
    /// NIC queue number
    pub queue: u32,
    /// XDP related flags
    pub xdp_flags: u32,
    /// Bind related flags
    pub bind_flags: u16,
    /// libbpf specific flags
    pub libbpf_flags: u32,
    /// Whether or not to enable busy-polling or rely on regular IRQ system
    pub busy_poll: BusyPoll,
}

/// BusyPoll
///
/// Settings for enabling busy-polling on the socket.
///
/// TODO: just use an Option?
#[derive(Debug, Clone, Copy)]
pub enum BusyPoll {
    /// Do not enable busy polling
    Disable,
    /// Enable busy-polling w/ budget value
    Enable(i32),
}

impl From<XskConfig> for libbpf_sys::xsk_socket_config {
    fn from(config: XskConfig) -> Self {
        libbpf_sys::xsk_socket_config {
            rx_size: config.rx_size,
            tx_size: config.tx_size,
            libbpf_flags: config.libbpf_flags,
            xdp_flags: config.xdp_flags,
            bind_flags: config.bind_flags,
        }
    }
}

/// NOTE: there is probably a more efficient way to do this, but for not this
/// will have to do. Also don't know that it's gonna actually end up running in
/// a const context but it can be const so it should be.
pub(crate) const fn kick_iterations(amt: usize) -> usize {
    if amt == 16 {
        return 1;
    }
    (amt / 16) + 1
}

fn set_sockopt<T>(fd: i32, key: i32, val: T) -> Result<()> {
    let ptr = addr_of!(val);
    let res = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            key,
            ptr.cast::<libc::c_void>(),
            mem::size_of::<T>() as u32,
        )
    };
    if res < 0 {
        let error = nix::errno::from_i32(res);
        let err = std::io::Error::from_raw_os_error(res);
        tracing::debug!("Got error: {:?}, raw error: {:?}", err, error);
        return Err(err.into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use umem::UdpPacket;

    use super::*;
    use crate::sys::umem::UmemBuilder;
    use std::process::{Child, Stdio};

    #[test]
    fn test_kick_iterations() {
        let under = kick_iterations(10);
        let over = kick_iterations(25);
        let equal = kick_iterations(16);
        assert_eq!(under, 1);
        assert_eq!(over, 2);
        assert_eq!(equal, 1);
    }

    pub(crate) fn run_udp_traffic_command() -> Child {
        std::process::Command::new("ip")
            .stdout(Stdio::null())
            .args(&[
                "netns", "exec", "test", "nping", "--udp", "-c", "100000", "--rate", "1000000",
                "10.1.0.2",
            ])
            .spawn()
            .unwrap()
    }

    #[test]
    fn construct_xsk_driver() {
        tracing_subscriber::fmt()
            .with_env_filter("glommio=debug")
            .with_thread_names(true)
            .init();
        tracing::info!("Logging started...");

        let config = XskConfig {
            if_name: "veth1",
            tx_size: 256,
            rx_size: 256,
            queue: 0,
            xdp_flags: XdpFlags::XDP_FLAGS_DRV_MODE.bits(),
            bind_flags: XskBindFlags::XDP_USE_NEED_WAKEUP.bits(),
            libbpf_flags: 0,
            busy_poll: BusyPoll::Disable,
        };

        let mut child = run_udp_traffic_command();

        let ubuilder = UmemBuilder::new(1024)
            .completion_queue_size(256)
            .fill_queue_size(256);

        crate::LocalExecutorBuilder::new()
            .name("main-thread")
            .mempool(ubuilder)
            .spawn(move || async move {
                let umem = umem::Umem::get();
                let mut sock = XskSocketDriver::new(config, umem.clone()).unwrap();
                tracing::debug!("Socket: {:#?}", sock);
                let mut frames = umem.borrow_mut().alloc(10);
                let filled = umem.borrow_mut().fill_frames(1024);
                tracing::debug!("Filled {} frames into fill queue.. ", filled);

                let mut recvd = 1;
                while recvd != 0 {
                    let mut frames = sock.consume_rx();
                    tracing::info!("[NO-POLL] Recieved: {}", frames.len());
                    recvd = frames.len();
                    Local::yield_if_needed().await;
                    if !frames.is_empty() {
                        let packet = frames.pop().unwrap();
                        let len = packet.ip_header_len();
                        // println!("LEN: {}, VERSION: {:?}", len, packet.ip_version(),);
                        let udppack = UdpPacket::new(frames.pop().unwrap());
                        let src = udppack.src_port();
                        let dst = udppack.dst_port();
                        let len = udppack.len();
                        let csum = udppack.checksum();
                        tracing::debug!(
                            "Source port: {}, Destination port: {}, len: {}, checksum: {}",
                            src,
                            dst,
                            len,
                            csum
                        );
                    }

                    let count = umem.borrow_mut().fill_count();
                    let free = (*umem).borrow().free_frames().len();
                    tracing::info!("Fill count: {}, free count: {}", count, free);
                    if count < 50 {
                        umem.borrow_mut().fill_frames(256);
                    }
                }

                let reactor = sock.reactor();
                let source = reactor
                    .xsk_poll(*sock.fd(), nix::poll::PollFlags::POLLIN)
                    .unwrap();
                let resp = source.collect_rw().await;
                tracing::debug!("async poll result: {:?}", resp);
                let mut frames = sock.consume_rx();
                tracing::debug!("Recieved: {:#?}", frames);
                for f in &mut frames {
                    tracing::debug!(
                        "BUF: {:#?}, frame: {:?}, 'buf': {:#?}, src/dst: {:#?}",
                        &f[..],
                        (f.frame_addr(), f.frame_len()),
                        f.buf(),
                        (f.ip_src(), f.ip_dst()),
                    );
                    let mac_src = f.mac_src_raw().to_vec();
                    // let mac_dst = f.mac_dst_raw().to_vec();
                    // f.mac_src_mut().copy_from_slice(&mac_dst[..]);
                    // f.mac_dst_mut().copy_from_slice(&mac_src[..]);
                    let before_csum = f.ip_checksum().to_vec();
                    tracing::debug!("Before Before checksum: {:?}", before_csum);
                    let old_dest = f.ip_dst();
                    f.calculate_ipv4_csum();
                    let csum = f.ip_checksum();
                    assert_eq!(&before_csum[..], csum);
                    f.set_ip_dst(f.ip_src());
                    f.set_ip_src(old_dest);
                    let csum = f.ip_checksum();
                    tracing::debug!("Before checksum: {:?}", csum);
                    f.calculate_ipv4_csum();
                    let csum = f.ip_checksum();
                    tracing::debug!("After checksum: {:?}", csum);
                }
                let amt = sock.produce_tx(&mut frames);
                tracing::debug!("Amt placed in TX queue: {}", amt);
                if sock.tx_needs_wakeup() {
                    for _ in 0..kick_iterations(amt) {
                        let source = reactor.kick_tx(*sock.fd());
                        let resp = source.collect_rw().await;
                        tracing::debug!("Kick TX resp: {:#?}", resp);
                    }
                }
                let amt = sock.consume_completions();
                tracing::debug!("Amt pulled out of completions ring: {:?}", amt);
            })
            .unwrap()
            .join()
            .unwrap();
        child.kill().unwrap();
    }

    #[test]
    fn process_udp_packets() {
        tracing_subscriber::fmt()
            .with_env_filter("glommio=debug")
            .with_thread_names(true)
            .init();
        tracing::info!("Logging started...");

        let config = XskConfig {
            if_name: "veth1",
            tx_size: 256,
            rx_size: 256,
            queue: 0,
            xdp_flags: XdpFlags::XDP_FLAGS_DRV_MODE.bits(),
            bind_flags: XskBindFlags::XDP_USE_NEED_WAKEUP.bits(),
            libbpf_flags: 0,
            busy_poll: BusyPoll::Disable,
        };

        let mut child = run_udp_traffic_command();
        let ubuilder = UmemBuilder::new(1024)
            .completion_queue_size(256)
            .fill_queue_size(256);

        crate::LocalExecutorBuilder::new()
            .name("main-thread")
            .xdp_config(config)
            .mempool(ubuilder)
            .make()
            .unwrap()
            .run(async move {
                let umem = umem::Umem::get();
                let mut sock = XskSocketDriver::new(config, umem.clone()).unwrap();
                tracing::debug!("Socket: {:#?}", sock);
                let mut frames = umem.borrow_mut().alloc(10);
                let filled = umem.borrow_mut().fill_frames(1024);
                tracing::debug!("Filled {} frames into fill queue.. ", filled);

                let mut recvd = 1;
                while recvd != 0 {
                    let mut frames = sock.consume_rx();
                    tracing::info!("[NO-POLL] Recieved: {}", frames.len());
                    recvd = frames.len();
                    Local::yield_if_needed().await;
                    if !frames.is_empty() {
                        let mut udppack = UdpPacket::new(frames.pop().unwrap());
                        let src = udppack.src_port();
                        let dst = udppack.dst_port();
                        let len = udppack.len();
                        let csum = udppack.checksum();
                        tracing::debug!(
                            "Source port: {}, Destination port: {}, len: {}, checksum: {}",
                            src,
                            dst,
                            len,
                            csum
                        );
                        udppack.set_src_port(dst);
                        udppack.set_dst_port(src);
                    }

                    let count = umem.borrow_mut().fill_count();
                    let free = (*umem).borrow().free_frames().len();
                    tracing::info!("Fill count: {}, free count: {}", count, free);
                    if count < 50 {
                        umem.borrow_mut().fill_frames(256);
                    }
                }

                let reactor = sock.reactor();
                let source = reactor
                    .xsk_poll(*sock.fd(), nix::poll::PollFlags::POLLIN)
                    .unwrap();
                let resp = source.collect_rw().await;
                tracing::debug!("async poll result: {:?}", resp);
                let mut frames = sock.consume_rx();
                tracing::debug!("Recieved: {:#?}", frames);
                for f in &mut frames {
                    tracing::debug!(
                        "BUF: {:#?}, frame: {:?}, 'buf': {:#?}, src/dst: {:#?}",
                        &f[..],
                        (f.frame_addr(), f.frame_len()),
                        f.buf(),
                        (f.ip_src(), f.ip_dst()),
                    );
                    let mac_src = f.mac_src_raw().to_vec();
                    // let mac_dst = f.mac_dst_raw().to_vec();
                    tracing::debug!(
                        "MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                        mac_src[0],
                        mac_src[1],
                        mac_src[2],
                        mac_src[3],
                        mac_src[4],
                        mac_src[5]
                    );
                    // f.mac_src_mut().copy_from_slice(&mac_dst[..]);
                    // f.mac_dst_mut().copy_from_slice(&mac_src[..]);
                    let before_csum = f.ip_checksum().to_vec();
                    tracing::debug!("Before Before checksum: {:?}", before_csum);
                    let old_dest = f.ip_dst();
                    f.calculate_ipv4_csum();
                    let csum = f.ip_checksum();
                    assert_eq!(&before_csum[..], csum);
                    f.set_ip_dst(f.ip_src());
                    f.set_ip_src(old_dest);
                    let csum = f.ip_checksum();
                    tracing::debug!("Before checksum: {:?}", csum);
                    f.calculate_ipv4_csum();
                    let csum = f.ip_checksum();
                    tracing::debug!("After checksum: {:?}", csum);
                }
                let amt = sock.produce_tx(&mut frames);
                tracing::debug!("Amt placed in TX queue: {}", amt);
                if sock.tx_needs_wakeup() {
                    for _ in 0..kick_iterations(amt) {
                        let source = reactor.kick_tx(*sock.fd());
                        let resp = source.collect_rw().await;
                        tracing::debug!("Kick TX resp: {:#?}", resp);
                    }
                }
                let amt = sock.consume_completions();
                tracing::debug!("Amt pulled out of completions ring: {:?}", amt);
            });
        child.kill().unwrap();
    }
}
