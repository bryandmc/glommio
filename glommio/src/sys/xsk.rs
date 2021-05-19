use core::slice;
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    convert::TryInto,
    ffi::CString,
    io, mem,
    net::{SocketAddr, ToSocketAddrs},
    os::unix::prelude::{IntoRawFd, RawFd},
    ptr,
    rc::{Rc, Weak},
    sync::atomic::AtomicPtr,
    time::Duration,
};

use crate::{executor::TaskQueue, parking, IoRequirements, Latency, Local, TaskQueueHandle};
use bitflags::bitflags;

use super::{
    add_source, to_user_data,
    umem::{self, Umem},
    Source, SourceType,
};

use crate::GlommioError;

type Result<T> = std::result::Result<T, GlommioError<()>>;

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

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct QueueId(pub u32);

#[derive(Debug)]
pub(crate) struct XskSocketDriver<'umem> {
    socket: Box<libbpf_sys::xsk_socket>,
    rx_queue: Box<libbpf_sys::xsk_ring_cons>,
    tx_queue: Box<libbpf_sys::xsk_ring_prod>,
    config: XskConfig,
    umem: Rc<RefCell<Umem<'umem>>>,
    reactor: Weak<parking::Reactor>,
    queue: QueueId,
    fd: RawFd,

    /// Incomplete frames - frames that have been put into the TX
    /// queue but have not yet been completed / reaped from the
    /// completion queue. Also uses max num_descriptors s/t we never
    /// allocate during the operation of the socket.
    incomplete_frames: VecDeque<Box<umem::FrameRef>>,
}

impl<'umem> XskSocketDriver<'umem> {
    pub(crate) fn new(
        config: XskConfig,
        umem: Rc<RefCell<Umem<'umem>>>,
    ) -> Result<XskSocketDriver<'umem>> {
        let tx: Box<libbpf_sys::xsk_ring_prod> = Default::default();
        let rx: Box<libbpf_sys::xsk_ring_cons> = Default::default();
        let mut xsk: *mut libbpf_sys::xsk_socket = std::ptr::null_mut();
        let xsk_ptr: *mut *mut libbpf_sys::xsk_socket = ptr::addr_of_mut!(xsk);
        let if_name_c = CString::new(config.if_name).unwrap();
        let queue = config.queue;
        let umem_ptr = unsafe { umem.borrow_mut().umem_ptr() };
        let rx_ptr = Box::into_raw(rx);
        let tx_ptr = Box::into_raw(tx);

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

        unsafe {
            Ok(XskSocketDriver {
                socket: Box::from_raw(xsk),
                rx_queue: Box::from_raw(rx_ptr),
                tx_queue: Box::from_raw(tx_ptr),
                fd: fd.into_raw_fd(),
                queue: QueueId(queue),
                config,
                umem,
                reactor: Rc::downgrade(&Local::get_reactor()),
                incomplete_frames: VecDeque::with_capacity(1024), // TODO: size this correctly
            })
        }
    }

    #[inline(always)]
    pub(crate) fn tx_needs_wakeup(&self) -> bool {
        unsafe { libbpf_sys::_xsk_ring_prod__needs_wakeup(self.tx_queue.as_ref()) != 0 }
    }

    /// It's unclear if this is worthwhile or not..
    #[inline(always)]
    pub(crate) fn fill_needs_wakeup(&self) -> bool {
        unsafe { libbpf_sys::_xsk_ring_prod__needs_wakeup(self.umem.borrow().fq()) != 0 }
    }

    #[inline(always)]
    pub(crate) fn reactor(&self) -> &Weak<parking::Reactor> {
        &self.reactor
    }

    #[inline(always)]
    pub(crate) fn fd(&self) -> &RawFd {
        &self.fd
    }

    #[inline(always)]
    pub(crate) fn tx_count(&self) -> usize {
        unsafe {
            (self.tx_queue.size
                - libbpf_sys::_xsk_prod_nb_free(
                    self.tx_queue.as_ref() as *const _ as *mut _,
                    self.tx_queue.size,
                ) as u32) as usize
        }
    }

    #[inline(always)]
    pub(crate) fn tx_count_cached(&self) -> usize {
        (self.tx_queue.size - (self.tx_queue.cached_cons - self.tx_queue.cached_prod)) as usize
    }

    /// Safety: This should be safe, despite having to coerce a shared reference
    /// to a mutable pointer. Technically the "mutation" would be updating the
    /// cached count so I think it should be OK.
    #[inline(always)]
    pub(crate) fn rx_count(&self) -> usize {
        unsafe {
            libbpf_sys::_xsk_cons_nb_avail(
                self.rx_queue.as_ref() as *const _ as *mut _,
                self.rx_queue.size,
            ) as usize
        }
    }

    #[inline(always)]
    pub(crate) fn rx_count_cached(&self) -> usize {
        (self.rx_queue.cached_prod - self.rx_queue.cached_cons) as usize
    }

    pub(crate) fn consume_rx(&mut self) -> Vec<umem::FrameBuf<'umem>> {
        log_queue_counts!(self.rx_queue, "RX");
        let mut borrowed_umem = self.umem.borrow_mut();
        let filled_frames = borrowed_umem.filled_frames_mut();
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

    pub(crate) fn produce_tx(&mut self, bufs: &mut Vec<umem::FrameBuf<'umem>>) -> usize {
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
        self.umem.borrow().completions()
    }

    pub(crate) fn umem(&self) -> &Rc<RefCell<Umem<'umem>>> {
        &self.umem
    }

    pub(crate) fn bind_udp_socket<A: Into<SocketAddr>>(&self, addr: A, queue: TaskQueueHandle) {
        let addr: SocketAddr = addr.into();
        let reactor = self.reactor.upgrade().unwrap();
        let source = Source::new(
            IoRequirements::new(Latency::Matters(Duration::from_millis(10)), 0),
            self.fd,
            SourceType::XskPoll,
            None,
            Some(queue),
        );
        // let idx = to_user_data(add_source(&source, reactor_queue));
    }
}

impl<'umem> Drop for XskSocketDriver<'umem> {
    fn drop(&mut self) {
        unsafe {
            tracing::debug!("Dropping AF_XDP socket (fd: {}) ...", self.fd);
            libbpf_sys::xsk_socket__delete(self.socket.as_mut());
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct XskConfig {
    if_name: &'static str,
    tx_size: u32,
    rx_size: u32,
    queue: u32,
    xdp_flags: u32,
    bind_flags: u16,
    libbpf_flags: u32,
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

#[cfg(test)]
mod tests {
    use umem::UdpPacket;

    use super::*;
    use crate::sys::umem::{UmemBuilder, UmemConfig};
    use std::process::{Child, Stdio};

    // #[test]
    // fn test_arena() {
    //     let mut underlying = [0u8; 1024];
    //     let alloc = unsafe {
    //         Arena {
    //             inner: Rc::new(InnerArena {
    //                 base: ptr::NonNull::new_unchecked(underlying.as_mut_ptr()),
    //                 current:
    // Cell::new(ptr::NonNull::new_unchecked(underlying.as_mut_ptr())),
    //                 out_count: Cell::new(0),
    //             }),
    //         }
    //     };
    //     dbg!(&alloc);
    //     let v = Vec::<u8, _>::new_in(alloc.clone());
    //     dbg!(v);
    //     let b = Box::new_in([1, 2, 3, 4, 5], alloc);
    //     dbg!(b);
    // }

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
        };

        let mut child = run_udp_traffic_command();

        crate::LocalExecutorBuilder::new()
            .name("main-thread")
            .spawn(move || async move {
                let umem = Rc::new(RefCell::new(
                    Umem::new(
                        UmemBuilder::new(1024)
                            .completion_queue_size(256)
                            .fill_queue_size(256),
                    )
                    .unwrap(),
                ));
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
                        println!("LEN: {}, VERSION: {:?}", len, packet.ip_version(),);
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
                    let free = umem.borrow().free_frames().len();
                    tracing::info!("Fill count: {}, free count: {}", count, free);
                    if count < 50 {
                        umem.borrow_mut().fill_frames(256);
                    }
                }

                let reactor = sock.reactor().upgrade().unwrap();
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
                    let mac_dst = f.mac_dst_raw().to_vec();
                    f.mac_src_mut().copy_from_slice(&mac_dst[..]);
                    f.mac_dst_mut().copy_from_slice(&mac_src[..]);
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
        };

        let mut child = run_udp_traffic_command();

        crate::LocalExecutorBuilder::new()
            .name("main-thread")
            .spawn(move || async move {
                let umem = Rc::new(RefCell::new(
                    Umem::new(
                        UmemBuilder::new(1024)
                            .completion_queue_size(256)
                            .fill_queue_size(256),
                    )
                    .unwrap(),
                ));
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
                    let free = umem.borrow().free_frames().len();
                    tracing::info!("Fill count: {}, free count: {}", count, free);
                    if count < 50 {
                        umem.borrow_mut().fill_frames(256);
                    }
                }

                let reactor = sock.reactor().upgrade().unwrap();
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
                    let mac_dst = f.mac_dst_raw().to_vec();
                    tracing::debug!(
                        "MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                        mac_src[0],
                        mac_src[1],
                        mac_src[2],
                        mac_src[3],
                        mac_src[4],
                        mac_src[5]
                    );
                    f.mac_src_mut().copy_from_slice(&mac_dst[..]);
                    f.mac_dst_mut().copy_from_slice(&mac_src[..]);
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
}
