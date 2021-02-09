//!
//! # AF_XDP socket implementation
//!
//! [AF_XDP kernel documentation](https://www.kernel.org/doc/html/v4.18/networkingTO/af_xdp.html)

use iou::PollFlags;

use crate::{
    error::ReactorErrorKind,
    sys::ebpf::{
        FrameBuf, FrameRef, Umem, XdpFlags, XskBindFlags, XskSocketConfig, XskSocketDriver,
    },
    GlommioError, Local,
};
use std::{cell::RefCell, rc::Rc};
use std::{convert::TryInto, mem::ManuallyDrop};

type Result<T> = std::result::Result<T, GlommioError<()>>;

/// Log the queue counts. The queue's all have the same structure, but because they are
/// different types, we need a macro to get that kind of 'duck-typing'.
#[macro_export]
macro_rules! log_queue_counts {
    ($q:expr, $t:literal) => {{
        let (prod, cons) = unsafe { (*$q.producer, *$q.consumer) };
        println!(
            "Queue '{}': Producer: {} ({}), Consumer: {} ({}).",
            $t, prod, $q.cached_prod, cons, $q.cached_cons
        );
    }};
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
    driver: XskSocketDriver,
    umem: Rc<RefCell<Umem>>,
    fill_factor: u32,
    refill_factor: u32,
}

impl XdpSocket {
    const DEFAULT_RX_BATCH: u64 = 5_000;

    fn new(config: XdpConfig) -> Result<XdpSocket> {
        dbg!(&config);
        let umem = Local::get_reactor().xdp_umem.clone();
        println!("created umem.. {:?}", umem);
        let driver = XskSocketDriver::new(config.into(), Local::get_reactor().xdp_umem.clone())?;
        println!("created driver.. {:?}", driver);
        Ok(XdpSocket {
            driver,
            umem,
            fill_factor: 2,
            refill_factor: 2,
        })
    }

    /// # create + bind AF_XDP socket
    ///
    /// Delivers L2 frames directly to userspace, depending on settings, directly from the NIC
    /// driver hook. Other times (non-zero-copy mode) by copying it to userspace. This is less
    /// efficient but more widely compatible and works even using the `generic` XDP. This happens
    /// after the allocation of the `skbuff` but uses a common interface, and functions as a good
    /// fallback, that is still generally faster than other methods that are available.
    ///
    pub fn bind(if_name: &'static str, queue: u32) -> Result<XdpSocket> {
        XdpSocket::new(XdpConfig::builder(if_name, queue).build())
    }

    /// # create + bind AF_XDP socket
    ///
    /// Bind using special configuration values beyond the interface name and queue id.
    pub fn bind_with_config(config: XdpConfig) -> Result<XdpSocket> {
        XdpSocket::new(config)
    }

    /// # Add descriptors to the `fill` ring
    ///
    /// This can be used to proactively fill a large number of descriptors in big chunks, when it's
    /// convenient for the user, instead of when the library has to. This is completely OPTIONAL.
    pub fn fill_ring(&mut self, amt: usize) -> usize {
        self.umem.borrow_mut().fill_descriptors(amt)
    }

    /// Receive frames from the socket.
    pub async fn recv(&mut self) -> Result<Vec<FrameBuf>> {
        let read_frames: Vec<_> = self
            .driver
            .consume_rx_owned(Self::DEFAULT_RX_BATCH)
            .into_iter()
            .map(|frame| frame.get_buffer(self.umem.clone()))
            .collect();

        if read_frames.is_empty() {
            let reactor = self.driver.reactor().upgrade().unwrap();
            let source = reactor.poll(
                *self.driver.fd(),
                PollFlags::POLLIN | PollFlags::POLLPRI | PollFlags::POLLHUP,
            );
            let code = source.collect_rw().await?;
            println!("Response code: {}", code);
            let read_frames: Vec<_> = self
                .driver
                .consume_rx_owned(Self::DEFAULT_RX_BATCH)
                .into_iter()
                .map(|frame| frame.get_buffer(self.umem.clone()))
                .collect();
            return Ok(read_frames);
        }
        Ok(read_frames)
    }

    /// Send frames
    pub async fn send(&mut self, frames: &mut Vec<FrameBuf>) -> Result<usize> {
        let mut total = 0;
        let mut retries = 0;
        let mut outer_sources = None;
        let amt = loop {
            retries += 1;
            // println!("Loop start..");
            let (temp_amt, sources) = self.driver.produce_tx_queued(frames);
            outer_sources = sources;
            // dbg!((retries, total, temp_amt, frames.len()));
            if retries == 20 {
                if total > 0 && self.driver.tx_needs_wakeup() {
                    if let Some(sources) = outer_sources {
                        if let Some(Some(last)) = sources.last() {
                            let _ = last.collect_rw().await?;
                        }
                    }
                }
                return Ok(total);
            }
            if temp_amt > 0 || frames.is_empty() {
                total += temp_amt;
                println!(
                    "Send Status: [ Sent: {} (total: {}), frames remaining: {}. ]",
                    temp_amt,
                    total,
                    frames.len(),
                );
                // If the remaining are used, we are done here
                if frames.is_empty() {
                    break total;
                }
            }
        };
        if amt > 0 && self.driver.tx_needs_wakeup() {
            if let Some(sources) = outer_sources {
                if let Some(Some(last)) = sources.last() {
                    let _ = last.collect_rw().await?;
                }
            }
        }

        Ok(amt)
    }

    /// Get a free buffer, so information can be copied into it.
    pub fn get_buffer(&mut self) -> Option<FrameBuf> {
        let mut umem = self.umem.borrow_mut();
        let full_size = umem.frame_size();
        umem.free_list.pop_front().map(|mut x| {
            // NOTE: setting this to full size gives us access to the full frame area
            x.len.set(full_size);
            x.get_buffer(self.umem.clone())
        })
    }

    /// Get free buffers to use for creating frames to send (most likely).
    pub fn get_buffers(&mut self, amt: usize) -> Vec<FrameBuf> {
        let mut umem = self.umem.borrow_mut();
        let full_size = umem.frame_size();
        umem.free_list
            .drain(..amt)
            .map(|mut x| {
                // NOTE: setting this to full size gives us access to the full frame area
                x.len.set(full_size);
                x.get_buffer(self.umem.clone())
            })
            .collect()
    }
}

/// XdpSocketConfig struct for configuring the AF_XDP socket
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct XdpConfig {
    /// *********** AF_XDP socket ***********
    /// Interface name
    if_name: &'static str,
    /// TX ring size
    tx_size: u32,
    /// RX ring size
    rx_size: u32,
    /// Queue number. This is usually 0, unless the device has multiple queues.
    queue: u32,
    /// Xdp related flags
    xdp_flags: u32,
    /// Bind flags
    bind_flags: u16,
    /// Libbpf specific flags
    libbpf_flags: u32,

    /// *********** UMEM ***********
    /// Fill ring size for the UMEM. Defaults to 2048.
    fill_size: u32,
    /// The Completion ring size for the UMEM. Defaults to 2048.
    comp_size: u32,
    /// The default frame size, usually equal to a page (usually 4096 bytes)
    frame_size: u32,
    /// Headroom to the frame. Defaults to 0. Keep in mind it actually seems to
    /// give 256 bytes of headroom, even when set to 0 and adds whatever you set
    /// here to that 256.. That headroom is actually useful for adding encapsulation
    /// headers to the frame without having to re-allocate / re-write the frame.
    frame_headroom: u32,
    /// Flags for the UMEM. Defaults to 0.
    umem_flags: u32,
    /// Number of descriptors
    pub(crate) umem_descriptors: u32,
}

/// Xsk socket configuration builder, helper struct.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct XdpConfigBuilder {
    if_name: Option<&'static str>,
    tx_size: u32,
    rx_size: u32,
    queue: u32,
    xdp_flags: u32,
    bind_flags: u16,
    libbpf_flags: u32,
    fill_size: u32,
    comp_size: u32,
    frame_size: u32,
    frame_headroom: u32,
    umem_flags: u32,
    umem_descriptors: u32,
}

impl XdpConfigBuilder {
    /// set which interface the socket is for
    ///
    pub const fn if_name(self, name: &'static str) -> XdpConfigBuilder {
        Self {
            if_name: Some(name),
            ..self
        }
    }
    /// Size of the tx ring.
    pub const fn tx_size(self, tx_size: u32) -> XdpConfigBuilder {
        // dbg!(!(tx_size & (4096 - 1)));
        if tx_size & (4096 - 1) == 0 {
            return XdpConfigBuilder { tx_size, ..self };
        }
        XdpConfigBuilder { ..self }
    }

    /// Size of the rx ring.
    pub const fn rx_size(self, rx_size: u32) -> XdpConfigBuilder {
        // dbg!(!(rx_size & (4096 - 1)));
        if rx_size & (4096 - 1) == 0 {
            // panic!("Must be divisible by the page size");
            return XdpConfigBuilder { rx_size, ..self };
        }
        XdpConfigBuilder { ..self }
    }

    /// Which queue to attach to.
    pub const fn queue(self, queue: u32) -> XdpConfigBuilder {
        XdpConfigBuilder { queue, ..self }
    }

    /// What `XDP` flags to use when setting up the socket
    pub const fn xdp_flags(self, xdp_flags: XdpFlags) -> XdpConfigBuilder {
        XdpConfigBuilder {
            xdp_flags: xdp_flags.bits(),
            ..self
        }
    }

    /// What `bind` flags to use when setting up the socket
    pub const fn bind_flags(self, bind_flags: XskBindFlags) -> XdpConfigBuilder {
        XdpConfigBuilder {
            bind_flags: bind_flags.bits(),
            ..self
        }
    }

    /// What `libbpf` flags to use when setting up the socket
    pub const fn libbpf_flags(self, libbpf_flags: u32) -> XdpConfigBuilder {
        XdpConfigBuilder {
            libbpf_flags,
            ..self
        }
    }

    /// Fill size
    pub const fn fill_size(self, fill_size: u32) -> XdpConfigBuilder {
        // dbg!(!(fill_size & (4096 - 1)));
        // assert!();
        // assert!(fill_size & (4096 - 1));
        if fill_size & (4096 - 1) == 0 {
            return XdpConfigBuilder { fill_size, ..self };
        }
        XdpConfigBuilder { ..self }
    }

    /// Completion size
    pub const fn completion_size(self, comp_size: u32) -> XdpConfigBuilder {
        // dbg!(comp_size & (4096 - 1));
        // assert!();
        if comp_size & (4096 - 1) == 0 {
            return XdpConfigBuilder { comp_size, ..self };
        }
        // assert!(comp_size & (4096 - 1));

        XdpConfigBuilder { ..self }
    }

    /// Frame size
    pub const fn frame_size(self, frame_size: u32) -> XdpConfigBuilder {
        XdpConfigBuilder { frame_size, ..self }
    }

    /// Frame headroom
    pub const fn frame_headroom(self, frame_headroom: u32) -> XdpConfigBuilder {
        XdpConfigBuilder {
            frame_headroom,
            ..self
        }
    }

    /// UMEM flags
    pub const fn umem_flags(self, umem_flags: u32) -> XdpConfigBuilder {
        XdpConfigBuilder { umem_flags, ..self }
    }

    /// Number of UMEM descriptors
    pub const fn umem_descriptors(self, umem_descriptors: u32) -> XdpConfigBuilder {
        XdpConfigBuilder {
            umem_descriptors,
            ..self
        }
    }

    /// Build the actual socket config
    pub fn build(self) -> XdpConfig {
        XdpConfig {
            if_name: self.if_name.expect("Interface name not provided!"),
            tx_size: self.tx_size,
            rx_size: self.rx_size,
            queue: self.queue,
            xdp_flags: self.xdp_flags,
            bind_flags: self.bind_flags,
            libbpf_flags: self.libbpf_flags,
            fill_size: self.fill_size,
            comp_size: self.comp_size,
            frame_size: self.frame_size,
            frame_headroom: self.frame_headroom,
            umem_flags: self.umem_flags,
            umem_descriptors: self.umem_descriptors,
        }
    }
}

impl XdpConfig {
    /// Create XDP socket configuration builder
    pub const fn builder(if_name: &'static str, queue: u32) -> XdpConfigBuilder {
        XdpConfigBuilder {
            fill_size: libbpf_sys::XSK_RING_PROD__DEFAULT_NUM_DESCS,
            comp_size: libbpf_sys::XSK_RING_CONS__DEFAULT_NUM_DESCS,
            frame_size: libbpf_sys::XSK_UMEM__DEFAULT_FRAME_SIZE,
            frame_headroom: libbpf_sys::XSK_UMEM__DEFAULT_FRAME_HEADROOM,
            umem_flags: libbpf_sys::XSK_UMEM__DEFAULT_FLAGS,
            if_name: Some(if_name),
            tx_size: libbpf_sys::XSK_RING_PROD__DEFAULT_NUM_DESCS,
            rx_size: libbpf_sys::XSK_RING_CONS__DEFAULT_NUM_DESCS,
            queue,
            xdp_flags: XdpFlags::empty().bits(),
            bind_flags: XskBindFlags::empty().bits(),
            libbpf_flags: 0,
            umem_descriptors: 1024, // this is only 4mb w/ 4kb pages
        }
    }
}

impl From<XdpConfig> for libbpf_sys::xsk_umem_config {
    fn from(config: XdpConfig) -> Self {
        libbpf_sys::xsk_umem_config {
            fill_size: config.fill_size,
            comp_size: config.comp_size,
            frame_size: config.frame_size,
            frame_headroom: config.frame_headroom,
            flags: config.umem_flags,
        }
    }
}

impl From<XdpConfig> for libbpf_sys::xsk_socket_config {
    fn from(config: XdpConfig) -> Self {
        libbpf_sys::xsk_socket_config {
            rx_size: config.rx_size,
            tx_size: config.tx_size,
            xdp_flags: config.xdp_flags,
            bind_flags: config.bind_flags,
            libbpf_flags: config.libbpf_flags,
        }
    }
}

impl From<XdpConfig> for (libbpf_sys::xsk_socket_config, libbpf_sys::xsk_umem_config) {
    fn from(config: XdpConfig) -> Self {
        (
            libbpf_sys::xsk_socket_config {
                rx_size: config.rx_size,
                tx_size: config.tx_size,
                xdp_flags: config.xdp_flags,
                bind_flags: config.bind_flags,
                libbpf_flags: config.libbpf_flags,
            },
            libbpf_sys::xsk_umem_config {
                fill_size: config.fill_size,
                comp_size: config.comp_size,
                frame_size: config.frame_size,
                frame_headroom: config.frame_headroom,
                flags: config.umem_flags,
            },
        )
    }
}

impl From<XdpConfig> for XskSocketConfig {
    fn from(original: XdpConfig) -> Self {
        XskSocketConfig {
            if_name: original.if_name,
            tx_size: original.tx_size,
            rx_size: original.rx_size,
            queue: original.queue,
            xdp_flags: original.xdp_flags,
            bind_flags: original.bind_flags,
            libbpf_flags: original.libbpf_flags,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::super::sys::ebpf::tests::{run_ping_command, run_udp_traffic_command, XDP_LOCK};
    use crate::{sys::ebpf::EtherType, LocalExecutorBuilder};

    use super::*;

    const XDP_CONFIG: XdpConfigBuilder = XdpConfig::builder("veth1", 0)
        .umem_descriptors(4096)
        .fill_size(1024)
        .completion_size(1024)
        .rx_size(1024)
        .tx_size(1024);

    #[test]
    #[cfg_attr(not(feature = "xdp"), ignore)]
    fn af_xdp_umem_get_buffers() {
        let _guard = XDP_LOCK.lock().unwrap();
        let builder = LocalExecutorBuilder::default();
        let local = builder.xdp_config(XDP_CONFIG.build()).make().unwrap();
        local.run(async move {
            let mut sock = XdpSocket::bind("veth1", 0).unwrap();
            dbg!(&sock);
            let buffs = sock.get_buffers(10);
            dbg!(&buffs);
        });
    }

    #[test]
    #[cfg_attr(not(feature = "xdp"), ignore)]
    fn af_xdp_umem_get_buffer() {
        let _guard = XDP_LOCK.lock().unwrap();
        let builder = LocalExecutorBuilder::default();
        let local = builder.xdp_config(XDP_CONFIG.build()).make().unwrap();
        local.run(async move {
            let mut sock = XdpSocket::bind_with_config(XDP_CONFIG.build()).unwrap();
            dbg!(&sock);
            let buff = sock.get_buffer();
            dbg!(&buff);
            let mut b = buff.unwrap();
            (&mut b[..10]).copy_from_slice(b"cdefghijkl");
            println!("BUFF: {:?}", &b[..]);
        });
    }

    #[test]
    #[cfg_attr(not(feature = "xdp"), ignore)]
    fn af_xdp_socket_send() {
        let _guard = XDP_LOCK.lock().unwrap_or_else(|x| x.into_inner());
        let config = XdpConfig::builder("veth1", 0)
            .umem_descriptors(20 * 4096)
            .fill_size(4 * 4096)
            .completion_size(4 * 4096)
            .rx_size(4 * 4096)
            .tx_size(4 * 4096)
            .build();

        let local = LocalExecutorBuilder::new()
            .pin_to_cpu(0)
            .spin_before_park(Duration::from_secs(1))
            .name("xdp-main")
            .xdp_config(config)
            .make()
            .unwrap();
        let mut cmd = run_udp_traffic_command();
        let mut cmd2 = run_udp_traffic_command();
        let mut cmd3 = run_udp_traffic_command();
        local.run(async move {
            let mut sock = XdpSocket::bind_with_config(config).unwrap();
            dbg!(&sock);
            for _ in 0..300 {
                // crate::timer::sleep(Duration::from_millis(10)).await;
                let mut frames = sock.recv().await.unwrap();
                // let buff = sock.get_buffer().unwrap();
                // println!("BUFFER: {:?}", &buff[..]);
                // frames.push(buff);
                if let Some(first) = frames.get_mut(0) {
                    let src_mac = first.mac_src().to_vec();
                    let dst_mac = first.mac_dst().to_vec();
                    if let EtherType::Ipv4 = first.ether_type() {
                        let out = first.ip_header_len();
                        let ipv = ( first[14] & 0b11110000 ) >> 4;
                        println!("Got frame of ether type: {:?} ({}), header size {} \
                                  ( {:08b} ) = {}", first.ether_type(), ipv, first[14], first[14], out);
                        println!("Got frame with data -- src: {:?}, dst: {:?}", first.ip_src(), first.ip_dst());
                        if let [a, b, c, d, e, f] = dst_mac[..] {
                            if let [g, h, i, j, k, l] = src_mac[..] {
                                println!(
                                    "Swapped dst mac: [ {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} ] with source mac \
                                     [ {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} ]",
                                    a, b, c, d, e, f, g, h, i, j, k, l
                                );
                            }
                        }
                    }

                    first.mac_dst_mut().copy_from_slice(&src_mac);
                    first.mac_src_mut().copy_from_slice(&dst_mac);
                    let dst_ip = first.ip_dst_raw().to_vec();
                    let src_ip = first.ip_src_raw().to_vec();
                    first.ip_dst_mut().copy_from_slice(&src_ip);
                    first.ip_src_mut().copy_from_slice(&dst_ip);
                }
                let resp = sock.send(&mut frames).await.unwrap();
                println!("Sent {} items. Pending completions queue: {}, free descriptor queue: {}",
                         resp, sock.umem.borrow().pending_completions.len(), sock.umem.borrow().free_list.len());
            }
            dbg!(&sock.umem.borrow().pending_completions.len());
        });
        cmd.kill().unwrap();
        cmd2.kill().unwrap();
        cmd3.kill().unwrap();
    }

    #[test]
    #[cfg_attr(not(feature = "xdp"), ignore)]
    fn af_xdp_socket_recv() {
        let _guard = XDP_LOCK.lock().unwrap_or_else(|x| x.into_inner());
        let builder = LocalExecutorBuilder::default();
        let conf = XdpConfig::builder("veth1", 0).umem_descriptors(10).build();
        let local = builder.xdp_config(conf).make().unwrap();
        let mut cmd = run_ping_command();
        std::thread::sleep(Duration::from_secs(2));
        local.run(async move {
            let mut sock = XdpSocket::bind("veth1", 0).unwrap();
            dbg!(&sock);
            for x in 0..20 {
                let resp = sock.recv().await.unwrap();
                dbg!(&resp, x);
            }
        });
        cmd.kill().unwrap();
    }

    #[test]
    #[cfg_attr(not(feature = "xdp"), ignore)]
    fn af_xdp_create_socket() {
        let _guard = XDP_LOCK.lock().unwrap_or_else(|x| x.into_inner());
        let builder = LocalExecutorBuilder::default();
        let conf = XdpConfig::builder("veth1", 0).umem_descriptors(10).build();
        let local = builder.xdp_config(conf).make().unwrap();

        local.run(async move {
            // let sock = XdpSocket::bind("veth1", 0);
            let sock = XdpSocket::bind_with_config(
                XdpConfig::builder("veth1", 0).umem_descriptors(10).build(),
            );
            dbg!(&sock);
        });
    }

    #[test]
    fn config_builder() {
        let config = XdpConfig::builder("veth1", 0)
            .tx_size(2048)
            .rx_size(2048)
            .umem_descriptors(10240)
            .build();
        let umem_config: libbpf_sys::xsk_umem_config = config.into();
        let socket_config: libbpf_sys::xsk_socket_config = config.into();
        dbg!(&config, &umem_config, &socket_config);

        let (sock, umem) = config.into();
        dbg!(sock, umem, config);
    }
}
