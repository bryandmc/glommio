//!
//! XDP socket support

use crate::{
    sys::ebpf::{FrameBuf, Umem, XdpFlags, XskBindFlags, XskSocketConfig, XskSocketDriver},
    GlommioError, Local,
};
use nix::poll::PollFlags;
use std::{cell::RefCell, rc::Rc};

type Result<T> = std::result::Result<T, GlommioError<()>>;

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

/// XDP socket
///
/// A raw L2 socket backed by an AF_XDP socket.
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
        let driver = XskSocketDriver::new(config.into(), Local::get_reactor().xdp_umem.clone())?;
        Ok(XdpSocket {
            driver,
            umem,
            fill_factor: 2,
            refill_factor: 2,
        })
    }

    /// Bind the AF_XDP socket
    pub fn bind(if_name: &'static str, queue: u32) -> Result<XdpSocket> {
        XdpSocket::new(XdpConfig::builder(if_name, queue).build())
    }

    pub fn bind_with_config(config: XdpConfig) -> Result<XdpSocket> {
        XdpSocket::new(config)
    }

    pub fn fill_ring(&mut self, amt: usize) -> usize {
        self.umem.borrow_mut().fill_descriptors(amt)
    }

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

    pub fn get_buffer(&mut self) -> Option<FrameBuf> {
        let umem = self.umem.borrow_mut();
        let full_size = umem.frame_size();
        let mut free_list = umem.free_list.borrow_mut();
        free_list.pop_front().map(|x| {
            // NOTE: setting this to full size gives us access to the full frame area
            x.len.set(full_size);
            x.get_buffer(self.umem.clone())
        })
    }

    pub fn get_buffers(&mut self, amt: usize) -> Vec<FrameBuf> {
        let umem = self.umem.borrow_mut();
        let full_size = umem.frame_size();
        let mut free_list = umem.free_list.borrow_mut();
        free_list
            .drain(..amt)
            .map(|x| {
                // NOTE: setting this to full size gives us access to the full frame area
                x.len.set(full_size);
                x.get_buffer(self.umem.clone())
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct XdpConfig {
    if_name: &'static str,
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
    pub(crate) umem_descriptors: u32,
    pub(crate) use_huge_pages: bool,
}

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
    use_huge_pages: bool,
}

impl XdpConfigBuilder {
    pub const fn if_name(self, name: &'static str) -> XdpConfigBuilder {
        Self {
            if_name: Some(name),
            ..self
        }
    }
    pub const fn tx_size(self, tx_size: u32) -> XdpConfigBuilder {
        if tx_size & (4096 - 1) == 0 {
            return XdpConfigBuilder { tx_size, ..self };
        }
        XdpConfigBuilder { ..self }
    }

    pub const fn rx_size(self, rx_size: u32) -> XdpConfigBuilder {
        if rx_size & (4096 - 1) == 0 {
            return XdpConfigBuilder { rx_size, ..self };
        }
        XdpConfigBuilder { ..self }
    }

    pub const fn queue(self, queue: u32) -> XdpConfigBuilder {
        XdpConfigBuilder { queue, ..self }
    }

    pub const fn xdp_flags(self, xdp_flags: XdpFlags) -> XdpConfigBuilder {
        XdpConfigBuilder {
            xdp_flags: xdp_flags.bits(),
            ..self
        }
    }

    pub const fn bind_flags(self, bind_flags: XskBindFlags) -> XdpConfigBuilder {
        XdpConfigBuilder {
            bind_flags: bind_flags.bits(),
            ..self
        }
    }

    pub const fn libbpf_flags(self, libbpf_flags: u32) -> XdpConfigBuilder {
        XdpConfigBuilder {
            libbpf_flags,
            ..self
        }
    }

    pub const fn fill_size(self, fill_size: u32) -> XdpConfigBuilder {
        if fill_size & (4096 - 1) == 0 {
            return XdpConfigBuilder { fill_size, ..self };
        }
        XdpConfigBuilder { ..self }
    }

    pub const fn completion_size(self, comp_size: u32) -> XdpConfigBuilder {
        if comp_size & (4096 - 1) == 0 {
            return XdpConfigBuilder { comp_size, ..self };
        }
        XdpConfigBuilder { ..self }
    }

    pub const fn frame_size(self, frame_size: u32) -> XdpConfigBuilder {
        XdpConfigBuilder { frame_size, ..self }
    }

    pub const fn frame_headroom(self, frame_headroom: u32) -> XdpConfigBuilder {
        XdpConfigBuilder {
            frame_headroom,
            ..self
        }
    }

    pub const fn umem_flags(self, umem_flags: u32) -> XdpConfigBuilder {
        XdpConfigBuilder { umem_flags, ..self }
    }

    pub const fn umem_descriptors(self, umem_descriptors: u32) -> XdpConfigBuilder {
        XdpConfigBuilder {
            umem_descriptors,
            ..self
        }
    }

    pub const fn use_huge_pages(self, use_huge_pages: bool) -> XdpConfigBuilder {
        XdpConfigBuilder {
            use_huge_pages,
            ..self
        }
    }

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
            use_huge_pages: self.use_huge_pages,
        }
    }
}

impl XdpConfig {
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
            umem_descriptors: 1024,
            use_huge_pages: false,
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
    use futures_lite::prelude::*;
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
                let mut frames = sock.recv().await.unwrap();
                if let Some(first) = frames.get_mut(0) {
                    let src_mac = first.mac_src().to_vec();
                    let dst_mac = first.mac_dst().to_vec();
                    if let EtherType::Ipv4 = first.ether_type() {
                        let out = first.ip_header_len();
                        let ipv = (first[14] & 0b11110000) >> 4;
                        println!(
                            "Got frame of ether type: {:?} ({}), header size {} ( {:08b} ) = {}",
                            first.ether_type(),
                            ipv,
                            first[14],
                            first[14],
                            out
                        );
                        println!(
                            "Got frame with data -- src: {:?}, dst: {:?}",
                            first.ip_src(),
                            first.ip_dst()
                        );
                        if let [a, b, c, d, e, f] = dst_mac[..] {
                            if let [g, h, i, j, k, l] = src_mac[..] {
                                println!(
                                    "Swapped dst mac: [ {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} \
                                     ] with source mac [ \
                                     {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} ]",
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
                println!(
                    "Sent {} items. Pending completions queue: {}, free descriptor queue: {}",
                    resp,
                    sock.umem.borrow().pending_completions.len(),
                    sock.umem.borrow().free_list.borrow().len()
                );
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
