//!
//! DHCP handling of userspace network stack

use std::net::Ipv4Addr;

use crate::{
    sys::{
        umem::{self, EtherType, UdpPacket},
        xsk,
    },
    timer::TimerActionOnce,
};

use super::{ip, MacAddr, BROADCAST_MAC};

pub(crate) struct Dhcp<T> {
    lease: Option<DhcpLease>,
    elapsed: Option<TimerActionOnce<T>>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DhcpLease {}

impl<T> Dhcp<T> {
    pub fn create() -> Dhcp<T> {
        Dhcp {
            lease: None,
            elapsed: None,
        }
    }

    fn create_dhcp_request(
        mac: MacAddr,
        ip: Ipv4Addr,
        mut buf: umem::FrameBuf<'_>,
    ) -> UdpPacket<'_> {
        buf.mac_src_mut().copy_from_slice(&mac.0);
        buf.set_mac_dst(BROADCAST_MAC);
        buf.set_ether_type(EtherType::Ipv4);
        buf.set_ip_src(ip);
        buf.set_ip_dst(Ipv4Addr::BROADCAST);
        buf.set_ip_header_len(20);
        buf.set_ip_version(ip::IpVersion::V4);
        buf.set_ip_total_len(320);
        buf.ip_tos_or_precedence();
        buf.set_ip_tos_or_precedence(6);
        buf.set_ip_ttl(64);
        buf.set_ip_protocol(0x11);
        buf.calculate_ipv4_csum();
        let mut udp = UdpPacket::new(buf);
        udp.set_src_port(68);
        udp.set_dst_port(67);
        udp.set_len(300);
        udp.calculate_udp_checksum();
        let csum = udp.checksum();
        println!("[UDP] CHECKSUM: {:#x}", csum);
        udp
    }
}

#[cfg(test)]
mod tests {
    use umem::FrameBuf;

    use crate::sys::umem::UmemBuilder;

    use super::*;

    #[test]
    fn dhcp_create() {
        // let mut umem = UmemBuilder::new(100).build().unwrap();
        // let mut frames = umem.alloc(1);
        // let first = frames.first_mut().unwrap();
        let mut first = FrameBuf::new();
        // let mac = MacAddr::new([0x52, 0x5e, 0x8e, 0x2c, 0xbe, 0x66]);
        let mac = MacAddr::new([0x9c, 0xb6, 0xd0, 0xf6, 0xcf, 0xd7]);
        unsafe {
            println!("{:#?}", &first);
            let udp = Dhcp::<()>::create_dhcp_request(mac, Ipv4Addr::new(0, 0, 0, 0), first);
            println!("{:#?}", &udp);
        }
    }
}
