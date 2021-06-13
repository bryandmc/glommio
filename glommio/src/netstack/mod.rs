//!
//! Network stack and related

use core::{fmt, future::Future};
use std::{
    marker::PhantomData,
    net::{IpAddr, SocketAddr},
};

use ahash::AHashMap;

use crate::sys::{umem, xsk, Source};

pub(crate) mod dhcp;
pub(crate) mod ip;

const BROADCAST_MAC_RAW: [u8; 6] = [0xff; 6];
const BROADCAST_MAC: MacAddr = MacAddr([0xff; 6]);

pub struct Port(pub u32);

pub enum SocketHandle {
    Udp(Option<Source>),
}

thread_local! {
    /// TODO: It actually might be nice to not have this in a thread-local because
    /// the cost of lookup using this macro is not 100% ideal. There's a nightly
    /// one that has native performance but we can't require nightly..
    static SOCKETS: AHashMap<(Port, xsk::QueueId), SocketHandle> = AHashMap::new();
}

trait Protocol {
    type Input;
    type Output;

    fn process_packet(&self, input: Self::Input) -> Self::Output;
}

struct Ethernet<'a>(PhantomData<&'a ()>);

impl<'a> Protocol for Ethernet<'a> {
    type Input = umem::FrameBuf;
    type Output = umem::FrameBuf;

    fn process_packet(&self, input: Self::Input) -> Self::Output {
        let ty = input.ether_type();
        input
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    pub fn new(inner: [u8; 6]) -> MacAddr {
        MacAddr(inner)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct MacAddrRef<'a>(&'a [u8]);

impl<'a> MacAddrRef<'a> {
    pub fn new(inner: &'a [u8]) -> MacAddrRef<'a> {
        MacAddrRef(inner)
    }
}

impl PartialEq<MacAddrRef<'_>> for MacAddr {
    fn eq(&self, other: &MacAddrRef<'_>) -> bool {
        self.0.eq(other.0)
    }
}

impl PartialEq<MacAddr> for MacAddrRef<'_> {
    fn eq(&self, other: &MacAddr) -> bool {
        self.0.eq(&other.0)
    }
}

impl std::ops::Deref for MacAddr {
    type Target = [u8; 6];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> std::ops::Deref for MacAddrRef<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> fmt::Debug for MacAddrRef<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let [a, b, c, d, e, f] = *self.0 {
            let addr = format!("{:x}:{:x}:{:x}:{:x}:{:x}:{:x}", a, b, c, d, e, f);
            return fmt.debug_tuple("MacAddrRef").field(&addr).finish();
        }
        fmt.debug_tuple("MacAddrRef").field(&"<invalid>").finish()
    }
}
impl fmt::Debug for MacAddr {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, f] = self.0;
        let addr = format!("{:x}:{:x}:{:x}:{:x}:{:x}:{:x}", a, b, c, d, e, f);
        return fmt.debug_tuple("MacAddr").field(&addr).finish();
    }
}

struct Interface {
    name: String,
}

struct Arp {
    table: AHashMap<IpAddr, MacAddr>,
}

struct Stack {
    arp_table: Option<Arp>,
    dhcp: Option<dhcp::Dhcp<()>>,
    interface: Interface,
    address: Option<SocketAddr>,
    gateway: Option<(IpAddr, MacAddr)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_addr_equality() {
        let mac = MacAddr::new([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        let inner = vec![0xff_u8; 6];
        let macref = MacAddrRef::new(&inner);
        assert!(mac == macref);
        println!("mac: {:?}, mac_ref: {:?}", mac, macref);
        dbg!(mac, macref);
    }

    // #[test]
    // fn dhcp_lease_timer() {
    //     tracing_subscriber::fmt()
    //         .with_env_filter("glommio=debug")
    //         .with_thread_names(true)
    //         .init();
    //     tracing::info!("Logging started...");
    //     tracing::debug!("BROADCAST MAC: {:x?}", BROADCAST_MAC_RAW);

    //     let exec = LocalExecutorBuilder::default().make().unwrap();
    //     exec.run(async move {
    //         let t2 = TimerActionOnce::do_in(Duration::from_secs(8), async
    // move {             tracing::info!("[OUTER] TIMER EXPIRED!!");
    //         });
    //         let t = timer::Timer::new(Duration::from_secs(2));
    //         let dhcp = Dhcp {
    //             lease: None,
    //             elapsed: TimerActionOnce::do_in(Duration::from_secs(2), async
    // move {                 tracing::info!("TIMER EXPIRED!!");
    //             }),
    //         };
    //         let dhcp_rc = Rc::new(RefCell::new(dhcp));

    //         let weak = Rc::downgrade(&dhcp_rc);
    //         dhcp_rc.borrow_mut().elapsed =
    //             TimerActionOnce::do_in(Duration::from_secs(2), async move {
    //                 if let Some(inner) = weak.upgrade() {
    //                     inner.borrow_mut().lease = Some(DhcpLease {});
    //                     let lease = inner.borrow().lease;
    //                     inner.borrow_mut().elapsed =
    //                         TimerActionOnce::do_in(Duration::from_secs(2),
    // async move {                             tracing::info!("INNER INNER:
    // {:?}", lease);                         });
    //                 }
    //             });
    //         t2.join().await;
    //     });
    // }
}
