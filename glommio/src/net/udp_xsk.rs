//!
//! UDP sockets powered by XDP

use std::{
    cell::RefCell,
    hash::{Hash, Hasher},
    net::ToSocketAddrs,
    rc::Rc,
};

use ahash::AHasher;

use crate::{sys::xsk, Local};

type Result<T> = crate::Result<T, ()>;

struct Udp {
    xsk: Rc<RefCell<xsk::XskSocketDriver<'static>>>,
}

impl Udp {
    pub fn bind<A: ToSocketAddrs>(addr: A) -> Result<Udp> {
        let reactor = Local::get_reactor();
        let xsk = reactor.xsk_sockets.get(&xsk::QueueId(0)).unwrap().clone();
        xsk.bind_udp_socket(addr);
        Ok(Udp { xsk })
    }

    pub async fn connect<A: ToSocketAddrs>(&self, addr: A) -> Result<()> {
        let mut hasher = AHasher::default();
        for socket_addr in addr.to_socket_addrs()? {
            socket_addr.hash(&mut hasher);
            let hash = hasher.finish();
        }
        Ok(())
    }
}
