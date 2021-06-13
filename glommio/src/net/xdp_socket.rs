//!
//! Raw AF_XDP socket access to users

use std::{
    borrow::{Borrow, BorrowMut},
    cell::RefCell,
    collections::VecDeque,
    rc::{Rc, Weak},
};

use itertools::Itertools;
use tracing::Instrument;

use crate::{
    parking::Reactor,
    sys::{
        umem::FrameBuf,
        xsk::{self, XskConfig, XskSocketDriver},
    },
    umem, Local,
};

#[macro_export]
macro_rules! ref_cnt {
    ($arg:expr) => {
        Rc::new(RefCell::new($arg))
    };
}

/// Raw L2 access to frames, destined to a particular interface/queue pair
pub struct RawXdpSocket {
    inner: Rc<RefCell<XdpSockInner>>,
}

struct XdpSockInner {
    interface: String,
    queue: xsk::QueueId,
    driver: Rc<RefCell<XskSocketDriver>>,
    xdp_reactor: Rc<xsk::Reactor>,
}

impl RawXdpSocket {
    pub fn new<S: AsRef<str>, Q: Into<xsk::QueueId>>(
        interface: S,
        queue: Q,
        config: XskConfig,
    ) -> RawXdpSocket {
        let xdp_reactor = Local::get_xdp_reactor();
        let driver = xdp_reactor.register_socket(config).unwrap();

        RawXdpSocket {
            inner: ref_cnt!(XdpSockInner {
                interface: interface.as_ref().to_string(),
                queue: queue.into(),
                driver,
                xdp_reactor,
            }),
        }
    }

    pub fn try_recv(&self) -> Vec<FrameBuf> {
        let ptr = self.inner.as_ptr();
        let driver = unsafe { &*ptr }.driver.clone();
        let mut refmut = (*driver).borrow_mut();
        let frames = refmut.consume_rx();
        frames
    }

    pub async fn recv(&self) {}

    pub fn on_recv<B, F>(&self, fun: F) -> Vec<B>
    where
        F: FnMut(FrameBuf) -> B,
    {
        self.batch_recv().into_iter().map(fun).collect_vec()
    }

    pub fn send(&self, frames: &mut VecDeque<umem::FrameBuf>) {
        (*self.inner)
            .borrow()
            .xdp_reactor
            .stage_tx_descriptors(frames);
    }

    pub fn batch_recv(&self) -> VecDeque<umem::FrameBuf> {
        let mut inner = (*self.inner).borrow_mut();
        inner.xdp_reactor.borrow_mut().recv_packets()
    }
}

#[cfg(test)]
mod tests {
    use crate::{sys::umem, xsk::BusyPoll, LocalExecutorBuilder};

    use super::*;

    #[test]
    fn construct_raw_xsk_socket() {
        tracing_subscriber::fmt()
            .with_env_filter("glommio=trace")
            .init();
        let config = xsk::XskConfig {
            if_name: "veth1",
            tx_size: 1024,
            rx_size: 1024,
            queue: 0,
            xdp_flags: xsk::XdpFlags::XDP_FLAGS_DRV_MODE.bits(),
            bind_flags: xsk::XskBindFlags::XDP_USE_NEED_WAKEUP.bits(),
            libbpf_flags: 0,
            busy_poll: BusyPoll::Disable,
        };
        let executor = LocalExecutorBuilder::new()
            .mempool(umem::UmemBuilder::new(1024))
            .spawn(move || async move {
                let reactor = Local::get_xdp_reactor();
                // let sock = reactor.register(config).unwrap();
                let mut l2 = RawXdpSocket::new("veth1", 0, config);
                // let u = umem::Umem::get();
                let frames = l2.try_recv();
                let frames = l2.recv().await;
                l2.on_recv(|x: umem::FrameBuf| x);
            })
            .unwrap()
            .join();
    }
}
