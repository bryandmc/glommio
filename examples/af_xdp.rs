use std::{cell::RefCell, io, rc::Rc, time::Duration};

use glommio::{net::xdp_socket, timer, umem, Local, LocalExecutorBuilder, Task};

fn main() -> Result<(), io::Error> {
    let mut builder = LocalExecutorBuilder::default();
    let local = builder
        .name("main")
        .pin_to_cpu(0)
        .mempool(umem::UmemBuilder::new(1024))
        .spin_before_park(Duration::from_secs(1))
        .make()?;

    local.run(async move {
        // do stuff
        let config = xsk::XskConfig {
            if_name: "veth1",
            tx_size: 256,
            rx_size: 256,
            queue: 0,
            xdp_flags: xsk::XdpFlags::XDP_FLAGS_DRV_MODE.bits(),
            bind_flags: xsk::XskBindFlags::XDP_USE_NEED_WAKEUP.bits(),
            libbpf_flags: 0,
        };

        let socket = xdp_socket::RawXdpSocket::new("veth1", 0, config);
        // let pool = umem::MEMPOOL.with(|x| x.clone());
    });

    Ok(())
}
