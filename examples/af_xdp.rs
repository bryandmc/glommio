use std::{cell::RefCell, io, rc::Rc, time::Duration};

use glommio::net::xdp::XdpSocket;
use glommio::{
    net::{xdp::XdpConfig, UdpSocket},
    timer, Local,
};
use glommio::{LocalExecutorBuilder, Task};

fn main() -> Result<(), io::Error> {
    let mut builder = LocalExecutorBuilder::default();
    let local = builder
        .name("main")
        .pin_to_cpu(0)
        .spin_before_park(Duration::from_secs(1))
        .make()?;

    local.run(async move {
        let mut socket =
            XdpSocket::bind_with_config(XdpConfig::builder("veth1", 0).build()).unwrap();
        let sock = Rc::new(RefCell::new(socket));
        let mut spawned = vec![];
        let inner_socket = sock.clone();
        let t = Task::local(async move {
            let mut sock_handle = inner_socket.borrow_mut();
            loop {
                let amt = sock_handle.recv().await;
                let bufs = amt.unwrap();
                if bufs.is_empty() {
                    return;
                }
                for mut b in bufs {
                    // dbg!(b.mac_src(), b.mac_dst(), b.ether_type());
                    println!("Got framebuf: {:?}", b);
                    let orig_dest = b[..6].to_vec();
                    let orig_src = b[6..12].to_vec();
                    b.mac_dst_mut().copy_from_slice(&orig_src);
                    b.mac_src_mut().copy_from_slice(&orig_dest);
                    let mut v = vec![b];
                    let resp = sock_handle.send(&mut v).await;
                }
                Local::yield_if_needed().await;
            }
        })
        .detach();
        spawned.push(t);
        let handles = futures::future::join_all(spawned).await;
        dbg!(&handles);
    });

    Ok(())
}
