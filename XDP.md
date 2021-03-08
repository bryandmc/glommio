# XDP omg wtf?!
XDP (eXpress DataPath): https://en.wikipedia.org/wiki/Express_Data_Path - used as the linux kernels answer to "kernel bypass" technologies. The fact is, it's almost impossible to atually beat DPDK in sheer performance, because it's purpose built for speed. But what it can do, is allow you to not "throw the baby out with the bathwater", regarding the linux kernel and it's networking stack. Specifically *AF_XDP*, is the part of XDP that we would use. It provides a model that is very similar to DPDK. It makes available a set of ring buffers to pass ownership of buffers that are shared by the kernel to DMA packets, and userspace, to directly access them. This is inherently unsafe, but is sound as long as you are being properly given "ownership" via these ring buffers.

## Design:
AF_XDP can operate in different modes, or it can select the best possible mode based on what's available. That said, the basic flow works like this...

1. Create UMEM (large allocation of memory, that will be divided into page-size (4k) frames). This will be the only allocation (short of our own structures) required.
2. Create AF_XDP socket, passing the UMEM pointer in, so they are tied together
3. RX path:
    a. Fill the "Fill" queue (ringbuf) with UMEM frame identifiers (just small struct with addr, len, options -- represents a slot in UMEM/frame)
    b. Check RX queue for available frames, this represents received frames
        i. This sometimes requires calling "poll". Currently I submit this through the ring, cause.. why not
        ii. In theory we could block on this spot and do it that way. Instead we are submitting through ring. Need to determine which is better.
        iii. Can we batch these calls to poll s/t we don't need to keep calling it, but it'll keep kicking on.
        iv. We can check a flag for all this. In high-perf drivers it shouldn't be required unless we haven't gotten packets for a long time.
    c. You now own these frames until you pass them somewhere else. It's safe to read the data from the UMEM where the descriptor points

4. TX path:
    0. You own the frames either from your stash (weren't put in fill ring), or that you got from RX
    a. Have UMEM frame full of data you want to send
    b. Insert descriptors for frames you want to send into TX queue
        i. Sometimes requires calling "sendto" on teh descriptor with no data attached. Only X (I forget the number) can be send PER call to sendto, so batch these up in one submission to the ring.
        ii. This is relatively efficient because we can batch them all up and not block. Might be able to jsut call the syscalls directly without blocking.
        iii. Zero-copy and hardware drivers likely won't require this at all. Luckily we check a flag before doing any of this.
    c. Receive finished (sent) descriptors from the "Completion queue".
5. Shutdown AF_XDP socket
6. Shutdown UMEM

## QUIC:
**Resources**:
- QUICHE[cloudflare]: https://github.com/cloudflare/quiche
- NEQO[mozilla]: https://github.com/mozilla/neqo


### Benefits:
We don't have to recreate TCP stack, which can still be offloaded to the linux kernel + io_uring for maximum performance.
