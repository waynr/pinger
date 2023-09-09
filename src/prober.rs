use crossbeam::queue::ArrayQueue;
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::probes::icmp::IcmpProbe;
use crate::error::Result;
use crate::socket::AsyncSocket;
use crate::ethernet::EthernetConf;

// A ring buffer of IcmpProbes that makes concurrent pings easy.
//
// # Implementation Notes
//
// Rather than using a single socket shared across all packets, we want separate sockets to
// simplify implementation of echo reply timeout on each echo request-reply pair. The idea
// here being that in the course of each `ping` call each socket only accepts the reply packet
// corresponding to the request it just sent and performs a tokio sleeps between non-blocking
// `recv` attempts so that an outer tokio timeout future can cancel the inner future at the
// specified icmp timeout.
//
// One potential limitation here is going to be the number of concurrent pings that can run
// since the number of `IcmpProbe` instances is limited using the ArrayQueue. One possibility
// to address this would be to use crossbeam's `SegQueue`[1] type which is an unbounded data
// structure with similar semantics. In this case we wouldn't even need to initialize the queue
// here, we could create new `IcmpProbe`s whenever `SeqQueue.pop` returns None, then push the
// new socket onto the queue when its first usage is finished. This would allow the queue to
// grow to its natural size for a given set of input parameters (count, interval) and network
// characteristics (round trip latency).
//
// I'm going to stick with ArrayQueue for now because I don't think it's necessary to really
// perfect the concurrency characteristics here, it's just something I wanted to point out.
//
// [1] https://docs.rs/crossbeam/latest/crossbeam/queue/struct.SegQueue.html
//
pub struct Prober {
    socket_rb: ArrayQueue<Box<IcmpProbe>>,
}

impl Prober {
    pub fn new(ethernet_conf: EthernetConf, rb_size: usize, icmp_timeout: Duration) -> Result<Self> {
        let sender = Self::create_sender(&ethernet_conf)?;
        let socket_rb: ArrayQueue<Box<IcmpProbe>> = ArrayQueue::new(rb_size);
        for _ in 0..rb_size {
            let receiver = Self::create_receiver()?;
            let icmp_socket = Box::new(IcmpProbe::new(
                sender.clone(),
                receiver,
                &ethernet_conf,
                icmp_timeout.clone(),
            )?);
            socket_rb
                .push(icmp_socket)
                .expect("don't push more than the queues capacity");
        }

        Ok(Self { socket_rb })
    }

    fn create_receiver() -> Result<AsyncSocket> {
        // note: for some reason using Domain::PACKET as is done in zmap (libpcap, really) doesn't
        // work here -- the socket never becomes ready for reading. for now I'm setting it back to
        // Domain::IPV4 but will continue trying to figure out how to get Domain::PACKET working
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;

        socket.set_nonblocking(true)?;
        let rw_timeout = Some(Duration::from_millis(1));
        socket.set_write_timeout(rw_timeout)?;
        socket.set_read_timeout(rw_timeout)?;

        Ok(AsyncSocket::new(socket)?)
    }

    fn create_sender(ethernet_conf: &EthernetConf) -> Result<AsyncSocket> {
        // choose Domain::PACKET here so that we can cache ICMP reply packets and circumvent
        // network-layer handling of packets in the kernel
        let socket = Socket::new(Domain::PACKET, Type::RAW, None)?;

        socket.set_nonblocking(true)?;
        let rw_timeout = Some(Duration::from_millis(1));
        socket.set_write_timeout(rw_timeout)?;
        socket.set_read_timeout(rw_timeout)?;

        // initialize sockaddr_storage then reference as raw pointer to a sockaddr_ll in order to
        // set link-layer options on the addr before binding the socket. the intent here is to bind
        // the AF_PACKET socket by index to the interface in the given EthernetConf.
        //
        // it's safe to initialize a sockaddr_storage to all zeroes because zeroes are valid values
        // for its fields.
        let mut addr_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        {
            // I don't really understand why this line isn't considered unsafe by the compiler
            let mut addr_ll_ref: *mut libc::sockaddr_ll =
                (&mut addr_storage as *mut libc::sockaddr_storage).cast();

            // these operations are safe because according to 'man sockaddr_storage' it is designed
            // to be at least as large as any other sockaddr_* libc type and cast to any of those
            // types (such as sockaddr_ll here) so that the needed fields for the sockaddr_* type
            // can be set
            //let hw = ethernet_conf.ethernet_info.source.clone();
            //log::debug!("hw addr: {:?}", hw);
            unsafe {
                (*addr_ll_ref).sll_family = libc::AF_PACKET as u16;
                (*addr_ll_ref).sll_ifindex = ethernet_conf.interface.index as i32;
                (*addr_ll_ref).sll_protocol = libc::ETH_P_ALL as u16;
                //(*addr_ll_ref).sll_addr = [hw.0, hw.1, hw.2, hw.3, hw.4, hw.5, 0, 0];
                log::debug!("sockaddr_ll for bind set to: {:?}", *addr_ll_ref);
            }
        }
        let len = std::mem::size_of_val(&addr_storage) as libc::socklen_t;

        // the following is safe because of the abovementioned explanations regarding initializing
        // the sockaddr_storage bits to 0 and casting to a sockaddr_ll to set link-layer fields for
        // the sockaddr; so we have correctly constructed our sockaddr_storage.
        let addr = unsafe { SockAddr::new(addr_storage, len) };

        // trying to bind any other type of SockAddr (eg Ipv4Addr) than what we have initialized
        // above would fail with an EINVAL error for an AF_PACKET
        socket.bind(&addr)?;

        Ok(AsyncSocket::new(socket)?)
    }

    pub async fn probe(&self, addr: &SockAddr, seq: u16) {
        let mut probe = loop {
            log::trace!("try retrieving probe for packet {}", seq);
            match self.socket_rb.pop() {
                Some(b) => break b,
                None => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        };

        probe.ping(addr, seq).await;

        loop {
            log::trace!("try pushing probe back onto queue");
            match self.socket_rb.push(probe) {
                Ok(_) => break,
                Err(b) => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    probe = b;
                }
            }
        }
    }
}

