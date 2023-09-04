use crossbeam::queue::ArrayQueue;
use std::io::ErrorKind;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

use clap::Parser;
use csv::{ReaderBuilder, Terminator};
use pnet::packet::{
    icmp::echo_reply::EchoReplyPacket,
    icmp::{echo_request::MutableEchoRequestPacket, IcmpCode, IcmpPacket, IcmpTypes},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    Packet,
};
use serde::Deserialize;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::task::JoinSet;
use tokio::time::timeout;

const ICMP_REQUEST_PACKET_SIZE: usize = MutableEchoRequestPacket::minimum_packet_size();
const ICMP_REPLY_PACKET_SIZE: usize =
    Ipv4Packet::minimum_packet_size() + EchoReplyPacket::minimum_packet_size();

struct Pinger {
    socket_rb: ArrayQueue<Box<IcmpSocket>>,
}

// A ring buffer of IcmpSockets that makes concurrent pings easy.
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
// since the number of `IcmpSocket` instances is limited using the ArrayQueue. One possibility
// to address this would be to use crossbeam's `SegQueue`[1] type which is an unbounded data
// structure with similar semantics. In this case we wouldn't even need to initialize the queue
// here, we could create new `IcmpSocket`s whenever `SeqQueue.pop` returns None, then push the
// new socket onto the queue when its first usage is finished. This would allow the queue to
// grow to its natural size for a given set of input parameters (count, interval) and network
// characteristics (round trip latency).
//
// I'm going to stick with ArrayQueue for now because I don't think it's necessary to really
// perfect the concurrency characteristics here, it's just something I wanted to point out.
//
// [1] https://docs.rs/crossbeam/latest/crossbeam/queue/struct.SegQueue.html
//
impl Pinger {
    //fn new(socket_rb: ArrayQueue<Box<IcmpSocket>>) -> Self {
    fn new(rb_size: usize, icmp_timeout: Duration) -> Result<Self> {
        let socket_rb: ArrayQueue<Box<IcmpSocket>> = ArrayQueue::new(rb_size);
        for _ in 0..rb_size {
            let icmp_socket = Box::new(IcmpSocket::new(icmp_timeout.clone())?);
            socket_rb
                .push(icmp_socket)
                .expect("don't push more than the queues capacity");
        }

        Ok(Self { socket_rb })
    }

    async fn ping(&self, addr: &SockAddr, seq: u16) {
        let mut socket = loop {
            log::trace!("try retrieving socket for packet {}", seq);
            match self.socket_rb.pop() {
                Some(b) => break b,
                None => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        };

        socket.ping(addr, seq).await;

        loop {
            log::trace!("try pushing socket back onto queue");
            match self.socket_rb.push(socket) {
                Ok(_) => break,
                Err(b) => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    socket = b;
                }
            }
        }
    }
}

/// Abstraction for containing individual socket instances and pre-allocated ICMP buffer.
///
/// # Notes on Socket choice:
///
/// So I tried using Domain::PACKET, but both `bind` and `send` socket methods were
/// failing with EINVAL errors, which suggests to me that the `socket2` crate may not be
/// handling those calls correctly for Domain::PACKET sockets (or I just haven't figured out
/// what else I needed to do to make it work beyond manually constructing an ipv4 buffer).
///
/// The reason I wanted to use Domain::PACKET is that I have been reading the `zmap` paper
/// recently[1] and learned one of the tricks they use to achieve such high packet throughput
/// is to use AF_PACKET and manually construct Ethernet packets. This has two primary benefits:
///
/// First, it bypasses TCP/IP/whatever handling at the kernel level. This reduces kernel-specific
/// cpu and memory overhead in high throughput applications.
///
/// Second, in network mapping (or ICMP echo as is the case here) there are often very few
/// differences between the different request packets, which means one can optimize the
/// program to reduce memory allocations by pre-allocating request packet buffers rather
/// constructing them for every request. Request packet buffers are only needed for the duration of
/// each send call, after which they can re-used for subsequent requests.
///
/// To be honest, for a simple exercise like this the memory allocation optimization probably isn't
/// necessary, but I've been wondering how I would implement something zmap-like in Rust while
/// reading the original zmap paper and this interview is a good chance to do that.
///
/// [1] https://zmap.io/paper.pdf
#[derive(Debug)]
struct IcmpSocket {
    inner: Socket,
    icmp_timeout: Duration,
    buf: [u8; ICMP_REQUEST_PACKET_SIZE],
}

impl IcmpSocket {
    fn new(icmp_timeout: Duration) -> Result<Self> {
        let inner = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;

        inner.set_nonblocking(true)?;
        let rw_timeout = Some(Duration::from_millis(100));
        inner.set_write_timeout(rw_timeout)?;
        inner.set_read_timeout(rw_timeout)?;
        //inner.connect(&addr)?;

        let mut buf = [0u8; ICMP_REQUEST_PACKET_SIZE];
        {
            let mut icmp_packet = MutableEchoRequestPacket::new(&mut buf)
                .expect("the buf size should be exactly the minimum icmp packet size");
            icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
            icmp_packet.set_icmp_code(IcmpCode(0));
            icmp_packet.set_identifier(42);
        }

        Ok(Self {
            inner,
            buf,
            icmp_timeout,
        })
    }

    /// Updates the icmp buffer with the current icmp sequence and the new icmp checksum.
    fn update_icmp_request_packet(&mut self, seq: u16) {
        let mut icmp_packet = MutableEchoRequestPacket::new(&mut self.buf)
            .expect("the buf size should be exactly the minimum icmp packet size");
        icmp_packet.set_sequence_number(seq);

        let checksum =
            pnet::packet::icmp::checksum(&IcmpPacket::new(icmp_packet.packet()).expect("TODO"));
        icmp_packet.set_checksum(checksum);
    }

    async fn ping(&mut self, addr: &SockAddr, seq: u16) {
        let start = Instant::now();
        let icmp_timeout = self.icmp_timeout.clone();
        let ip = addr.as_socket_ipv4().unwrap().ip().clone();
        let ping_actual = self.ping_actual(addr, seq);
        match timeout(icmp_timeout, ping_actual).await {
            Err(_elapsed) => println!("{},{},TIMEDOUT", ip, seq),
            Ok(_) => {
                let elapsed = start.elapsed();
                println!("{},{},{}", ip, seq, elapsed.as_millis());
            }
        }
    }

    async fn ping_actual(&mut self, addr: &SockAddr, seq: u16) {
        self.update_icmp_request_packet(seq);
        self.send_echo_request(addr, seq).await;
        self.recv_echo_reply(seq).await;
    }

    async fn send_echo_request(&mut self, addr: &SockAddr, seq: u16) {
        loop {
            match self.inner.send_to(&self.buf, addr) {
                Err(e) => {
                    if e.kind() == ErrorKind::WouldBlock {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    } else {
                        panic!("unhandled socket send error: {}", e);
                    }
                }
                Ok(length) => {
                    log::debug!("sent {} bytes for request {}", length, seq);
                    break;
                }
            }
        }
    }

    async fn recv_echo_reply(&mut self, seq: u16) {
        // "works", but nothing gets written
        //let mut reply_buf: Vec<MaybeUninit<u8>> = Vec::new();
        //let mut reply_slice = reply_buf.as_mut_slice();

        // doesn't work because recv can (apparently) only take an array of MaybeUninit<u8> values
        //let mut reply_buf = vec![0u8; ICMP_REPLY_PACKET_SIZE];
        //let mut reply_slice = reply_buf.as_mut_slice();

        // works, bytes get written, but requires unsafe mem::transmute to get something usable

        // note: we create a bigger array than ICMP_REPLY_PACKET_SIZE because it's possible we get
        // something other than an ICMP reply from the remote and we should try to be aware when
        // that's happening
        let max_packet_size = ICMP_REPLY_PACKET_SIZE + 100;
        loop {
            let mut reply_slice = [MaybeUninit::<u8>::uninit(); ICMP_REPLY_PACKET_SIZE + 100];
            match self.inner.recv(&mut reply_slice) {
                Err(e) => {
                    if e.kind() == ErrorKind::WouldBlock {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    } else {
                        panic!("unhandled socket send error: {}", e);
                    }
                }
                Ok(bytes_read) if bytes_read < ICMP_REPLY_PACKET_SIZE => {
                    panic!(
                        "received packet too small {}, expected {}",
                        bytes_read, ICMP_REPLY_PACKET_SIZE,
                    );
                }
                Ok(bytes_read) if bytes_read > max_packet_size => {
                    panic!(
                        "exceeded max packet size {}, received {}",
                        max_packet_size, bytes_read,
                    );
                }
                Ok(bytes_read) => {
                    log::debug!("received {} bytes for reply {}", bytes_read, seq);
                    if let Some(icmp_reply_packet) =
                        get_icmp_echo_reply_packet(reply_slice, bytes_read)
                    {
                        if icmp_reply_packet.get_sequence_number() == seq {
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Transmute an owned array of `MaybeUninit<u8>` into `Vec<u8>`, check that it's the right kind of
/// IP/ICMP packet, then give ownership of the `Vec<u8>` over to a `EchoReplyPacket<'static>` if
/// everything goes well.
///
/// Note that while dropping `MaybeUninit` values doesn't drop the contained value [1], in this
/// case we rely on the fact that only up to `bytes_read` elements have been written to by the
/// socket library, all other elements are actually uninitialized and therefore safe to be dropped
/// in this function. The elements up to `bytes_read` are properly converted into `u8` and
/// therefore will be properly dropped either by this method or by the calling context once it
/// takes ownership of the `EchoReplyPacket<'static>` return value.
///
/// There is however, a small risk of memory leak IF the program panics while iterating over the
/// initialized values of `buf` [2]. But if the program does panic, it's not like we're recovering
/// it anywhere so the entire program should terminate and memory returned to the kernel.
///
/// [1] https://doc.rust-lang.org/stable/std/mem/union.MaybeUninit.html#method.new
/// [2] https://doc.rust-lang.org/stable/std/mem/union.MaybeUninit.html#initializing-an-array-element-by-element
fn get_icmp_echo_reply_packet(
    buf: [MaybeUninit<u8>; ICMP_REPLY_PACKET_SIZE + 100],
    bytes_read: usize,
) -> Option<EchoReplyPacket<'static>> {
    let mut reply_buf: Vec<u8> = buf
        .into_iter()
        .take(bytes_read)
        .map(|m| unsafe { std::mem::transmute::<_, u8>(m) })
        .collect();

    // check that it's an ICMP packet, comlain if it isn't
    let ipv4_header_len = {
        let ipv4_packet = Ipv4Packet::new(&reply_buf)
            .expect("packet length already verified to be ICMP_REPLY_PACKET_SIZE");
        let protocol = ipv4_packet.get_next_level_protocol();
        match protocol {
            IpNextHeaderProtocols::Icmp => (),
            _ => {
                panic!("unexpected ip next level protocol number: {}", protocol);
            }
        }
        {
            let icmp_packet = IcmpPacket::new(ipv4_packet.payload()).expect("meow");
            match (icmp_packet.get_icmp_type(), icmp_packet.get_icmp_code()) {
                (IcmpTypes::EchoReply, IcmpCode(0)) => (),
                (t, c) => {
                    panic!("unexpected icmp (type, code): ({:?}, {:?})", t, c);
                }
            }
        }
        log::trace!("ipv4 header len: {}", ipv4_packet.get_header_length());
        log::trace!("ipv4 total len: {}", ipv4_packet.get_total_length());
        ipv4_packet.get_total_length() as usize - ipv4_packet.payload().len() as usize
    };

    log::trace!("ipv4 header len: {}", ipv4_header_len);
    let reply_buf: Vec<u8> = reply_buf.drain(ipv4_header_len..).collect();
    log::trace!("echo reply buf len: {}", reply_buf.len());
    Some(EchoReplyPacket::owned(reply_buf).expect("meow"))
}

#[derive(Parser, Debug)]
#[command(author, version)]
struct Cli {
    targets: String,
}

#[derive(Debug, Deserialize)]
struct Target {
    addr: Ipv4Addr,
    count: u16,
    interval: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut rdr = ReaderBuilder::new()
        .has_headers(false)
        .delimiter(b',')
        .terminator(Terminator::Any(b';'))
        .from_reader(cli.targets.as_bytes());
    let mut targets: Vec<Target> = Vec::new();
    for result in rdr.deserialize() {
        let t: Target = result?;
        targets.push(t);
    }

    let icmp_timeout = Duration::from_millis(5000);

    let queue_size = 100usize;
    let pinger = Arc::new(Pinger::new(queue_size, icmp_timeout)?);

    let mut set = JoinSet::new();

    for target in targets.into_iter() {
        let p = pinger.clone();
        set.spawn(async move {
            let mut set = JoinSet::new();

            let p = p.clone();
            let mut interval = tokio::time::interval(Duration::from_millis(target.interval));
            let addr: Box<SockAddr> = Box::new(SocketAddrV4::new(target.addr, 0).into());
            for i in 0..target.count {
                interval.tick().await;
                let a = addr.clone();
                let p = p.clone();
                set.spawn(async move { p.ping(&a, i).await });
            }

            while set.join_next().await.is_some() {}
        });
    }

    while set.join_next().await.is_some() {}

    Ok(())
}
