use crossbeam::queue::ArrayQueue;
use pnet::packet::icmp::MutableIcmpPacket;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

use clap::Parser;
use csv::{ReaderBuilder, Terminator};
use futures::stream::TryStreamExt;
use netlink_packet_route::rtnl::{address, constants as nlconsts, link, neighbour};
use netlink_packet_route::LinkMessage;
use pnet::packet::{
    ethernet::{EtherTypes, Ethernet, EthernetPacket, MutableEthernetPacket},
    icmp::echo_reply::EchoReplyPacket,
    icmp::{echo_request::MutableEchoRequestPacket, IcmpCode, IcmpPacket, IcmpTypes},
    ip::IpNextHeaderProtocols,
    ipv4::{Ipv4Packet, MutableIpv4Packet},
    MutablePacket, Packet,
};
use pnet::util::MacAddr;
use rtnetlink::{new_connection, Handle, IpVersion};
use serde::Deserialize;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::unix::AsyncFd;
use tokio::task::JoinSet;
use tokio::time::timeout;

const ETHERNET_PACKET_MIN_SIZE: usize = MutableEthernetPacket::minimum_packet_size();
const IPV4_PACKET_MIN_SIZE: usize = Ipv4Packet::minimum_packet_size();
const ICMP_REQUEST_PACKET_SIZE: usize = ETHERNET_PACKET_MIN_SIZE
    + IPV4_PACKET_MIN_SIZE
    + MutableEchoRequestPacket::minimum_packet_size();
const ICMP_REPLY_PACKET_SIZE: usize = ETHERNET_PACKET_MIN_SIZE
    + Ipv4Packet::minimum_packet_size()
    + EchoReplyPacket::minimum_packet_size();

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
    fn new(ethernet_conf: EthernetConf, rb_size: usize, icmp_timeout: Duration) -> Result<Self> {
        let socket_rb: ArrayQueue<Box<IcmpSocket>> = ArrayQueue::new(rb_size);
        for _ in 0..rb_size {
            let inner = Self::create_socket(&ethernet_conf)?;
            let icmp_socket = Box::new(IcmpSocket::new(inner, &ethernet_conf, icmp_timeout.clone())?);
            socket_rb
                .push(icmp_socket)
                .expect("don't push more than the queues capacity");
        }

        Ok(Self { socket_rb })
    }

    fn create_socket(ethernet_conf: &EthernetConf) -> Result<Socket> {
        // choose Domain::PACKET here so that we can cache ICMP reply packets and circumvent
        // network-layer handling of packets in the kernel
        let socket = Socket::new(
            Domain::PACKET,
            Type::RAW,
            Some(Protocol::from(libc::ETH_P_ALL.to_be())),
        )?;

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

        socket.set_nonblocking(true)?;
        let rw_timeout = Some(Duration::from_millis(1));
        socket.set_write_timeout(rw_timeout)?;
        socket.set_read_timeout(rw_timeout)?;

        Ok(socket)
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

/// Abstraction for containing individual socket instances and pre-allocated Ethernet packet
/// buffer.
///
/// # Notes on Socket choice:
///
/// The reason I choose Domain::PACKET is that I have been reading the `zmap` paper recently[1] and
/// learned one of the tricks they use to achieve such high packet throughput is to use AF_PACKET
/// and manually construct Ethernet packets. This has two primary benefits:
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
    inner: AsyncFd<Socket>,
    icmp_timeout: Duration,
    buf: [u8; ICMP_REQUEST_PACKET_SIZE],
}

impl IcmpSocket {
    fn new(socket: Socket, ethernet_conf: &EthernetConf, icmp_timeout: Duration) -> Result<Self> {

        let mut buf = [0u8; ICMP_REQUEST_PACKET_SIZE];
        {
            let mut ethernet_packet = MutableEthernetPacket::new(&mut buf).expect("meow");
            log::debug!("ethernet_packet len: {}", ethernet_packet.packet().len());
            ethernet_packet.set_source(ethernet_conf.ethernet_info.source);
            ethernet_packet.set_destination(ethernet_conf.ethernet_info.destination);
            ethernet_packet.set_ethertype(ethernet_conf.ethernet_info.ethertype);

            log::debug!(
                "ethernet_packet payload len: {}",
                ethernet_packet.payload().len()
            );
            let mut ipv4_packet =
                MutableIpv4Packet::new(ethernet_packet.payload_mut()).expect("meow");
            log::debug!("ipv4_packetlen: {}", ipv4_packet.packet().len());
            ipv4_packet.set_version(4);
            ipv4_packet.set_source(ethernet_conf.interface.address);
            ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
            ipv4_packet.set_header_length(5);
            ipv4_packet.set_ttl(101); // not sure what a good value here would be so i picked this
            ipv4_packet.set_checksum(0); // not sure what a good value here would be so i picked this
            ipv4_packet.set_total_length(
                (MutableIpv4Packet::minimum_packet_size()
                    + MutableEchoRequestPacket::minimum_packet_size()) as u16,
            );
            // arbitrarily
            let checksum = pnet::packet::ipv4::checksum(
                &Ipv4Packet::new(ipv4_packet.packet()).expect("the buf size should be fine"),
            );
            ipv4_packet.set_checksum(checksum);

            log::debug!("ipv4 len: {}", MutableIpv4Packet::minimum_packet_size());
            log::debug!(
                "icmp min len: {}",
                MutableEchoRequestPacket::minimum_packet_size()
            );
            log::debug!("ipv4_packet total len: {}", ipv4_packet.get_total_length());
            log::debug!("ipv4_packet payload len: {}", ipv4_packet.payload().len());
            let mut icmp_packet = MutableEchoRequestPacket::new(ipv4_packet.payload_mut())
                .expect("the buf size should be exactly the minimum icmp packet size");
            icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
            icmp_packet.set_icmp_code(IcmpCode(0));
            icmp_packet.set_identifier(42);
        }

        Ok(Self {
            inner: AsyncFd::new(socket)?,
            buf,
            icmp_timeout,
        })
    }

    async fn recv(&self, out: &mut [MaybeUninit<u8>]) -> std::io::Result<usize> {
        loop {
            let mut guard = self.inner.readable().await?;

            match guard.try_io(|inner| inner.get_ref().recv(out)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    async fn send_to(&self, addr: &SockAddr) -> std::io::Result<usize> {
        loop {
            let mut guard = self.inner.writable().await?;

            match guard.try_io(|inner| inner.get_ref().send_to(&self.buf, addr)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Updates the icmp buffer with the current icmp sequence and the new icmp checksum.
    fn update_icmp_request_packet(&mut self, addr: &Ipv4Addr, seq: u16) {
        let mut ethernet_packet = MutableEthernetPacket::new(&mut self.buf).expect("meow");

        let mut ipv4_packet = MutableIpv4Packet::new(ethernet_packet.payload_mut()).expect("meow");
        ipv4_packet.set_destination(addr.clone());
        ipv4_packet.set_checksum(0);
        let checksum = pnet::packet::ipv4::checksum(
            &Ipv4Packet::new(ipv4_packet.packet()).expect("the buf size should be fine"),
        );
        ipv4_packet.set_checksum(checksum);

        let mut icmp_packet = MutableEchoRequestPacket::new(ipv4_packet.payload_mut())
            .expect("the buf size should be exactly the minimum icmp packet size");
        icmp_packet.set_sequence_number(seq);
        icmp_packet.set_checksum(0);

        let checksum = pnet::packet::icmp::checksum(
            &IcmpPacket::new(icmp_packet.packet())
                .expect("the buf size should be exactly the minimum icmp packet size"),
        );
        icmp_packet.set_checksum(checksum);
    }

    async fn ping(&mut self, addr: &SockAddr, seq: u16) {
        let ip = addr.as_socket_ipv4().unwrap().ip().clone();
        self.update_icmp_request_packet(&ip, seq);
        self.send_echo_request(addr, seq).await;

        let start = Instant::now();
        let icmp_timeout = self.icmp_timeout.clone();
        let ip = addr.as_socket_ipv4().unwrap().ip().clone();
        match timeout(icmp_timeout, self.recv_echo_reply(addr, seq)).await {
            Err(_elapsed) => println!("{},{},TIMEDOUT", ip, seq),
            Ok(_) => {
                let elapsed = start.elapsed();
                println!("{},{},{}", ip, seq, elapsed.as_micros());
            }
        }
    }

    async fn send_echo_request(&mut self, addr: &SockAddr, seq: u16) {
        loop {
            log::trace!("about to try sending via async io");
            match self.send_to(addr).await {
                Err(e) => {
                    panic!("unhandled socket send error: {}", e);
                }
                Ok(length) => {
                    log::trace!("sent {} bytes for request {}", length, seq);
                    break;
                }
            }
        }
    }

    async fn recv_echo_reply(&mut self, addr: &SockAddr, seq: u16) {
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
        let ipv4addr = addr
            .as_socket_ipv4()
            .expect("we only support ipv4 for now")
            .ip()
            .clone();
        loop {
            let mut reply_slice = [MaybeUninit::<u8>::uninit(); ICMP_REPLY_PACKET_SIZE + 100];
            match self.recv(&mut reply_slice).await {
                Err(e) => {
                    panic!("unhandled socket read error: {}", e);
                }
                Ok(bytes_read) => {
                    // Transmute an owned array of `MaybeUninit<u8>` into `Vec<u8>` then check if
                    // it's the packet we're looking for.
                    //
                    // Note that while dropping `MaybeUninit` values doesn't drop the contained
                    // value [1], in this case we rely on the fact that only up to `bytes_read`
                    // elements have been written to by the socket library, all other elements are
                    // actually uninitialized and therefore safe to be dropped in this function.
                    // The elements up to `bytes_read` are properly converted into `u8` and
                    // therefore will be properly dropped either by this method or by the calling
                    // context once it takes ownership of the `EchoReplyPacket<'static>` return
                    // value.
                    //
                    // There is however, a small risk of memory leak IF the program panics while
                    // iterating over the initialized values of `buf` [2]. But if the program does
                    // panic, it's not like we're recovering it anywhere so the entire program
                    // should terminate and memory returned to the kernel.
                    //
                    // [1] https://doc.rust-lang.org/stable/std/mem/union.MaybeUninit.html#method.new
                    // [2] https://doc.rust-lang.org/stable/std/mem/union.MaybeUninit.html#initializing-an-array-element-by-element
                    let reply_buf: Vec<u8> = reply_slice
                        .into_iter()
                        .take(bytes_read)
                        .map(|m| unsafe { std::mem::transmute::<_, u8>(m) })
                        .collect();
                    log::trace!("received {} bytes for reply {}", bytes_read, seq);
                    if bytes_read < ICMP_REPLY_PACKET_SIZE {
                        log::trace!(
                            "received packet too small {}, expected {}",
                            bytes_read,
                            ICMP_REPLY_PACKET_SIZE,
                        );
                        continue;
                    }

                    if is_expected_packet(&reply_buf, &ipv4addr, seq) {
                        break;
                    }
                }
            }
        }
    }
}

/// Check that the given buffer is:
/// * from the expected link local addr
/// * from the expected source IP
/// * the right kind of IP packet (ICMP)
/// * the right kind of ICMP packet (Echo Reply)
/// * the expected sequence number
fn is_expected_packet(reply_buf: &[u8], addr: &Ipv4Addr, seq: u16) -> bool {
    // check that it's an Ethernet packet
    let ethernet_packet = EthernetPacket::new(&reply_buf)
        .expect("packet length already verified to be at least ICMP_REPLY_PACKET_SIZE");
    // check that it's an ICMP packet
    let ipv4_header_len = {
        let ipv4_packet = Ipv4Packet::new(&reply_buf)
            .expect("packet length already verified to be at least ICMP_REPLY_PACKET_SIZE");
        let source = &ipv4_packet.get_source();
        if source != addr {
            log::trace!("unexpected ipv4 source address: {source}");
            return false;
        }
        let protocol = ipv4_packet.get_next_level_protocol();
        match protocol {
            IpNextHeaderProtocols::Icmp => (),
            _ => {
                log::trace!("unexpected ip next level protocol number: {}", protocol);
                return false;
            }
        }
        // check that it's the right ICMP packet type
        {
            let icmp_packet = IcmpPacket::new(ipv4_packet.payload())
                .expect("packet length already verified to be at least ICMP_REPLY_PACKET_SIZE");
            match (icmp_packet.get_icmp_type(), icmp_packet.get_icmp_code()) {
                (IcmpTypes::EchoReply, IcmpCode(0)) => (),
                (t, c) => {
                    log::trace!("unexpected icmp (type, code): ({:?}, {:?})", t, c);
                    return false;
                }
            }
        }
        log::trace!("ipv4 header len: {}", ipv4_packet.get_header_length());
        log::trace!("ipv4 total len: {}", ipv4_packet.get_total_length());
        ipv4_packet.get_total_length() as usize - ipv4_packet.payload().len() as usize
    };

    log::trace!("ipv4 header len: {}", ipv4_header_len);
    let reply_buf = &reply_buf[ipv4_header_len..];
    log::trace!("echo reply buf len: {}", reply_buf.len());
    let reply_packet = EchoReplyPacket::new(reply_buf)
        .expect("packet length already verified to be at least ICMP_REPLY_PACKET_SIZE");

    reply_packet.get_sequence_number() == seq
}

#[derive(Debug)]
/// Information about the interface on which we will emit packets and listen for responses.
struct InterfaceInfo {
    name: String,
    index: u32,
    //address: [u8; 4],
    address: Ipv4Addr,
    mac_addr: MacAddr,
}

impl TryFrom<LinkMessage> for InterfaceInfo {
    type Error = Box<dyn std::error::Error>;

    fn try_from(lm: LinkMessage) -> Result<InterfaceInfo> {
        let index = lm.header.index;

        let name = lm
            .nlas
            .iter()
            .find_map(|nla| match nla {
                link::nlas::Nla::IfName(name) => Some(name.clone()),
                _ => None,
            })
            .ok_or::<Box<dyn std::error::Error>>(
                format!("couldn't find interface name for {index}").into(),
            )?;

        let mac_addr = lm
            .nlas
            .iter()
            .find_map(|nla| match nla {
                link::nlas::Nla::PermAddress(v) if v.len() == 6 => {
                    Some(MacAddr(v[0], v[1], v[2], v[3], v[4], v[5]))
                }
                _ => None,
            })
            .ok_or::<Box<dyn std::error::Error>>(
                format!("couldn't find MAC address for interface {name} (idx: {index})").into(),
            )?;

        Ok(InterfaceInfo {
            name,
            index,
            address: Ipv4Addr::new(0u8, 0, 0, 0),
            mac_addr,
        })
    }
}

impl InterfaceInfo {
    async fn retrieve_address(&mut self, handle: Handle) -> Result<()> {
        let mut addresses = handle
            .address()
            .get()
            .set_link_index_filter(self.index)
            .execute();

        let notfoundmsg = format!(
            "unable to retrieve address for interface {} (idx {})",
            self.name, self.index
        );

        while let Some(msg) = addresses.try_next().await? {
            if msg.header.family as u16 != nlconsts::AF_INET {
                continue;
            }

            self.address = msg
                .nlas
                .iter()
                .find_map(|nla| match nla {
                    address::nlas::Nla::Address(v) if v.len() == 4 => {
                        Some(Ipv4Addr::new(v[0], v[1], v[2], v[3]))
                    }
                    _ => None,
                })
                .ok_or::<Box<dyn std::error::Error>>(notfoundmsg.into())?;
            return Ok(());
        }

        Err(notfoundmsg.into())
    }
}

/// Contains information retrieved from the local network stack necessary to construct Ethernet
/// packets.
#[derive(Debug)]
struct EthernetConf {
    ethernet_info: Ethernet,
    interface: InterfaceInfo,
}

impl EthernetConf {
    /// Prepare a EthernetConf for the specified interface name.
    async fn new(interface_name: String) -> Result<Self> {
        // due to some kind of bug in rtnetlink, we have to use a separate netlink connection for
        // getting the link info than what we use for getting the neighbor info
        // TODO: file bug report w/ minimal reproduction
        let (connection, handle, _) = new_connection()?;
        tokio::spawn(connection);

        let interface = get_interface_by_name(handle.clone(), interface_name).await?;
        let destination = get_neighbor_by_interface(handle.clone(), &interface).await?;

        let ethernet_info = Ethernet {
            destination,
            source: interface.mac_addr,
            ethertype: EtherTypes::Ipv4,
            payload: Vec::new(),
        };
        Ok(Self {
            ethernet_info,
            interface,
        })
    }

    /// Prepare a EthernetConf for the interface attached to the default route.
    async fn any() -> Result<Self> {
        // due to some kind of bug in rtnetlink, we have to use a separate netlink connection for
        // routes+links than what we subsequently use for neighbours.
        // TODO: file bug report w/ minimal reproduction
        let (connection, handle, _) = new_connection()?;
        tokio::spawn(connection);

        let index = get_default_route_interface_index(handle.clone()).await?;
        let interface = get_interface_by_index(handle.clone(), index).await?;
        let destination = get_neighbor_by_interface(handle.clone(), &interface).await?;

        let ethernet_info = Ethernet {
            destination,
            source: interface.mac_addr,
            ethertype: EtherTypes::Ipv4,
            payload: Vec::new(),
        };
        Ok(Self {
            ethernet_info,
            interface,
        })
    }
}

async fn get_default_route_interface_index(handle: Handle) -> Result<u32> {
    let mut routes = handle.route().get(IpVersion::V4).execute();

    while let Some(route) = routes.try_next().await? {
        if let Some(idx) = route.output_interface() {
            log::debug!("found interface index: {idx}");
            return Ok(idx);
        }
    }
    Err(format!("couldn't find suitable default route").into())
}

async fn get_interface_by_index(handle: Handle, interface_index: u32) -> Result<InterfaceInfo> {
    let mut links = handle.link().get().match_index(interface_index).execute();

    let mut ii = if let Some(link) = links.try_next().await? {
        let ii: InterfaceInfo = link.try_into()?;
        log::debug!("found interface {0}: {ii:?}", ii.name);
        ii
    } else {
        return Err(format!("couldn't find netlink info for interface {interface_index}").into());
    };

    ii.retrieve_address(handle).await?;

    Ok(ii)
}

async fn get_interface_by_name(handle: Handle, interface_name: String) -> Result<InterfaceInfo> {
    let mut links = handle
        .link()
        .get()
        .match_name(interface_name.clone())
        .execute();

    let mut ii = if let Some(link) = links.try_next().await? {
        let ii: InterfaceInfo = link.try_into()?;
        log::debug!("found interface {interface_name}: {ii:?}");
        ii
    } else {
        return Err(format!("couldn't find netlink info for {interface_name}").into());
    };

    ii.retrieve_address(handle).await?;

    Ok(ii)
}

async fn get_neighbor_by_interface(handle: Handle, interface: &InterfaceInfo) -> Result<MacAddr> {
    let mut neighbors = handle
        .neighbours()
        .get()
        .set_family(IpVersion::V4)
        .execute();

    while let Some(msg) = neighbors.try_next().await? {
        if msg.header.ifindex != interface.index {
            log::debug!(
                "neighbor does not match output interface ({}) ({msg:?})",
                interface.index
            );
            continue;
        }
        return msg
            .nlas
            .iter()
            .find_map(|nla| match nla {
                neighbour::Nla::LinkLocalAddress(v) if v.len() == 6 => {
                    Some(MacAddr(v[0], v[1], v[2], v[3], v[4], v[5]))
                }
                _ => None,
            })
            .ok_or(format!("found neighbor for {interface:?} but no MAC address: {msg:?}").into());
    }

    Err(format!("unable to find neighbor MAC address for interface {interface:?}").into())
}

#[derive(Parser, Debug)]
#[command(author, version)]
struct Cli {
    targets: String,

    #[arg(default_value_t = 5000, long)]
    icmp_timeout: u64,

    #[arg(short, long)]
    interface: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Target {
    addr: Ipv4Addr,
    count: u16,
    interval: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();
    let mut rdr = ReaderBuilder::new()
        .has_headers(false)
        .delimiter(b',')
        .terminator(Terminator::Any(b';'))
        .from_reader(cli.targets.as_bytes());
    let mut targets: Vec<Target> = Vec::new();
    for result in rdr.deserialize() {
        let t: Target = result?;
        if t.interval < 1 {
            return Err(format!(
                "error in target {}: interval must be between 1 and 1000 (ms)",
                t.addr
            )
            .into());
        }
        if t.interval > 1000 {
            return Err(format!(
                "error in target {}: interval must be between 1 and 1000 (ms)",
                t.addr
            )
            .into());
        }
        if t.count < 1 {
            return Err(
                format!("error in target {}: count must be between 1 and 10", t.addr).into(),
            );
        }
        if t.count > 10 {
            return Err(
                format!("error in target {}: count must be between 1 and 10", t.addr).into(),
            );
        }
        targets.push(t);
    }

    let ethernet_conf = if let Some(interface_name) = cli.interface {
        EthernetConf::new(interface_name).await?
    } else {
        EthernetConf::any().await?
    };

    log::debug!("ethernet config: {:?}", ethernet_conf);

    let icmp_timeout = Duration::from_millis(cli.icmp_timeout);

    let queue_size = 100usize;
    let pinger = Arc::new(Pinger::new(ethernet_conf, queue_size, icmp_timeout)?);

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
