use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use pnet::packet::{
    ethernet::MutableEthernetPacket,
    icmp::echo_reply::EchoReplyPacket,
    icmp::{echo_request::MutableEchoRequestPacket, IcmpCode, IcmpPacket, IcmpTypes},
    ip::IpNextHeaderProtocols,
    ipv4::{Ipv4Packet, MutableIpv4Packet},
    MutablePacket, Packet,
};
use serde::Serialize;
use socket2::SockAddr;
use tokio::time::timeout;

use crate::error::Result;
use crate::ethernet::EthernetConf;
use crate::prober::{Probe, TargetParams};
use crate::socket::AsyncSocket;

const ETHERNET_PACKET_MIN_SIZE: usize = MutableEthernetPacket::minimum_packet_size();
const IPV4_PACKET_MIN_SIZE: usize = Ipv4Packet::minimum_packet_size();
const ICMP_REQUEST_PACKET_SIZE: usize = ETHERNET_PACKET_MIN_SIZE
    + IPV4_PACKET_MIN_SIZE
    + MutableEchoRequestPacket::minimum_packet_size();
const ICMP_REPLY_PACKET_SIZE: usize = EchoReplyPacket::minimum_packet_size();

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
pub struct IcmpProbe {
    sender: AsyncSocket,
    receiver: AsyncSocket,
    icmp_timeout: Duration,
    buf: [u8; ICMP_REQUEST_PACKET_SIZE],
}

impl IcmpProbe {
    pub fn new(
        sender: AsyncSocket,
        receiver: AsyncSocket,
        ethernet_conf: &EthernetConf,
        icmp_timeout: Duration,
    ) -> Result<Self> {
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
            sender,
            receiver,
            buf,
            icmp_timeout,
        })
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

    pub async fn ping(&mut self, addr: &SockAddr, seq: u16) {
        let ip = addr.as_socket_ipv4().unwrap().ip().clone();
        self.update_icmp_request_packet(&ip, seq);
        let receiver = self.receiver.clone();
        let recv_echo_reply_fut = tokio::spawn(Self::recv_echo_reply(receiver, ip.clone(), seq));
        self.send_echo_request(seq).await;

        let start = Instant::now();
        let icmp_timeout = self.icmp_timeout.clone();
        match timeout(icmp_timeout, recv_echo_reply_fut).await {
            Err(_elapsed) => println!("{},{},TIMEDOUT", ip, seq),
            Ok(_) => {
                let elapsed = start.elapsed();
                println!("{},{},{}", ip, seq, elapsed.as_micros());
            }
        }
    }

    async fn send_echo_request(&self, seq: u16) {
        log::trace!("about to try sending via async io");
        match self.sender.send(&self.buf).await {
            Err(e) => {
                panic!("unhandled socket send error: {}", e);
            }
            Ok(length) => {
                log::trace!("sent {} bytes for request {}", length, seq);
            }
        }
    }

    async fn recv_echo_reply(receiver: AsyncSocket, ipv4addr: Ipv4Addr, seq: u16) {
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
        loop {
            let mut reply_slice = [MaybeUninit::<u8>::uninit(); ICMP_REPLY_PACKET_SIZE + 100];
            match receiver.recv(&mut reply_slice).await {
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

#[derive(Serialize)]
pub struct IcmpOutput {}

impl Probe for IcmpProbe {
    type Output = IcmpOutput;

    fn update_buffer(&mut self, tparams: &TargetParams) -> Result<()> {
        self.update_icmp_request_packet(&tparams.addr, tparams.seq);
        Ok(())
    }

    fn get_buffer(&self) -> &[u8] {
        &self.buf
    }

    fn validate_response(&self, buf: &[u8], tparams: &TargetParams) -> Option<Self::Output> {
        if is_expected_packet(buf, &tparams.addr, tparams.seq) {
            Some(IcmpOutput {})
        } else {
            None
        }
    }
}

/// Check that the given buffer is:
/// * from the expected source IP
/// * the right kind of IP packet (ICMP)
/// * the right kind of ICMP packet (Echo Reply)
/// * the expected sequence number
fn is_expected_packet(reply_buf: &[u8], addr: &Ipv4Addr, seq: u16) -> bool {
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
