use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use crossbeam::queue::ArrayQueue;
use serde::Serialize;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::time::timeout;

use crate::error::Result;
use crate::ethernet::EthernetConf;
use crate::socket::AsyncSocket;

/// Parametes describing a single `Probe` target.
#[derive(Clone)]
pub struct TargetParams {
    pub addr: Ipv4Addr,
    pub seq: u16,
}

impl std::fmt::Display for TargetParams {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?} ({})", self.addr, self.seq)
    }
}

/// A probe managed by a `ProbeTask`. `Probe` implementations are largely responsible for
/// generating and optionally caching request packets.
#[async_trait]
pub trait Probe {
    // The output generated when the `Prober` successfully detects a response to the `Probe` for a
    // given `TargetParams`.
    type Output: Send + Serialize;

    /// Send request using the given `AsyncSocket` with the given `TargetParams`.
    async fn send(&mut self, socket: AsyncSocket, params: &TargetParams) -> Result<()>;

    /// Return true if the given buffer matches the expectation for the given target parameters.
    // TODO: might be more efficient to use pcap or something else to filter packets
    fn validate_response(&self, buf: &[u8], params: &TargetParams) -> Option<Self::Output>;
}

/// ProbeTask holds general probe configuration and the sockets used to send request packets.
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
/// [1] https://zmap.io/paper.pdf
#[derive(Debug)]
struct ProbeTask<P: Probe + Send + Sync + 'static + std::fmt::Debug> {
    probe: P,
    sender: AsyncSocket,
    // TODO: there is a risk if a `ProbeTask` is idle for too long that the socket's kernel-side
    // receive buffer fills up with packets. this could lead to two problems: packet loss on the
    // kernel side and unnecessary cpu usage on the user side when draining the receiver.
    //
    // in the long term it's probably better to have one single receiving socket "owned" by the
    // `Prober` which distributes matching `Probe::Output` via oneshot channels to `ProbeTasks`
    // that registry filter closures when they begin listening for their specific packet
    //
    // in the short term (while convering `IcmpProbe` to this generic `Prober` framework) it's
    // probably fine to leave this as-is.
    receiver: AsyncSocket,
    timeout: Duration,
}

impl<P: Probe + Send + Sync + 'static + std::fmt::Debug> ProbeTask<P> {
    /// Asynchronously run probe task end-to-end, including wait for reply.
    async fn probe(&mut self, tparams: TargetParams) -> Result<P::Output> {
        self.probe
            .send(self.sender.clone(), &tparams)
            .await?;

        // it's safe-ish to have a gap between sending the request and receiving the packet here
        // because the receiver `AsyncSocket` is always listening for packets and the underlying
        // kernel packet buffer for this socket _should_ be large enough for the current toy use
        // case nature of this probing framework that we won't receive packets on it fast enough
        // that the one we are looking for gets dropped before we have a chance to receive it.
        //
        // as mentioned in comments on the receiver itself, we eventually want to refactor to use a
        // global receiving socket per `Prober` to enable high frequency scanning. this will likely
        // mean we need to spawn a separate task to wait for the reply prior to sending the request
        // to avoid races in low-latency scanning applications.
        let wait_for_reply_fut = self.wait_for_reply(&tparams);

        let start = Instant::now();
        let output = match timeout(self.timeout.clone(), wait_for_reply_fut).await {
            Err(_elapsed) => {
                println!("{},{},TIMEDOUT", tparams.addr, tparams.seq);
                return Err(format!("timed out waiting for {} probe reply", tparams).into());
            }
            Ok(o) => {
                let elapsed = start.elapsed();
                println!("{},{},{}", tparams.addr, tparams.seq, elapsed.as_micros());
                o
            }
        };
        Ok(output)
    }

    /// Send the Probe's ethernet packet on the sender AsyncSocket.
    async fn wait_for_reply(
        &self,
        tparams: &TargetParams,
    ) -> P::Output {
        loop {
            let mut buf: Vec<u8> = Vec::with_capacity(4096);
            let mut uninit = buf.spare_capacity_mut();
            match self.receiver.recv(&mut uninit).await {
                Err(e) => {
                    panic!("unhandled socket read error: {}", e);
                }
                Ok(len) => {
                    // this is safe because we have the exact number of bytes written into the
                    // uinit
                    unsafe {
                        buf.set_len(len);
                    }
                    log::trace!("received {} bytes for reply {}", len, tparams);
                    if let Some(output) = self.probe.validate_response(&buf, &tparams) {
                        return output;
                    }
                }
            }
        }
    }
}

/// Generic framework for asynchronously conducting network scans. A ring buffer of Probes that
/// makes concurrent network probes easy.
///
/// # Implementation Notes
///
/// (these notes were originally applicable to the non-generic icmp echo request implementation)
///
/// Rather than using a single socket shared across all packets, we want separate sockets to
/// simplify implementation of echo reply timeout on each echo request-reply pair. The idea
/// here being that in the course of each `ping` call each socket only accepts the reply packet
/// corresponding to the request it just sent and performs a tokio sleeps between non-blocking
/// `recv` attempts so that an outer tokio timeout future can cancel the inner future at the
/// specified icmp timeout.
///
/// One potential limitation here is going to be the number of concurrent pings that can run
/// since the number of `IcmpProbe` instances is limited using the ArrayQueue. One possibility
/// to address this would be to use crossbeam's `SegQueue`[1] type which is an unbounded data
/// structure with similar semantics. In this case we wouldn't even need to initialize the queue
/// here, we could create new `IcmpProbe`s whenever `SeqQueue.pop` returns None, then push the
/// new socket onto the queue when its first usage is finished. This would allow the queue to
/// grow to its natural size for a given set of input parameters (count, interval) and network
/// characteristics (round trip latency).
///
/// I'm going to stick with ArrayQueue for now because I don't think it's necessary to really
/// perfect the concurrency characteristics yet, it's just something I wanted to point out.
///
/// [1] https://docs.rs/crossbeam/latest/crossbeam/queue/struct.SegQueue.html
pub struct Prober<P: Probe + Send + Sync + 'static + std::fmt::Debug> {
    queue: ArrayQueue<Box<ProbeTask<P>>>,
}

impl<P: Probe + Send + Sync + 'static + std::fmt::Debug> Prober<P> {
    pub fn new(probes: Vec<P>, ethernet_conf: EthernetConf, timeout: Duration) -> Result<Self> {
        let sender = create_sender(&ethernet_conf)?;

        let queue = ArrayQueue::new(probes.len());
        for probe in probes {
            let receiver = create_receiver()?;
            let probe_task = ProbeTask {
                probe,
                sender: sender.clone(),
                receiver,
                timeout: timeout.clone(),
            };
            queue.push(Box::new(probe_task)).expect(
                "the queue should have the same capacity as the number of elements we are pushing",
            );
        }
        Ok(Self { queue })
    }

    // Execute async task to probe the given target.
    pub async fn probe(&self, tparams: TargetParams) -> Option<P::Output> {
        let mut task = loop {
            log::trace!("try retrieving probe task {}", tparams);
            match self.queue.pop() {
                Some(b) => break b,
                None => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        };

        let output = match task.probe(tparams.clone()).await {
            Ok(o) => Some(o),
            Err(e) => {
                eprintln!("{} failed: {:?}", tparams, e);
                None
            }
        };

        loop {
            log::trace!("try pushing task back onto queue");
            match self.queue.push(task) {
                Ok(_) => break,
                Err(b) => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    task = b;
                }
            }
        }
        output
    }
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
