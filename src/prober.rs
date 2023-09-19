use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_channel::{Receiver as ACReceiver, Sender as ACSender};
use async_trait::async_trait;
use serde::Serialize;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::error::{Error, Result};
use crate::ethernet::EthernetConf;
use crate::socket::AsyncSocket;

/// Parametes describing a single `Probe` target.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TargetParams {
    pub addr: Ipv4Addr,
    pub seq: u16,
}

impl std::fmt::Display for TargetParams {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{},{}", self.addr, self.seq)
    }
}

pub enum ProbeReport<P: Probe> {
    ReceivedOutput(P::Output, Duration),
    TimedOut(TargetParams),
}

impl<P: Probe> std::fmt::Display for ProbeReport<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::ReceivedOutput(output, duration) => {
                write!(f, "{output},{}", duration.as_micros())
            }
            Self::TimedOut(targetparams) => write!(f, "{targetparams},TIMEDOUT"),
        }
    }
}

/// A probe managed by a `ProbeTask`. `Probe` implementations are largely responsible for
/// generating and optionally caching request packets.
#[async_trait]
pub trait Probe {
    // The output generated when the `Prober` successfully detects a response to the `Probe` for a
    // given `TargetParams`.
    type Output: Send + Serialize + std::fmt::Debug + std::fmt::Display;

    /// Send request using the given `AsyncSocket` with the given `TargetParams`.
    async fn send(&mut self, socket: AsyncSocket, params: &TargetParams) -> Result<()>;

    /// Validate whether the given packet buffer matches this Probe type. If so, return the
    /// detected TargetParams and Self::Output.
    fn validate_response(buf: &[u8]) -> Option<(TargetParams, Self::Output)>;

    /// Return an AsyncSocket configured for this specific type of probe. Defaults to a RAW IPV4
    /// socket that receives ICMPV4 packets.
    fn create_receiver(_e: &EthernetConf) -> Result<AsyncSocket> {
        create_receiver()
    }

    /// Return an AsyncSocket configured for this specific type of probe. Defaults to a RAW
    /// AF_PACKET socket bound to the interface specified in the `&EthernetConf`.
    fn create_sender(ec: &EthernetConf) -> Result<AsyncSocket> {
        create_sender(ec)
    }
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

    /// Receives targets from the target-generator task.
    target_receiver: ACReceiver<TargetParams>,

    /// Sends ProbeReports
    output_sender: UnboundedSender<ProbeReport<P>>,

    sender: AsyncSocket,
    listener: ProbeListener<P>,

    timeout: Duration,
}

impl<P: Probe + Send + Sync + 'static + std::fmt::Debug> ProbeTask<P> {
    /// Asynchronously run probe task end-to-end, including wait for reply.
    async fn probe(&mut self, tparams: &TargetParams) -> Result<()> {
        let probe_waiter_fut = {
            let (sender, receiver) = async_channel::bounded(1);
            // create a probe response waiter task
            let probe_waiter_fut = tokio::spawn(async move {
                log::debug!("waiting for response to probe");
                receiver.recv().await
            });
            log::debug!("registering probe waiter with ProbeListener");
            self.listener
                .put_probe_sender(tparams.clone(), sender)
                .await;
            probe_waiter_fut
        };

        log::debug!("sending probe for {tparams}");
        self.probe.send(self.sender.clone(), tparams).await?;

        let start = Instant::now();

        // create a timer
        let output_sender = self.output_sender.clone();
        let probe_timeout = self.timeout.clone();
        let tparams = tparams.clone();
        let _fut = tokio::spawn(async move {
            let probe_report = match timeout(probe_timeout, probe_waiter_fut).await {
                // Elapsed timeout error
                Err(_elapsed) => {
                    log::debug!("timed out waiting for {tparams} probe reply");
                    ProbeReport::TimedOut(tparams.clone())
                }
                // JoinError for probe waiter task
                Ok(Err(e)) => {
                    if e.is_panic() {
                        log::debug!("probe waiter task panicked");
                    } else if e.is_cancelled() {
                        log::debug!("probe waiter task cancelled");
                    } else {
                        log::debug!("probe waiter task failed for unknown reason");
                    }
                    // not clear if returning a result here would be helpful
                    return;
                }
                // RecvError returned inside probe waiter task
                Ok(Ok(Err(e))) => {
                    log::debug!("probe waiter failed to receive output: {e}");
                    return;
                }
                // whew!
                Ok(Ok(Ok(o))) => {
                    let elapsed = start.elapsed();
                    ProbeReport::ReceivedOutput(o, elapsed)
                }
            };
            match output_sender.send(probe_report) {
                Ok(_) => (),
                Err(e) => {
                    log::debug!("shutting down ProbeTask after failing to send output: {e}");
                }
            };
        });

        Ok(())
    }

    /// Probe targets as they become avaailable on the channel
    async fn run(&mut self) -> Result<()> {
        loop {
            let target = match self.target_receiver.recv().await {
                Ok(t) => t,
                Err(e) => {
                    log::debug!("shutting down ProbeTask after failing to receive target: {e}");
                    break;
                }
            };
            log::debug!("received target {target}, attempting to send probe");
            match self.probe(&target).await {
                Ok(probe_report) => probe_report,
                Err(e) => {
                    log::debug!("probe of {target} failed: {e}");
                    continue;
                }
            }
        }
        log::debug!("ProbeTask finished running");
        Ok(())
    }
}

#[derive(Debug)]
struct ProbeListener<P: Probe> {
    waiting_probes: Arc<Mutex<HashMap<TargetParams, ACSender<P::Output>>>>,
    socket: AsyncSocket,
}

impl<P: Probe> Clone for ProbeListener<P> {
    fn clone(&self) -> Self {
        Self {
            waiting_probes: self.waiting_probes.clone(),
            socket: self.socket.clone(),
        }
    }
}

impl<P: Probe> ProbeListener<P> {
    async fn listen_forever(mut self) {
        loop {
            let mut buf: Vec<u8> = Vec::with_capacity(4096);
            if let Err(e) = self.recv(&mut buf).await {
                log::debug!("ProbeListener receive failed: {e}");
            }
            if let Err(e) = self.handle_packet(&buf).await {
                log::debug!("ProbeListener failed to handle packet: {e}");
            }
        }
    }

    async fn handle_packet(&mut self, buf: &[u8]) -> Result<()> {
        log::debug!("received packet, checking for match with waiting probe");
        if let Some((tparams, output)) = P::validate_response(buf) {
            if let Some(sender) = self.get_probe_sender(&tparams).await {
                if let Err(e) = sender.send(output).await {
                    log::debug!(
                        "failed to send output for {tparams:?} to handler, channel closed: {e}"
                    );
                    return Err(Error::OutputHandlerChannelClosed);
                }
            } else {
                log::debug!("unable to match a detected packet to a probe waiter");
            }
        }

        Ok(())
    }

    async fn put_probe_sender(&self, tparams: TargetParams, sender: ACSender<P::Output>) {
        let mut g = self.waiting_probes.lock().await;
        if let Some(_s) = g.insert(tparams.clone(), sender) {
            log::error!("{tparams:?} already present in waiting probes");
        }
    }

    async fn get_probe_sender(&self, tparams: &TargetParams) -> Option<ACSender<P::Output>> {
        let mut g = self.waiting_probes.lock().await;
        g.remove(tparams)
    }

    async fn recv(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        let mut uninit = buf.spare_capacity_mut();
        match self.socket.recv(&mut uninit).await {
            Err(e) => {
                panic!("unhandled socket read error: {}", e);
            }
            Ok(len) => {
                log::trace!("received {} bytes for packet", len);
                // this is safe because we have the exact number of bytes written into the
                // MaybeUninit buf
                unsafe {
                    buf.set_len(len);
                }
                Ok(len)
            }
        }
    }
}

/// Generic framework for asynchronously conducting network scans. A ring buffer of Probes that
/// makes concurrent network probes easy.
#[derive(Clone)]
pub struct Prober<P: Probe + Send + Sync + 'static + std::fmt::Debug> {
    target_receiver: ACReceiver<TargetParams>,
    output_sender: UnboundedSender<ProbeReport<P>>,
}

impl<P: Probe + Send + Sync + 'static + std::fmt::Debug> Prober<P> {
    pub fn new() -> Result<(
        Self,
        ACSender<TargetParams>,
        UnboundedReceiver<ProbeReport<P>>,
    )> {
        let (output_sender, output_receiver) = unbounded_channel();
        let (target_sender, target_receiver) = async_channel::unbounded();

        Ok((
            Self {
                target_receiver,
                output_sender,
            },
            target_sender,
            output_receiver,
        ))
    }

    pub async fn run_probes(
        self,
        mut probes: Vec<P>,
        ethernet_conf: EthernetConf,
        timeout: Duration,
    ) -> Result<()> {
        let sender_socket = P::create_sender(&ethernet_conf)?;
        let mut join_set = JoinSet::new();

        let probe_listener = ProbeListener::<P> {
            waiting_probes: Arc::new(Mutex::new(HashMap::new())),
            socket: P::create_receiver(&ethernet_conf)?,
        };

        for probe in probes.drain(0..) {
            let mut probe_task = ProbeTask {
                probe,
                sender: sender_socket.clone(),
                listener: probe_listener.clone(),
                timeout: timeout.clone(),
                output_sender: self.output_sender.clone(),
                target_receiver: self.target_receiver.clone(),
            };
            join_set.spawn(async move {
                match probe_task.run().await {
                    Ok(_) => (),
                    Err(e) => {
                        log::error!("ProbeTask unexpectedly failed: {e:?}");
                    }
                }
            });
        }

        let cancel = CancellationToken::new();
        let cloned_cancel = cancel.clone();
        let listener_fut = tokio::spawn(async move {
            tokio::select! {
                _ = cloned_cancel.cancelled() => {},
                _ = probe_listener.listen_forever() => {},
            }
        });

        log::debug!("waiting for probe tasks to finish");
        while join_set.join_next().await.is_some() {}
        cancel.cancel();

        log::debug!("waiting for ProbeListener task to finish");
        listener_fut.await?;

        Ok(())
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
