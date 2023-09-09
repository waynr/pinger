use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use csv::{ReaderBuilder, Terminator};
use serde::Deserialize;
use socket2::SockAddr;
use tokio::task::JoinSet;

mod error;
mod ethernet;
mod prober;
mod probes;
mod socket;

use error::Result;
use ethernet::EthernetConf;
use prober::Prober;

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
    let prober = Arc::new(Prober::new(ethernet_conf, queue_size, icmp_timeout)?);

    let mut set = JoinSet::new();

    for target in targets.into_iter() {
        let p = prober.clone();
        set.spawn(async move {
            let mut set = JoinSet::new();

            let p = p.clone();
            let mut interval = tokio::time::interval(Duration::from_millis(target.interval));
            let addr: Box<SockAddr> = Box::new(SocketAddrV4::new(target.addr, 0).into());
            for i in 0..target.count {
                interval.tick().await;
                let a = addr.clone();
                let p = p.clone();
                set.spawn(async move { p.probe(&a, i).await });
            }

            while set.join_next().await.is_some() {}
        });
    }

    while set.join_next().await.is_some() {}

    Ok(())
}
