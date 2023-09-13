use std::net::Ipv4Addr;
use std::time::Duration;

use clap::Parser;
use csv::{ReaderBuilder, Terminator};
use serde::Deserialize;

mod error;
mod ethernet;
mod prober;
mod probes;
mod socket;

use error::{Error, Result};
use ethernet::EthernetConf;
use prober::{Prober, TargetParams};
use probes::icmp::IcmpProbe;
use tokio::task::JoinSet;

#[derive(Parser, Debug)]
#[command(author, version)]
struct Cli {
    targets: String,

    #[arg(default_value_t = 5000, long)]
    icmp_timeout: u64,

    #[arg(short, long)]
    interface: Option<String>,

    #[arg(default_value_t = 5, short, long)]
    concurrent_probes: usize,
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
        let addr = t.addr;
        if t.interval < 1 {
            return Err(Error::GenericStringError(format!(
                "error in target {addr}: interval must be between 1 and 1000 (ms)",
            )));
        }
        if t.interval > 1000 {
            return Err(Error::GenericStringError(format!(
                "error in target {addr}: interval must be between 1 and 1000 (ms)",
            )));
        }
        if t.count < 1 {
            return Err(Error::GenericStringError(format!(
                "error in target {addr}: count must be between 1 and 10",
            )));
        }
        if t.count > 10 {
            return Err(Error::GenericStringError(format!(
                "error in target {addr}: count must be between 1 and 10",
            )));
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

    let probes = IcmpProbe::many(cli.concurrent_probes, &ethernet_conf)?;
    let (prober, target_sender, mut output_receiver) = Prober::new()?;

    let probe_tasks_fut =
        tokio::spawn(async move { prober.run_probes(probes, ethernet_conf, icmp_timeout).await });
    let output_handling_fut = tokio::spawn(async move {
        while let Some(output) = output_receiver.recv().await {
            println!("{output}");
        }
    });

    let mut set = JoinSet::new();

    for target in targets.into_iter() {
        let sender = target_sender.clone();
        set.spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(target.interval));
            for i in 0..target.count {
                interval.tick().await;
                let tparams = TargetParams {
                    addr: target.addr,
                    seq: i,
                };
                if let Err(e) = sender.send(tparams).await {
                    log::error!("error sending target to ProbeTasks: {e}");
                }
            }
        });
    }

    while set.join_next().await.is_some() {}

    log::debug!("closing target sender");
    target_sender.close();

    log::debug!("awaiting probe tasks finish");
    probe_tasks_fut.await??;

    log::debug!("awaiting output handling task finish");
    output_handling_fut.await?;

    Ok(())
}
