use std::net::Ipv4Addr;

use futures::stream::TryStreamExt;
use netlink_packet_route::rtnl::{address, constants as nlconsts, link, neighbour};
use netlink_packet_route::LinkMessage;
use pnet::packet:: ethernet::{EtherTypes, Ethernet};
use pnet::util::MacAddr;
use rtnetlink::{new_connection, Handle, IpVersion};

use crate::error::{Error, Result};

/// Information about the interface on which we will emit packets and listen for responses.
#[derive(Debug)]
pub struct InterfaceInfo {
    name: String,
    pub index: u32,
    //address: [u8; 4],
    pub address: Ipv4Addr,
    mac_addr: MacAddr,
}

impl TryFrom<LinkMessage> for InterfaceInfo {
    type Error = Error;

    fn try_from(lm: LinkMessage) -> Result<InterfaceInfo> {
        let index = lm.header.index;

        let name = lm
            .nlas
            .iter()
            .find_map(|nla| match nla {
                link::nlas::Nla::IfName(name) => Some(name.clone()),
                _ => None,
            })
            .ok_or(Error::GenericStringError(format!(
                "couldn't find interface name for {index}"
            )))?;

        let mac_addr = lm
            .nlas
            .iter()
            .find_map(|nla| match nla {
                link::nlas::Nla::PermAddress(v) if v.len() == 6 => {
                    Some(MacAddr(v[0], v[1], v[2], v[3], v[4], v[5]))
                }
                _ => None,
            })
            .ok_or(Error::GenericStringError(format!(
                "couldn't find MAC address for interface {name} (idx: {index})"
            )))?;

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

        let notfounderr = Error::GenericStringError(format!(
            "unable to retrieve address for interface {} (idx {})",
            self.name, self.index
        ));

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
                .ok_or(notfounderr)?;
            return Ok(());
        }

        Err(notfounderr)
    }
}

/// Contains information retrieved from the local network stack necessary to construct Ethernet
/// packets.
#[derive(Debug)]
pub struct EthernetConf {
    pub ethernet_info: Ethernet,
    pub interface: InterfaceInfo,
}

impl EthernetConf {
    /// Prepare a EthernetConf for the specified interface name.
    pub async fn new(interface_name: String) -> Result<Self> {
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
    pub async fn any() -> Result<Self> {
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
    Err(Error::GenericStringError(format!(
        "couldn't find suitable default route"
    )))
}

async fn get_interface_by_index(handle: Handle, interface_index: u32) -> Result<InterfaceInfo> {
    let mut links = handle.link().get().match_index(interface_index).execute();

    let mut ii = if let Some(link) = links.try_next().await? {
        let ii: InterfaceInfo = link.try_into()?;
        log::debug!("found interface {0}: {ii:?}", ii.name);
        ii
    } else {
        return Err(Error::GenericStringError(format!(
            "couldn't find netlink info for interface {interface_index}"
        )));
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
        return Err(Error::GenericStringError(format!(
            "couldn't find netlink info for {interface_name}"
        )));
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
            .ok_or(Error::GenericStringError(format!(
                "found neighbor for {interface:?} but no MAC address: {msg:?}"
            )));
    }

    Err(Error::GenericStringError(format!(
        "unable to find neighbor MAC address for interface {interface:?}"
    )))
}
