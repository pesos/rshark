//! # Sniffer
//!
//! A module for sniffing/capturing packets over a given network interface.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use pnet::datalink::{self, NetworkInterface};
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;

/// Types of packets that are captured
#[derive(Clone, Copy, Debug)]
pub enum PacketType {
    TCP,
    UDP,
    ICMP,
    ICMPv6,
    ARP,
}

/// Stores various fields and data related to a packet,
/// depending on the type of the packet
pub struct PacketInfo {
    pub packet_type: PacketType,
    pub source_ip: Option<IpAddr>,
    pub dest_ip: Option<IpAddr>,
    pub packet_data: Box<dyn Packet + Send + Sync>,
}

/// Stores all captured packets and other statistics
pub struct NetworkInfo {
    pub packets: Vec<PacketInfo>,
    pub captured_packets: u64,
    pub dropped_packets: u64,
}

impl PacketInfo {
    /// Returns a data of a packet stored in a structure
    ///
    /// # Arguments
    ///
    /// * `packet_type` - Denotes the type of packet
    /// * `source_ip` - Source IP address
    /// * `dest_ip` - Destination IP address
    /// * `data` - Header and payload data of the packet
    fn new(
        packet_type: PacketType,
        source_ip: Option<IpAddr>,
        dest_ip: Option<IpAddr>,
        data: Box<dyn Packet + Send + Sync>,
    ) -> Self {
        let packet_data = data;
        PacketInfo {
            packet_type,
            source_ip,
            dest_ip,
            packet_data,
        }
    }
}

impl NetworkInfo {
    /// Creates and returns a new `NetworkInfo` structure
    pub fn new() -> Self {
        let packets: Vec<PacketInfo> = Vec::new();
        let captured_packets = 0u64;
        let dropped_packets = 0u64;

        NetworkInfo {
            packets,
            captured_packets,
            dropped_packets,
        }
    }
}

/// Function handler for UDP datagram
fn handle_udp_packet(
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    net_info: &Arc<RwLock<NetworkInfo>>,
) {
    let udp = UdpPacket::owned(packet.to_vec());

    if let Some(udp) = udp {
        let udp_packet_info = PacketInfo::new(
            PacketType::UDP,
            Some(source),
            Some(destination),
            Box::new(udp),
        );
        net_info.write().unwrap().packets.push(udp_packet_info);
        net_info.write().unwrap().captured_packets += 1;
    } else {
        net_info.write().unwrap().dropped_packets += 1;
    }
}

/// Function handler for ICMP packets
fn handle_icmp_packet(
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    net_info: &Arc<RwLock<NetworkInfo>>,
) {
    let icmp_packet = IcmpPacket::owned(packet.to_vec());
    if let Some(icmp_packet) = icmp_packet {
        // TODO: Print this information in the UI
        // match icmp_packet.get_icmp_type() {
        //     IcmpTypes::EchoReply => {
        //         let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
        //         println!(
        //             "[{}]: ICMP echo reply {} -> {} (seq={:?}, id={:?})",
        //             interface_name,
        //             source,
        //             destination,
        //             echo_reply_packet.get_sequence_number(),
        //             echo_reply_packet.get_identifier()
        //         );
        //     }
        //     IcmpTypes::EchoRequest => {
        //         let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
        //         println!(
        //             "[{}]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
        //             interface_name,
        //             source,
        //             destination,
        //             echo_request_packet.get_sequence_number(),
        //             echo_request_packet.get_identifier()
        //         );
        //     }
        //     _ => println!(
        //         "[{}]: ICMP packet {} -> {} (type={:?})",
        //         interface_name,
        //         source,
        //         destination,
        //         icmp_packet.get_icmp_type()
        //     ),
        // }
        let icmp_packet_info = PacketInfo::new(
            PacketType::ICMP,
            Some(source),
            Some(destination),
            Box::new(icmp_packet),
        );
        net_info.write().unwrap().packets.push(icmp_packet_info);
        net_info.write().unwrap().captured_packets += 1;
    } else {
        net_info.write().unwrap().dropped_packets += 1;
    }
}

/// Function handler for ICMPv6 packets
fn handle_icmpv6_packet(
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    net_info: &Arc<RwLock<NetworkInfo>>,
) {
    let icmpv6_packet = Icmpv6Packet::owned(packet.to_vec());
    if let Some(icmpv6_packet) = icmpv6_packet {
        let icmpv6_packet_info = PacketInfo::new(
            PacketType::ICMPv6,
            Some(source),
            Some(destination),
            Box::new(icmpv6_packet),
        );
        net_info.write().unwrap().packets.push(icmpv6_packet_info);
        net_info.write().unwrap().captured_packets += 1;
    } else {
        net_info.write().unwrap().dropped_packets += 1;
    }
}

/// Function handler for TCP segment
fn handle_tcp_packet(
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    net_info: &Arc<RwLock<NetworkInfo>>,
) {
    let tcp = TcpPacket::owned(packet.to_vec());
    if let Some(tcp) = tcp {
        let tcp_packet_info = PacketInfo::new(
            PacketType::TCP,
            Some(source),
            Some(destination),
            Box::new(tcp),
        );
        net_info.write().unwrap().packets.push(tcp_packet_info);
        net_info.write().unwrap().captured_packets += 1;
    } else {
        net_info.write().unwrap().dropped_packets += 1;
    }
}

/// Handles transport layer packets based on the protocol
fn handle_transport_protocol(
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
    net_info: &Arc<RwLock<NetworkInfo>>,
) {
    match protocol {
        IpNextHeaderProtocols::Udp => handle_udp_packet(source, destination, packet, net_info),
        IpNextHeaderProtocols::Tcp => handle_tcp_packet(source, destination, packet, net_info),
        IpNextHeaderProtocols::Icmp => handle_icmp_packet(source, destination, packet, net_info),
        IpNextHeaderProtocols::Icmpv6 => {
            handle_icmpv6_packet(source, destination, packet, net_info)
        }
        _ => {
            net_info.write().unwrap().dropped_packets += 1;
        }
    }
}

/// Handles IPv4 datagram
fn handle_ipv4_packet(ethernet: &EthernetPacket, net_info: &Arc<RwLock<NetworkInfo>>) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
            net_info,
        );
    } else {
        net_info.write().unwrap().dropped_packets += 1;
    }
}

/// Handles IPv6 datagram
fn handle_ipv6_packet(ethernet: &EthernetPacket, net_info: &Arc<RwLock<NetworkInfo>>) {
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            IpAddr::V6(header.get_source()),
            IpAddr::V6(header.get_destination()),
            header.get_next_header(),
            header.payload(),
            net_info,
        );
    } else {
        net_info.write().unwrap().dropped_packets += 1;
    }
}

/// Handles ARP packets
fn handle_arp_packet(ethernet: &EthernetPacket, net_info: &Arc<RwLock<NetworkInfo>>) {
    let header = ArpPacket::owned(ethernet.payload().to_vec());
    if let Some(header) = header {
        let arp_packet_info = PacketInfo::new(PacketType::ARP, None, None, Box::new(header));
        net_info.write().unwrap().packets.push(arp_packet_info);
        net_info.write().unwrap().captured_packets += 1;
    } else {
        net_info.write().unwrap().dropped_packets += 1;
    }
}

/// Handles ethernet frames
fn handle_ethernet_frame(ethernet: &EthernetPacket, net_info: &Arc<RwLock<NetworkInfo>>) {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(ethernet, net_info),
        EtherTypes::Ipv6 => handle_ipv6_packet(ethernet, net_info),
        EtherTypes::Arp => handle_arp_packet(ethernet, net_info),
        _ => {
            net_info.write().unwrap().dropped_packets += 1;
        }
    }
}

/// Check and return a valid network interface
pub fn get_valid_interface(
    iface_name: String,
    interfaces: Vec<NetworkInterface>,
) -> Option<NetworkInterface> {
    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;
    let interface = interfaces.into_iter().filter(interface_names_match).next();

    interface
}

/// Start capturing/sniffing packets on a valid network interface
pub fn start_packet_sniffer(
    interface: NetworkInterface,
    net_info: Arc<RwLock<NetworkInfo>>,
    running: Arc<AtomicBool>,
) {
    use pnet::datalink::Channel::Ethernet;

    // Create a channel to receive packets on
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type: {}"),
        Err(e) => {
            running.store(false, Ordering::SeqCst);
            panic!("Unable to create channel: {}", e)
        }
    };

    while running.load(Ordering::Relaxed) {
        let mut buf: [u8; 1600] = [0u8; 1600];
        let mut fake_ethernet_frame = MutableEthernetPacket::new(&mut buf[..]).unwrap();
        match rx.next() {
            Ok(packet) => {
                let payload_offset;
                if cfg!(any(target_os = "macos", target_os = "ios"))
                    && interface.is_up()
                    && !interface.is_broadcast()
                    && ((!interface.is_loopback() && interface.is_point_to_point())
                        || interface.is_loopback())
                {
                    if interface.is_loopback() {
                        // The pnet code for BPF loopback adds a zero'd out Ethernet header
                        payload_offset = 14;
                    } else {
                        // Maybe is TUN interface
                        payload_offset = 0;
                    }
                    if packet.len() > payload_offset {
                        let version = Ipv4Packet::new(&packet[payload_offset..])
                            .unwrap()
                            .get_version();
                        if version == 4 {
                            fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_ethertype(EtherTypes::Ipv4);
                            fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                            handle_ethernet_frame(&fake_ethernet_frame.to_immutable(), &net_info);
                            continue;
                        } else if version == 6 {
                            fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_ethertype(EtherTypes::Ipv6);
                            fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                            handle_ethernet_frame(&fake_ethernet_frame.to_immutable(), &net_info);
                            continue;
                        }
                    }
                }
                handle_ethernet_frame(&EthernetPacket::new(packet).unwrap(), &net_info);
            }
            Err(e) => panic!("Unable to receive packet: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_get_valid_interface() {
        let iface_name = "eth0".to_string();
        let mut interfaces: Vec<NetworkInterface> = vec![];

        let intf_eth0 = NetworkInterface {
            name: "eth0".to_string(),
            index: 0,
            mac: None,
            ips: vec![],
            flags: 0,
        };

        for i in 0..5 {
            let temp_intf = NetworkInterface {
                name: format!("eth{}", i),
                index: 0,
                mac: None,
                ips: vec![],
                flags: 0,
            };

            interfaces.push(temp_intf);
        }

        let valid_intf = get_valid_interface(iface_name, interfaces);

        assert_eq!(Some(intf_eth0), valid_intf);
    }

    #[test]
    fn test_get_valid_interface_fail() {
        let iface_name = "wlan0".to_string();
        let mut interfaces: Vec<NetworkInterface> = vec![];

        for i in 0..5 {
            let temp_intf = NetworkInterface {
                name: format!("eth{}", i),
                index: 0,
                mac: None,
                ips: vec![],
                flags: 0,
            };

            interfaces.push(temp_intf);
        }

        let valid_intf = get_valid_interface(iface_name, interfaces);

        assert_eq!(None, valid_intf);
    }

    #[test]
    fn test_handle_udp_packet_ipv4() {
        let source_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let dest_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let net_info = Arc::new(RwLock::new(NetworkInfo::new()));
        let test_net_info = net_info.clone();

        let byte_packet = [0u8; 200];

        handle_udp_packet(source_ip, dest_ip, &byte_packet, &net_info);

        let udp_packet = UdpPacket::new(&byte_packet).unwrap();

        assert_eq!(test_net_info.read().unwrap().packets.len(), 1usize);

        let res_packet_info = &test_net_info.read().unwrap().packets[0];

        assert_eq!(res_packet_info.source_ip.unwrap(), source_ip);
        assert_eq!(res_packet_info.dest_ip.unwrap(), dest_ip);

        let res_udp_packet = UdpPacket::new(res_packet_info.packet_data.packet()).unwrap();

        assert_eq!(udp_packet, res_udp_packet);
        assert_eq!(test_net_info.read().unwrap().captured_packets, 1u64);
    }

    #[test]
    fn test_handle_udp_packet_ipv4_fail() {
        let source_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let dest_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let net_info = Arc::new(RwLock::new(NetworkInfo::new()));
        let test_net_info = net_info.clone();

        // Minimum UDP packet size is 8 bytes(payload is 0)
        // So the packet must be dropped
        let byte_packet = [0u8; 7];

        handle_udp_packet(source_ip, dest_ip, &byte_packet, &net_info);

        assert_eq!(test_net_info.read().unwrap().packets.len(), 0);
        assert_eq!(test_net_info.read().unwrap().captured_packets, 0u64);
        assert_eq!(test_net_info.read().unwrap().dropped_packets, 1u64);
    }

    #[test]
    fn test_handle_tcp_packet_ipv4() {
        let source_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let dest_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let net_info = Arc::new(RwLock::new(NetworkInfo::new()));
        let test_net_info = net_info.clone();

        let byte_packet = [0u8; 200];

        handle_tcp_packet(source_ip, dest_ip, &byte_packet, &net_info);

        let tcp_packet = TcpPacket::new(&byte_packet).unwrap();

        assert_eq!(test_net_info.read().unwrap().packets.len(), 1usize);

        let res_packet_info = &test_net_info.read().unwrap().packets[0];

        assert_eq!(res_packet_info.source_ip.unwrap(), source_ip);
        assert_eq!(res_packet_info.dest_ip.unwrap(), dest_ip);

        let res_tcp_packet = TcpPacket::new(res_packet_info.packet_data.packet()).unwrap();

        assert_eq!(tcp_packet, res_tcp_packet);
        assert_eq!(test_net_info.read().unwrap().captured_packets, 1u64);
    }

    #[test]
    fn test_handle_tcp_packet_ipv4_fail() {
        let source_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let dest_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let net_info = Arc::new(RwLock::new(NetworkInfo::new()));
        let test_net_info = net_info.clone();

        // Minimum TCP packet size is 8 bytes(weird)
        // So the packet must be dropped
        let byte_packet = [0u8; 7];

        handle_udp_packet(source_ip, dest_ip, &byte_packet, &net_info);

        assert_eq!(test_net_info.read().unwrap().packets.len(), 0);
        assert_eq!(test_net_info.read().unwrap().captured_packets, 0u64);
        assert_eq!(test_net_info.read().unwrap().dropped_packets, 1u64);
    }
}
