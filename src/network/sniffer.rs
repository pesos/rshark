use pnet::datalink::{self, NetworkInterface};
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
#[allow(unused_imports)]
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

#[derive(Clone, Copy, Debug)]
pub enum PacketType {
    TCP = 0,
    UDP,
    ICMP,
    ICMPv6,
    ARP,
}

pub struct PacketInfo {
    pub packet_type: PacketType,
    pub source_ip: Option<IpAddr>,
    pub dest_ip: Option<IpAddr>,
    pub packet_data: Box<dyn Packet + Send + Sync>,
}

impl PacketInfo {
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

#[allow(unused_variables)]
fn handle_udp_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    packets: &Arc<RwLock<Vec<PacketInfo>>>,
) {
    let udp = UdpPacket::owned(packet.to_vec());

    if let Some(udp) = udp {
        // println!(
        //     "[{}]: UDP Packet: {}:{} > {}:{}; length: {}",
        //     interface_name,
        //     source,
        //     udp.get_source(),
        //     destination,
        //     udp.get_destination(),
        //     udp.get_length()
        // );
        let temp = PacketInfo::new(
            PacketType::UDP,
            Some(source),
            Some(destination),
            Box::new(udp),
        );
        packets.write().unwrap().push(temp);
    } else {
        // println!("[{}]: Malformed UDP Packet", interface_name);
    }
}

#[allow(unused_variables)]
fn handle_icmp_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    packets: &Arc<RwLock<Vec<PacketInfo>>>,
) {
    let icmp_packet = IcmpPacket::owned(packet.to_vec());
    if let Some(icmp_packet) = icmp_packet {
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
        let temp = PacketInfo::new(
            PacketType::ICMP,
            Some(source),
            Some(destination),
            Box::new(icmp_packet),
        );
        packets.write().unwrap().push(temp);
    } else {
        // println!("[{}]: Malformed ICMP Packet", interface_name);
    }
}

#[allow(unused_variables)]
fn handle_icmpv6_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    packets: &Arc<RwLock<Vec<PacketInfo>>>,
) {
    let icmpv6_packet = Icmpv6Packet::owned(packet.to_vec());
    if let Some(icmpv6_packet) = icmpv6_packet {
        // println!(
        //     "[{}]: ICMPv6 packet {} -> {} (type={:?})",
        //     interface_name,
        //     source,
        //     destination,
        //     icmpv6_packet.get_icmpv6_type()
        // )
        let temp = PacketInfo::new(
            PacketType::ICMPv6,
            Some(source),
            Some(destination),
            Box::new(icmpv6_packet),
        );
        packets.write().unwrap().push(temp);
    } else {
        // println!("[{}]: Malformed ICMPv6 Packet", interface_name);
    }
}

#[allow(unused_variables)]
fn handle_tcp_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    packets: &Arc<RwLock<Vec<PacketInfo>>>,
) {
    let tcp = TcpPacket::owned(packet.to_vec());
    if let Some(tcp) = tcp {
        // println!(
        //     "[{}]: TCP Packet: {}:{} > {}:{}; length: {}",
        //     interface_name,
        //     source,
        //     tcp.get_source(),
        //     destination,
        //     tcp.get_destination(),
        //     packet.len()
        // );
        let temp = PacketInfo::new(
            PacketType::TCP,
            Some(source),
            Some(destination),
            Box::new(tcp),
        );
        packets.write().unwrap().push(temp);
    } else {
        // println!("[{}]: Malformed TCP Packet", interface_name);
    }
}

fn handle_transport_protocol(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
    packets: &Arc<RwLock<Vec<PacketInfo>>>,
) {
    match protocol {
        IpNextHeaderProtocols::Udp => {
            handle_udp_packet(interface_name, source, destination, packet, packets)
        }
        IpNextHeaderProtocols::Tcp => {
            handle_tcp_packet(interface_name, source, destination, packet, packets)
        }
        IpNextHeaderProtocols::Icmp => {
            handle_icmp_packet(interface_name, source, destination, packet, packets)
        }
        IpNextHeaderProtocols::Icmpv6 => {
            handle_icmpv6_packet(interface_name, source, destination, packet, packets)
        }
        _ => {}
    }
}

fn handle_ipv4_packet(
    interface_name: &str,
    ethernet: &EthernetPacket,
    packets: &Arc<RwLock<Vec<PacketInfo>>>,
) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
            packets,
        );
    } else {
        // println!("[{}]: Malformed IPv4 Packet", interface_name);
    }
}

fn handle_ipv6_packet(
    interface_name: &str,
    ethernet: &EthernetPacket,
    packets: &Arc<RwLock<Vec<PacketInfo>>>,
) {
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V6(header.get_source()),
            IpAddr::V6(header.get_destination()),
            header.get_next_header(),
            header.payload(),
            packets,
        );
    } else {
        // println!("[{}]: Malformed IPv6 Packet", interface_name);
    }
}

fn handle_arp_packet(
    interface_name: &str,
    ethernet: &EthernetPacket,
    packets: &Arc<RwLock<Vec<PacketInfo>>>,
) {
    let header = ArpPacket::owned(ethernet.payload().to_vec());
    if let Some(header) = header {
        // println!(
        //     "[{}]: ARP packet: {}({}) > {}({}); operation: {:?}",
        //     interface_name,
        //     ethernet.get_source(),
        //     header.get_sender_proto_addr(),
        //     ethernet.get_destination(),
        //     header.get_target_proto_addr(),
        //     header.get_operation()
        // );
        let temp = PacketInfo::new(PacketType::ARP, None, None, Box::new(header));
        packets.write().unwrap().push(temp);
    } else {
        // println!("[{}]: Malformed ARP Packet", interface_name);
    }
}

fn handle_ethernet_frame(
    interface: &NetworkInterface,
    ethernet: &EthernetPacket,
    packets: &Arc<RwLock<Vec<PacketInfo>>>,
) {
    let interface_name = &interface.name[..];
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(interface_name, ethernet, packets),
        EtherTypes::Ipv6 => handle_ipv6_packet(interface_name, ethernet, packets),
        EtherTypes::Arp => handle_arp_packet(interface_name, ethernet, packets),
        _ => {}
    }
}

pub fn start_packet_sniffer(
    iface_name: String,
    packets: Arc<RwLock<Vec<PacketInfo>>>,
    running: Arc<AtomicBool>,
) {
    use pnet::datalink::Channel::Ethernet;

    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap_or_else(|| panic!("No such network interface: {}", iface_name));

    // Create a channel to receive on
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packetdump: unhandled channel type: {}"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
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
                            handle_ethernet_frame(
                                &interface,
                                &fake_ethernet_frame.to_immutable(),
                                &packets,
                            );
                            continue;
                        } else if version == 6 {
                            fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_ethertype(EtherTypes::Ipv6);
                            fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                            handle_ethernet_frame(
                                &interface,
                                &fake_ethernet_frame.to_immutable(),
                                &packets,
                            );
                            continue;
                        }
                    }
                }
                handle_ethernet_frame(&interface, &EthernetPacket::new(packet).unwrap(), &packets);
            }
            Err(e) => panic!("packetdump: unable to receive packet: {}", e),
        }
    }
}
