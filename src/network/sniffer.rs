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

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

#[derive(Clone, Copy, Debug)]
pub enum PacketType {
    TCP,
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
        let udp_packet_info = PacketInfo::new(
            PacketType::UDP,
            Some(source),
            Some(destination),
            Box::new(udp),
        );
        packets.write().unwrap().push(udp_packet_info);
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
        let icmpv6_packet_info = PacketInfo::new(
            PacketType::ICMPv6,
            Some(source),
            Some(destination),
            Box::new(icmpv6_packet),
        );
        packets.write().unwrap().push(icmpv6_packet_info);
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
        let tcp_packet_info = PacketInfo::new(
            PacketType::TCP,
            Some(source),
            Some(destination),
            Box::new(tcp),
        );
        packets.write().unwrap().push(tcp_packet_info);
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
    _interface_name: &str,
    ethernet: &EthernetPacket,
    packets: &Arc<RwLock<Vec<PacketInfo>>>,
) {
    let header = ArpPacket::owned(ethernet.payload().to_vec());
    if let Some(header) = header {
        let arp_packet_info = PacketInfo::new(PacketType::ARP, None, None, Box::new(header));
        packets.write().unwrap().push(arp_packet_info);
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

pub fn get_valid_interface(
    iface_name: String,
    interfaces: Vec<NetworkInterface>,
) -> Option<NetworkInterface> {
    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;
    let interface = interfaces.into_iter().filter(interface_names_match).next();

    interface
}

pub fn start_packet_sniffer(
    interface: NetworkInterface,
    packets: Arc<RwLock<Vec<PacketInfo>>>,
    running: Arc<AtomicBool>,
) {
    use pnet::datalink::Channel::Ethernet;

    // Create a channel to receive on
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type: {}"),
        Err(e) => panic!("Unable to create channel: {}", e),
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
            Err(e) => panic!("Unable to receive packet: {}", e),
        }
    }
}
