extern crate pnet;

mod events;
mod network;

use std::env;
use std::error::Error;
use std::io::{self, Write};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;

use crate::events::{Event, Events};
use network::{start_packet_sniffer, PacketInfo};

#[allow(unused_imports)]
use termion::{event::Key, input::MouseTerminal, raw::IntoRawMode, screen::AlternateScreen};
#[allow(unused_imports)]
use tui::{
    backend::TermionBackend,
    layout::{Constraint, Corner, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Span, Spans},
    widgets::{Block, Borders, List, ListItem, ListState},
    Terminal,
};

use pnet::packet::{
    arp::ArpPacket, icmp::IcmpPacket, icmpv6::Icmpv6Packet, tcp::TcpPacket, udp::UdpPacket,
};

fn main() {
    let iface_name = match env::args().nth(1) {
        Some(n) => n,
        None => {
            write!(io::stderr(), "USAGE: packetdump <NETWORK INTERFACE>").unwrap();
            process::exit(1);
        }
    };

    let running = Arc::new(AtomicBool::new(true));
    let packets = Arc::new(RwLock::new(Vec::<PacketInfo>::new()));

    let net_packets = packets.clone();
    let read_packets = packets.clone();

    let network_running = running.clone();

    let network_sniffer = thread::spawn(|| {
        start_packet_sniffer(iface_name, net_packets, network_running);
    });

    let ui_running = running.clone();

    let packets_len = thread::spawn(|| {
        draw_ui(read_packets, ui_running).expect("Error!");
    });

    network_sniffer.join().unwrap();
    packets_len.join().unwrap();
}

fn draw_ui(
    packets: Arc<RwLock<Vec<PacketInfo>>>,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn Error>> {
    let stdout = io::stdout().into_raw_mode()?;
    let backend = TermionBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let events = Events::new();

    let mut packets_state_selected = true;

    let mut packets_state = ListState::default();
    let mut packets_info_state = ListState::default();
    let mut packets_info_len: usize = 0;

    while running.load(Ordering::Relaxed) {
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(80), Constraint::Percentage(10)].as_ref())
                .split(f.size());

            let header = Spans::from(Span::styled(
                get_packets_ui_header(),
                Style::default().fg(Color::Black).bg(Color::White),
            ));

            let items: Vec<ListItem> = packets
                .read()
                .unwrap()
                .iter()
                .map(|i| {
                    let ptype = get_packet_info(i);
                    ListItem::new(Spans::from(ptype))
                        .style(Style::default().fg(Color::White).bg(Color::Black))
                })
                .collect();

            let items = List::new(items)
                .block(
                    Block::default()
                        .title(header)
                        .borders(Borders::ALL)
                        .style(Style::default().bg(Color::Black)),
                )
                .highlight_style(Style::default().bg(Color::Red).add_modifier(Modifier::BOLD));

            f.render_stateful_widget(items, chunks[0], &mut packets_state);

            if let Some(i) = packets_state.selected() {
                let items: Vec<ListItem> = get_packet_description(&packets.read().unwrap()[i])
                    .iter()
                    .map(|field| {
                        let field_val = field.to_string();
                        ListItem::new(Spans::from(field_val))
                            .style(Style::default().fg(Color::White).bg(Color::Black))
                    })
                    .collect();

                packets_info_len = items.len();

                let items = List::new(items)
                    .block(
                        Block::default()
                            .title("Packet Information")
                            .borders(Borders::ALL)
                            .style(Style::default().bg(Color::Black)),
                    )
                    .highlight_style(Style::default().bg(Color::Red).add_modifier(Modifier::BOLD));

                f.render_stateful_widget(items, chunks[1], &mut packets_info_state);
            }
        })?;

        match events.next()? {
            Event::Input(input) => match input {
                Key::Char('q') => {
                    terminal.clear()?;
                    running.store(false, Ordering::SeqCst);
                }
                Key::Left => {
                    packets_state.select(None);
                }
                Key::Down => {
                    if packets_state_selected {
                        let i = match packets_state.selected() {
                            Some(i) => {
                                if i >= packets.read().unwrap().len() {
                                    0
                                } else {
                                    i + 1
                                }
                            }
                            None => 0,
                        };
                        packets_state.select(Some(i));
                    } else {
                        let i = match packets_info_state.selected() {
                            Some(i) => {
                                if i >= packets_info_len {
                                    0
                                } else {
                                    i + 1
                                }
                            }
                            None => 0,
                        };
                        packets_info_state.select(Some(i));
                    }
                }
                Key::Up => {
                    if packets_state_selected {
                        let i = match packets_state.selected() {
                            Some(i) => {
                                if i == 0 {
                                    packets.read().unwrap().len() - 1
                                } else {
                                    i - 1
                                }
                            }
                            None => 0,
                        };
                        packets_state.select(Some(i));
                    } else {
                        let i = match packets_info_state.selected() {
                            Some(i) => {
                                if i == 0 {
                                    packets_info_len - 1
                                } else {
                                    i - 1
                                }
                            }
                            None => 0,
                        };
                        packets_info_state.select(Some(i));
                    }
                }
                Key::Char('\t') => {
                    packets_state_selected = !packets_state_selected;
                }
                _ => {}
            },
            Event::Tick => {}
        }
    }

    Ok(())
}

fn get_packets_ui_header() -> String {
    format!(
        "{:<20}    {:<20}    {:<10}    {:<6}    {:<20}",
        "Source", "Destination", "Protocol", "Length", "Info"
    )
}

fn get_packet_info(packet: &PacketInfo) -> String {
    match packet.packet_type {
        network::PacketType::TCP => {
            let raw_packet = packet.packet_data.packet();
            let payload = packet.packet_data.payload();

            let source_ip = if let Some(ip) = packet.source_ip {
                ip.to_string()
            } else {
                "NA".to_string()
            };

            let dest_ip = if let Some(ip) = packet.dest_ip {
                ip.to_string()
            } else {
                "NA".to_string()
            };

            let tcp = TcpPacket::new(raw_packet);
            if let Some(tcp) = tcp {
                format!(
                    "{:<20}    {:<20}    {:<10}    {:<6}    {:<6}->{:<6}",
                    source_ip,
                    dest_ip,
                    "TCP",
                    payload.to_vec().len(),
                    tcp.get_source(),
                    tcp.get_destination()
                )
            } else {
                format!("TCP packet malformed")
            }
        }
        network::PacketType::UDP => {
            let raw_packet = packet.packet_data.packet();
            let payload = packet.packet_data.payload();

            let source_ip = if let Some(ip) = packet.source_ip {
                ip.to_string()
            } else {
                "NA".to_string()
            };

            let dest_ip = if let Some(ip) = packet.dest_ip {
                ip.to_string()
            } else {
                "NA".to_string()
            };

            let udp = UdpPacket::new(raw_packet);
            if let Some(udp) = udp {
                format!(
                    "{:<20}    {:<20}    {:<10}    {:<6}    {:<6}->{:<6}",
                    source_ip,
                    dest_ip,
                    "UDP",
                    payload.to_vec().len(),
                    udp.get_source(),
                    udp.get_destination()
                )
            } else {
                format!("UDP packet malformed")
            }
        }
        network::PacketType::ARP => {
            let raw_packet = packet.packet_data.packet();
            let payload = packet.packet_data.payload();

            let arp = ArpPacket::new(raw_packet);

            if let Some(arp) = arp {
                format!(
                    "{:<20}    {:<20}    {:<10}    {:<6}    {:?}",
                    arp.get_sender_hw_addr(),
                    arp.get_target_hw_addr(),
                    "ARP",
                    payload.to_vec().len(),
                    arp.get_operation()
                )
            } else {
                format!("ARP malformed")
            }
        }
        network::PacketType::ICMP => {
            let raw_packet = packet.packet_data.packet();
            let payload = packet.packet_data.payload();

            let source_ip = if let Some(ip) = packet.source_ip {
                ip.to_string()
            } else {
                "NA".to_string()
            };

            let dest_ip = if let Some(ip) = packet.dest_ip {
                ip.to_string()
            } else {
                "NA".to_string()
            };

            let icmp = IcmpPacket::new(raw_packet);

            // TODO: Improve print information
            if let Some(icmp) = icmp {
                format!(
                    "{:<20}    {:<20}    {:<10}    {:<6}    {:?}",
                    source_ip,
                    dest_ip,
                    "ICMP",
                    payload.to_vec().len(),
                    icmp.get_icmp_code()
                )
            } else {
                format!("ICMP packet malformed")
            }
        }
        // TODO: Print information for ICMP
        network::PacketType::ICMPv6 => format!("ICMPv6"),
    }
}

fn get_packet_description(packet: &PacketInfo) -> Vec<String> {
    let mut pkt_desc: Vec<String> = vec![];

    match packet.packet_type {
        network::PacketType::TCP => {
            let raw_packet = packet.packet_data.packet();
            // let payload = packet.packet_data.payload().to_ascii_lowercase();

            if let Some(ip) = packet.source_ip {
                pkt_desc.push(format!("Source IP: {}", ip.to_string()));
            } else {
                pkt_desc.push(format!("Source IP: {}", "NA".to_string()));
            }

            if let Some(ip) = packet.dest_ip {
                pkt_desc.push(format!("Destination IP: {}", ip.to_string()));
            } else {
                pkt_desc.push(format!("Destination IP: {}", "NA".to_string()));
            }

            let tcp = TcpPacket::new(raw_packet);
            if let Some(tcp) = tcp {
                pkt_desc.push(format!("Source Port: {}", tcp.get_source()));
                pkt_desc.push(format!("Destination Port: {}", tcp.get_destination()));
                pkt_desc.push(format!("Sequence Number: {}", tcp.get_sequence()));
                pkt_desc.push(format!(
                    "Acknowledgement Number: {}",
                    tcp.get_acknowledgement()
                ));
                pkt_desc.push(format!("Flags: {:b}", tcp.get_flags()));
                pkt_desc.push(format!("Window: {}", tcp.get_window()));
            }
        }
        network::PacketType::UDP => {
            let raw_packet = packet.packet_data.packet();
            // let payload = packet.packet_data.payload();

            if let Some(ip) = packet.source_ip {
                pkt_desc.push(format!("Source IP: {}", ip.to_string()));
            } else {
                pkt_desc.push(format!("Source IP: {}", "NA".to_string()));
            }

            if let Some(ip) = packet.dest_ip {
                pkt_desc.push(format!("Destination IP: {}", ip.to_string()));
            } else {
                pkt_desc.push(format!("Destination IP: {}", "NA".to_string()));
            }

            let udp = UdpPacket::new(raw_packet);
            if let Some(udp) = udp {
                pkt_desc.push(format!("Source Port: {}", udp.get_source()));
                pkt_desc.push(format!("Destination Port: {}", udp.get_destination()));
            }
        }
        network::PacketType::ARP => {
            let raw_packet = packet.packet_data.packet();
            // let payload = packet.packet_data.payload();

            let arp = ArpPacket::new(raw_packet);
            if let Some(arp) = arp {
                pkt_desc.push(format!("Hardware Type: {:?}", arp.get_hardware_type()));
                pkt_desc.push(format!("Protocol Type: {:?}", arp.get_protocol_type()));
                // TODO: Elaborate on the ARP option
                pkt_desc.push(format!("Operation: {:?}", arp.get_operation()));
                pkt_desc.push(format!("Sender Hardware Address: {}", arp.get_sender_hw_addr()));
                pkt_desc.push(format!("Target Hardware Address: {}", arp.get_target_hw_addr()));
                pkt_desc.push(format!("Sender IP Address: {}", arp.get_sender_proto_addr()));
                pkt_desc.push(format!("Target IP Address: {}", arp.get_target_proto_addr()));
            }
        }
        network::PacketType::ICMP => {
            let raw_packet = packet.packet_data.packet();
            // let payload = packet.packet_data.payload();

            if let Some(ip) = packet.source_ip {
                pkt_desc.push(format!("Source IP: {}", ip.to_string()));
            } else {
                pkt_desc.push(format!("Source IP: {}", "NA".to_string()));
            }

            if let Some(ip) = packet.dest_ip {
                pkt_desc.push(format!("Destination IP: {}", ip.to_string()));
            } else {
                pkt_desc.push(format!("Destination IP: {}", "NA".to_string()));
            }

            let icmp = IcmpPacket::new(raw_packet);

            if let Some(icmp) = icmp {
                pkt_desc.push(format!("ICMP Type: {:?}", icmp.get_icmp_type()));
                pkt_desc.push(format!("ICMP Code: {:?}", icmp.get_icmp_code()));
            }
        }
        // TODO: Packet description for ICMPv6 packets
        network::PacketType::ICMPv6 => pkt_desc.push("None".to_string()),
    };

    pkt_desc
}
