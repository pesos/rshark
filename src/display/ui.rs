use std::error::Error;
use std::io;
use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc, RwLock};

use super::events::{Event, Events};
use crate::network::{NetworkInfo, PacketInfo, PacketType};

use termion::{event::Key, raw::IntoRawMode};
use tui::{
    backend::TermionBackend,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Span, Spans},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Terminal,
};

#[allow(unused_imports)]
use pnet::packet::{
    arp::ArpPacket, icmp::IcmpPacket, icmpv6::Icmpv6Packet, tcp::TcpPacket, udp::UdpPacket,
};

/// Main function which renders UI on the terminal
pub fn draw_ui(
    net_info: Arc<RwLock<NetworkInfo>>,
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
            // Setting the layout of the UI
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints(
                    [
                        Constraint::Percentage(80),
                        Constraint::Percentage(15),
                        Constraint::Percentage(5),
                    ]
                    .as_ref(),
                )
                .split(f.size());

            // Header for packet capture view
            let header = Spans::from(Span::styled(
                get_packets_ui_header(),
                Style::default().fg(Color::Black).bg(Color::White),
            ));

            // Getting info about packets captured
            let items: Vec<ListItem> = net_info
                .read()
                .unwrap()
                .packets
                .iter()
                .enumerate()
                .map(|(current_num, p)| {
                    let ptype = get_packet_info(p, current_num + 1);
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

            // Rendering the packets that are captured
            f.render_stateful_widget(items, chunks[0], &mut packets_state);

            // Rendering logic for displaying packet information in the bottom window pane
            if let Some(i) = packets_state.selected() {
                if i < net_info.read().unwrap().packets.len() {
                    let items: Vec<ListItem> =
                        get_packet_description(&net_info.read().unwrap().packets[i])
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
                        .highlight_style(
                            Style::default().bg(Color::Red).add_modifier(Modifier::BOLD),
                        );

                    f.render_stateful_widget(items, chunks[1], &mut packets_info_state);
                }
            } else {
                let items = List::new(vec![])
                    .block(
                        Block::default()
                            .title("Packet Information")
                            .borders(Borders::ALL)
                            .style(Style::default().bg(Color::Black)),
                    )
                    .highlight_style(Style::default().bg(Color::Red).add_modifier(Modifier::BOLD));

                f.render_stateful_widget(items, chunks[1], &mut packets_info_state);
            }

            // Footer info rendering
            let footer = vec![Spans::from(vec![
                Span::raw(format!(
                    "Captured Packets: {} ",
                    net_info.read().unwrap().captured_packets
                )),
                Span::raw(format!(
                    "Dropped Packets: {} ",
                    net_info.read().unwrap().dropped_packets
                )),
            ])];

            let footer_para = Paragraph::new(footer)
                .block(Block::default())
                .style(Style::default().fg(Color::White).bg(Color::Black))
                .alignment(Alignment::Left);

            f.render_widget(footer_para, chunks[2]);
        })?;

        // Capture events from the keyboard
        match events.next()? {
            Event::Input(input) => match input {
                Key::Char('q') => {
                    terminal.clear()?;
                    running.store(false, Ordering::SeqCst);
                }
                Key::Left | Key::Esc => {
                    packets_state.select(None);
                }
                Key::Down | Key::Char('j') => {
                    if packets_state_selected {
                        let i = match packets_state.selected() {
                            Some(i) => {
                                if i >= net_info.read().unwrap().packets.len() {
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
                Key::Up | Key::Char('k') => {
                    if packets_state_selected {
                        let i = match packets_state.selected() {
                            Some(i) => {
                                if i == 0 {
                                    net_info.read().unwrap().packets.len().saturating_sub(1)
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
                                    packets_info_len.saturating_sub(1)
                                } else {
                                    i - 1
                                }
                            }
                            None => 0,
                        };
                        packets_info_state.select(Some(i));
                    }
                }
                Key::Char('g') => {
                    if packets_state_selected {
                        packets_state.select(Some(0));
                    } else {
                        packets_info_state.select(Some(0));
                    }
                }
                Key::Char('G') => {
                    if packets_state_selected {
                        packets_state.select(Some(
                            net_info.read().unwrap().packets.len().saturating_sub(1),
                        ));
                    } else {
                        packets_info_state.select(Some(packets_info_len.saturating_sub(1)));
                    }
                }
                Key::Char('\t') | Key::Char('J') => {
                    packets_state_selected = !packets_state_selected;
                }
                _ => {}
            },
            Event::Tick => {}
        }
    }

    Ok(())
}

/// Get header of packet capture UI
fn get_packets_ui_header() -> String {
    format!(
        "{:<10}    {:<40}    {:<40}    {:<10}    {:<6}    {:<20}",
        "Num", "Source", "Destination", "Protocol", "Length", "Info"
    )
}

/// Get brief packet info
fn get_packet_info(packet: &PacketInfo, current_num: usize) -> String {
    match packet.packet_type {
        PacketType::TCP => {
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
                    "{:<10}    {:<40}    {:<40}    {:<10}    {:<6}    {:<6} -> {:<6}",
                    current_num,
                    source_ip,
                    dest_ip,
                    "TCP",
                    payload.to_vec().len(),
                    tcp.get_source(),
                    tcp.get_destination()
                )
            } else {
                "TCP packet malformed".to_string()
            }
        }
        PacketType::UDP => {
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
                    "{:<10}    {:<40}    {:<40}    {:<10}    {:<6}    {:<6} -> {:<6}",
                    current_num,
                    source_ip,
                    dest_ip,
                    "UDP",
                    payload.to_vec().len(),
                    udp.get_source(),
                    udp.get_destination()
                )
            } else {
                "UDP packet malformed".to_string()
            }
        }
        PacketType::ARP => {
            let raw_packet = packet.packet_data.packet();
            let payload = packet.packet_data.payload();

            let arp = ArpPacket::new(raw_packet);

            if let Some(arp) = arp {
                format!(
                    "{:<10}    {:<40}    {:<40}    {:<10}    {:<6}    {:?}",
                    current_num,
                    arp.get_sender_hw_addr(),
                    arp.get_target_hw_addr(),
                    "ARP",
                    payload.to_vec().len(),
                    arp.get_operation()
                )
            } else {
                "ARP malformed".to_string()
            }
        }
        PacketType::ICMP => {
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

            // TODO: Improve print information based on ICMP Type
            if let Some(icmp) = icmp {
                format!(
                    "{:<10}    {:<40}    {:<40}    {:<10}    {:<6}    {:?}",
                    current_num,
                    source_ip,
                    dest_ip,
                    "ICMP",
                    payload.to_vec().len(),
                    icmp.get_icmp_code()
                )
            } else {
                "ICMP packet malformed".to_string()
            }
        }
        // TODO: Print information for ICMP
        PacketType::ICMPv6 => {
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

            let icmpv6 = Icmpv6Packet::new(raw_packet);

            // TODO: Improve print information based on ICMP Type
            if let Some(icmpv6) = icmpv6 {
                format!(
                    "{:<10}    {:<40}    {:<40}    {:<10}    {:<6}    {:?}",
                    current_num,
                    source_ip,
                    dest_ip,
                    "ICMPv6",
                    payload.to_vec().len(),
                    icmpv6.get_icmpv6_code()
                )
            } else {
                "ICMPv6 packet malformed".to_string()
            }
        }
    }
}

/// Get detailed packet description
fn get_packet_description(packet: &PacketInfo) -> Vec<String> {
    let mut pkt_desc: Vec<String> = vec![];

    match packet.packet_type {
        PacketType::TCP => {
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
        PacketType::UDP => {
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
        PacketType::ARP => {
            let raw_packet = packet.packet_data.packet();
            // let payload = packet.packet_data.payload();

            let arp = ArpPacket::new(raw_packet);
            if let Some(arp) = arp {
                pkt_desc.push(format!("Hardware Type: {:?}", arp.get_hardware_type()));
                pkt_desc.push(format!("Protocol Type: {:?}", arp.get_protocol_type()));
                // TODO: Elaborate on the ARP option
                pkt_desc.push(format!("Operation: {:?}", arp.get_operation()));
                pkt_desc.push(format!(
                    "Sender Hardware Address: {}",
                    arp.get_sender_hw_addr()
                ));
                pkt_desc.push(format!(
                    "Target Hardware Address: {}",
                    arp.get_target_hw_addr()
                ));
                pkt_desc.push(format!(
                    "Sender IP Address: {}",
                    arp.get_sender_proto_addr()
                ));
                pkt_desc.push(format!(
                    "Target IP Address: {}",
                    arp.get_target_proto_addr()
                ));
            }
        }
        PacketType::ICMP => {
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

            // TODO: Expand description based on ICMP type
            if let Some(icmp) = icmp {
                pkt_desc.push(format!("ICMP Type: {:?}", icmp.get_icmp_type()));
                pkt_desc.push(format!("ICMP Code: {:?}", icmp.get_icmp_code()));
            }
        }
        // TODO: Packet description for ICMPv6 packets
        PacketType::ICMPv6 => {
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

            let icmpv6 = Icmpv6Packet::new(raw_packet);

            // TODO: Expand description based on ICMP type
            if let Some(icmpv6) = icmpv6 {
                pkt_desc.push(format!("ICMPv6 Type: {:?}", icmpv6.get_icmpv6_type()));
                pkt_desc.push(format!("ICMPv6 Code: {:?}", icmpv6.get_icmpv6_code()));
            }
        }
    };

    pkt_desc
}
