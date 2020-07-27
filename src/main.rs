extern crate pnet;

mod display;
mod network;

use std::env;
use std::io::{self, Write};
use std::process;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};
use std::thread;

use display::draw_ui;
use network::{get_valid_interface, start_packet_sniffer, PacketInfo};

use pnet::datalink::interfaces;

fn main() {
    let iface_name = match env::args().nth(1) {
        Some(n) => n,
        None => {
            write!(io::stderr(), "USAGE: packetdump <NETWORK INTERFACE>").unwrap();
            process::exit(1);
        }
    };

    let interface = match get_valid_interface(iface_name, interfaces()) {
        Some(interface) => interface,
        None => {
            writeln!(io::stderr(), "Invalid network interface.").unwrap();
            process::exit(1);
        }
    };

    let running = Arc::new(AtomicBool::new(true));
    let packets = Arc::new(RwLock::new(Vec::<PacketInfo>::new()));

    let net_packets = packets.clone();
    let read_packets = packets.clone();

    let network_running = running.clone();

    let network_sniffer = thread::spawn(|| {
        start_packet_sniffer(interface, net_packets, network_running);
    });

    let ui_running = running.clone();

    let packets_len = thread::spawn(|| {
        draw_ui(read_packets, ui_running).expect("Error!");
    });

    network_sniffer.join().unwrap();
    packets_len.join().unwrap();
}
