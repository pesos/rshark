extern crate clap;
extern crate pnet;

mod display;
mod network;

use std::io::{self, Write};
use std::process;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};
use std::thread;

use display::draw_ui;
use network::{get_valid_interface, start_packet_sniffer, NetworkInfo};

use clap::{App, Arg};
use pnet::datalink::interfaces;

fn main() {
    let matches = App::new("rshark")
        .version("0.1.0")
        .author("Prithvi MK <prithvikrishna49@gmail.com>")
        .about("Terminal UI based simple packet monitoring tool")
        .arg(
            Arg::with_name("interface")
                .short('i')
                .long("interface")
                .value_name("INTERFACE")
                .about("Sets network interface to capture packets on")
                .takes_value(true),
        )
        .get_matches();

    let iface_name = match matches.value_of("interface") {
        Some(iface_name) => iface_name.to_string(),
        None => {
            writeln!(io::stderr(), "Network interface not provided").unwrap();
            process::exit(1);
        }
    };

    // Check and get valid network interface
    let interface = match get_valid_interface(iface_name, interfaces()) {
        Some(interface) => interface,
        None => {
            writeln!(io::stderr(), "Invalid network interface.").unwrap();
            process::exit(1);
        }
    };

    // Variable which is used to notify whether threads should be running
    let running = Arc::new(AtomicBool::new(true));

    // Maintains packets, num of captured packets and num of dropped packets
    let net_info = Arc::new(RwLock::new(NetworkInfo::new()));

    let network_net_info = net_info.clone();
    let ui_net_info = net_info.clone();

    let network_running = running.clone();
    let display_running = running.clone();

    let network_sniffer_thread = thread::spawn(|| {
        start_packet_sniffer(interface, network_net_info, network_running);
    });

    let display_thread = thread::spawn(|| {
        draw_ui(ui_net_info, display_running).expect("Error!");
    });

    network_sniffer_thread.join().unwrap();
    display_thread.join().unwrap();
}
