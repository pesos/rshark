extern crate clap;
extern crate pnet;

mod display;
mod network;

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
                .short("i")
                .long("interface")
                .value_name("INTERFACE")
                .help("Sets network interface to capture packets on")
                .takes_value(true),
        )
        .get_matches();

    let iface_name = match matches.value_of("interface") {
        Some(iface_name) => iface_name.to_string(),
        None => {
            eprintln!("Network interface not provided");
            process::exit(1);
        }
    };

    // Check and get valid network interface
    let interface = match get_valid_interface(iface_name, interfaces()) {
        Some(interface) => interface,
        None => {
            eprintln!("Invalid network interface");
            process::exit(1);
        }
    };

    // Variable which is used to notify whether threads should be running
    let running = Arc::new(AtomicBool::new(true));

    // Maintains packets, num of captured packets and num of dropped packets
    let net_info = Arc::new(RwLock::new(NetworkInfo::new()));

    let network_net_info = Arc::clone(&net_info);
    let ui_net_info = Arc::clone(&net_info);

    let network_running = Arc::clone(&running);
    let display_running = Arc::clone(&running);

    let network_sniffer_thread = thread::spawn(|| {
        start_packet_sniffer(interface, network_net_info, network_running);
    });

    let display_thread = thread::spawn(|| {
        draw_ui(ui_net_info, display_running).expect("Error!");
    });

    let res_net = network_sniffer_thread.join();
    display_thread.join().unwrap();
    if res_net.is_err() {
        println!("Failed to start packet capture.");
        std::process::exit(0);
    }
}
