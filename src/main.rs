mod libreria;
mod args;

use crate::libreria::{print_all_devices, select_device, check_device_available, capture_packet};
use args::InputArgs;
use clap::Parser;
use pcap::Device;

fn main() {

    println!("Welcome to packet sniffer!");
    println!("---------------------------------");

    let arguments = InputArgs::parse();
    let list = Device::list().unwrap();

    match arguments.show {
        true => { print_all_devices(list.clone())}
        false => { println!("non settato")}
    }

    let mut selected_code = arguments.device_number;

    let mut available = check_device_available( selected_code as i32,list.clone());
    while !available {
        println!("The selected network adapter is not available!");
        println!("The available network adapter are: ");
        print_all_devices(list.clone());
        selected_code = select_device().parse::<usize>().unwrap();
        available = check_device_available( selected_code as i32, list.clone());
    }
    let selected_device = list[selected_code -1].clone();
    println!("The details of the selected device are: ");
    println!("{:?}", selected_device);
    capture_packet(selected_device);
}
