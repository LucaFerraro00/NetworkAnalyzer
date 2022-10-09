mod args;

use std::env;
use args::InputArgs;
use clap::Parser;
use pcap::Device;



fn main() {

/*
    //Check enovirement variables
    for (n,v) in env::vars() {
        println!("{}: {}", n,v);
    }*/

    println!("Welcome to packet sniffer!");
    println!("---------------------------------");

    let arguments = InputArgs::parse();
    let list = Device::list().unwrap();
    let mut open_file = mylib::create_file(arguments.fileName);

    match arguments.show {
        true => { mylib::print_all_devices(list.clone())}
        false => { () }
    }

    let mut selected_code = arguments.device_number;

    let mut available = mylib::check_device_available( selected_code as i32,list.clone());
    while !available {
        println!("The selected network adapter is not available!");
        println!("The available network adapter are: ");
        mylib::print_all_devices(list.clone());
        selected_code = mylib::select_device().parse::<usize>().unwrap();
        available = mylib::check_device_available( selected_code as i32, list.clone());
    }
    let selected_device = list[selected_code -1].clone();
    println!("The details of the selected device are: ");
    println!("{:?}", selected_device);
    mylib::capture_packet(selected_device);

}
