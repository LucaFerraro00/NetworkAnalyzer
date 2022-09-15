mod libreria;

use crate::libreria::{print_all_devices, manage_parameters, progress_bar, select_device, check_device_available, capture_packet};
use std::env::args;


fn main() {
    let parameters = args();
    manage_parameters(parameters);

    println!("Welcome to packet sniffer!");
    println!("---------------------------------");
    println!("The available devices are:");
    let list = print_all_devices();
    let mut selected_code = select_device();
    let mut available = check_device_available( selected_code.parse::<i32>().unwrap(),list.clone());
    while !available {
        println!("The selected network adapter is not available!");
        println!("The available network adapter are: ");
        print_all_devices();
        selected_code = select_device();
        available = check_device_available( selected_code.parse::<i32>().unwrap(), list.clone());
    }
    let selected_device = list[selected_code.parse::<usize>().unwrap() -1].clone();
    println!("The details of the selected device are: ");
    println!("{:?}", selected_device);
    capture_packet(selected_device);
}
