mod args;

use std::{env, thread};
use args::InputArgs;
use clap::Parser;
use pcap::Device;



fn main() {


    println!("Welcome to packet sniffer!");
    println!("---------------------------------");

    let mut arguments = InputArgs::parse();

    /*nel thread principale ci deve essere una sorta di loop che aggiorna i parametri presi dal terminale
      per mettere in pausa o rifar partire lo sniffing.*/


    let th1 = thread::spawn(move||{
        let list = Device::list().unwrap();
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
    });

    

    match th1.join() {
        //non serve a nulla, solo per controllare che sia tutto ok
        Ok(res) => { println!("ok join") },
        Err(err) => { println!("errore join") },
    }

}



/*
    let mut line = String::new();
    println!("Enter your command :");
    let b1 = std::io::stdin().read_line(&mut line).unwrap();
    println!("comando inserito: {:?}",line);*/
