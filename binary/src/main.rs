mod args;

use std::{env, thread};
use std::collections::HashMap;
use std::io::BufRead;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use args::InputArgs;
use clap::Parser;
use pcap::Device;
use indicatif::ProgressBar;


fn main() {


    println!("Welcome to packet sniffer!");
    println!("---------------------------------");
    println!("THE CAPTURE IS GOING ON....");
    println!("digit 'pause' to temporaly stop the sniffing");
    println!("digit 'resume' to resum the sniffing");
    println!("digit 'end' to finish the sniffing");


    let mut arguments = InputArgs::parse();

    let mut pause = Arc::new(Mutex::new(false));
    let mut pause_copy= pause.clone();
    let mut pause_copy2= pause.clone();
    let mut end = Arc::new(Mutex::new(false));
    let mut end_copy= end.clone();
    let mut end_copy2= end.clone();


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

        let mut now = SystemTime::now();
        let mut print_report = false;


        let mut map : HashMap<String, mylib::structures::CustomData> = HashMap::new();

        loop {
            let mut e = end_copy.clone();
            let mut p = pause_copy.clone();
            let selected_device = list[selected_code -1].clone();
            if *p.lock().unwrap()==false {
                let time_interval = Duration::from_secs(10);
                let mut diff = now.elapsed().unwrap();
                if diff > time_interval {
                    print_report=true;
                    now = SystemTime::now();
                }
                map = mylib::capture_packet(selected_device, print_report, map);
                print_report=false;
            }
            //println!("dentro loop thread secondario: end={}",*end.lock().unwrap());
            if *e.lock().unwrap() {break}
        }
    });

    let th2 = thread::spawn(move ||{
        loop {
            let mut e = end_copy2.clone();
            let mut p = pause_copy2.clone();
                let pb = ProgressBar::new(8);
                for _ in 0..8 {
                    if *e.lock().unwrap() {break}
                    if ! (*p.lock().unwrap()) {
                        pb.inc(1);
                        thread::sleep(Duration::from_secs(1));
                    }
                }
                pb.finish_and_clear();
                if *e.lock().unwrap() {break}
        }
    });

    loop {
        let mut end_copy= end.clone();
        let mut line = String::new();
        println!("Enter your command :");
        let mut std_lock = std::io::stdin();
        std_lock..read_line(&mut line).unwrap();
        //let b1 = std::io::stdin().read_line(&mut line).unwrap();
        if line.contains("end") {
            *end.lock().unwrap() = true;
            println!("goodbye");
        }
        if line.contains("pause") {
            *pause.lock().unwrap() = true;
            println!("CAPTURE IS WAITING FOR RESUMING");
        }
        if line.contains("resume") {
            *pause.lock().unwrap() = false;
            println!("CAPTURE IS GOING ON");
        }
        if *end_copy.lock().unwrap() {break}
    }


    match th1.join() {
        //non serve a nulla, solo per controllare che sia tutto ok
        Ok(res) => { println!("ok join thread sniff") },
        Err(err) => { println!("errore join") },
    }

    match th2.join() {
        //non serve a nulla, solo per controllare che sia tutto ok
        Ok(res) => { println!("ok join thread print") },
        Err(err) => { println!("errore print") },
    }


}



/*

let mut line = String::new();
println!("Enter your command :");
let b1 = std::io::stdin().read_line(&mut line).unwrap();
println!("comando inserito: {:?}",line);*/