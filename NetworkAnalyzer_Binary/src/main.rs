
use std::{thread};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use pcap::Device;
use network_analyzer_lib::{network_features, structures, argparse};

fn main() {

    let matched_arguments = argparse::initialize_cli_parser();
    let parameters = argparse::matches_arguments(matched_arguments);
    println!("{:?}",parameters);
    argparse::print_title();
    network_features::print_menu();

    let pause = Arc::new(Mutex::new(false));
    let pause_copy= pause.clone();
    let end = Arc::new(Mutex::new(false));
    let end_copy= end.clone();

    let th1 = thread::spawn(move||{

        let list = Device::list().unwrap();
        /*match parameters.show {
            true => { network_features::print_all_devices(list.clone())}
            false => { () }
        }*/
        let selected_code = parameters.nic_id;

        /*
        let mut available = network_features::check_device_available( selected_code as i32,list.clone());
        while !available {
            println!("The selected network adapter is not available!");
            println!("The available network adapter are: ");
            network_features::print_all_devices(list.clone());
            selected_code = network_features::select_device().parse::<u64>().unwrap();
            available = network_features::check_device_available( selected_code as i32, list.clone());
        }*/

        let mut now = SystemTime::now();
        let mut print_report = false;
        let mut map : HashMap<structures::CustomKey, structures::CustomData> = HashMap::new();
        loop {
            let e = end_copy.clone();
            let p = pause_copy.clone();
            let selected_device = list[(selected_code as usize) -1].clone();
            if *p.lock().unwrap()==false {
                let interval = Duration::from_secs(parameters.time_interval);
                let diff = now.elapsed().unwrap();
                if diff > interval {
                    print_report=true;
                    now = SystemTime::now();
                }
                map = network_features::capture_packet(selected_device, &parameters, print_report,  map);
                print_report=false;
            }
            //println!("dentro loop thread secondario: end={}",*end.lock().unwrap());
            if *e.lock().unwrap() {break}
        }
    });

    /*THREAD PER LA STAMPA DI UNA BARA COME FEEDBACK PER INDICARE CHE LA CATTURA E' IN CORSO
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
    });*/

    loop {
        let end_copy= end.clone();
        let mut line = String::new();
        println!("Enter your command :");
        let std_lock = std::io::stdin();
        std_lock.read_line(&mut line).unwrap();
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
        Ok(_) => { println!("Capture ended") },
        Err(err) => { println!("{:?}",err) },
    }

}
