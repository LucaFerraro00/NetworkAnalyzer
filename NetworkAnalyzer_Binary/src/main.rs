
use std::{thread};
use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use pcap::Device;
use network_analyzer_lib::{network_features, structures, argparse};
use colored::Colorize;

fn main() {

    let matched_arguments = argparse::initialize_cli_parser();
    let parameters = argparse::matches_arguments(matched_arguments);
    let parameters_cloned = parameters.clone();
    //check if device is available
    let device_list = Device::list().unwrap();
    let selected_code = match parameters.nic_id{
        num if num < 0 => {
            println!("{}", "ERROR: NicId cannot be negative".red());
            return;
        },
        num if num >= device_list.len() as isize =>{
            println!("{} \n\t{}", "ERROR: The index of the nicId is wrong".red(),
                     "Please check again the list of available devices running cargo run -- --list");
            //std::process::exit(-1);
            return;
        }  num => num as usize
    } as usize;
    argparse::print_title();
    let mut capturing = true;
    network_features::print_menu(parameters.clone(), capturing);

    let pause = Arc::new(Mutex::new(false));
    let pause_copy= pause.clone();
    let end = Arc::new(Mutex::new(false));
    let end_copy= end.clone();

    let _th1 = thread::spawn(move||{

        let mut now = SystemTime::now();
        let mut map : HashMap<structures::CustomKey, structures::CustomData> = HashMap::new();
        loop {
            let e = end_copy.clone();
            let p = pause_copy.clone();
            let selected_device = device_list[selected_code].clone();
            if *p.lock().unwrap()==false {
                let interval = Duration::from_secs(parameters.time_interval);
                let diff = now.elapsed().unwrap();
                if diff > interval {
                    println!("Print file {:?}", diff);
                    network_features::write_to_file(map.clone(), &parameters);
                    now = SystemTime::now();
                }
                match network_features::capture_packet(selected_device, &parameters,  map){
                   Ok(m) => {
                       map = m;
                   }
                    Err(e)=> {
                        println!("{}", "\n\n...\nERROR: pcap is not able to open the capture on the selected device!".red());
                        std::process::exit(0);
                    }
                }
            }
            //println!("dentro loop thread secondario: end={}",*end.lock().unwrap());
            if *e.lock().unwrap() {break}
        }
    });


    loop {
        let end_copy= end.clone();
        let mut line = String::new();
        println!("Enter your command :");
        print!(">_");
        std::io::stdout().flush().unwrap();
        let std_lock = std::io::stdin();
        std_lock.read_line(&mut line).unwrap();
        //let b1 = std::io::stdin().read_line(&mut line).unwrap();
        if line.contains("end") {
            *end.lock().unwrap() = true;
            println!("{}","\nGoodbye".bold().green());
        }
        if line.contains("pause") {
            *pause.lock().unwrap() = true;
            println!("{}","\nCAPTURE SNIFFING PAUSED..".bold().yellow());
            capturing = false;
            network_features::print_menu(parameters_cloned.clone(), capturing);
        }
        if line.contains("resume") {
            *pause.lock().unwrap() = false;
            println!("{}","\nCAPTURE RESUMED..".bold().green());
            capturing = true;
            network_features::print_menu(parameters_cloned.clone(), capturing);
        }
        if *end_copy.lock().unwrap() {break}
    }


}
