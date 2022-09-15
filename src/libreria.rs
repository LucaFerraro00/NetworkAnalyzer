use std::env::Args;
use std::io::{stdout, Write};
use std::time::Duration;
use pcap::Device;

//Stampa a video la lista di ttutti i network adapter e ritorna al main tale lista.
pub fn print_all_devices () -> Vec<Device>{
    let list = Device::list().unwrap();
    let mut i =1;
    for d in list.clone() {
        println!("{}) NAME: {} -- DESCRIPTION: {}",i,d.name, d.desc.unwrap());
        i=i+1;
    }
    return list;
}

pub fn manage_parameters (parameters: Args){
    //il ptimo parametro[0] rappresenta il percorso dell'esegubile (non serve)
    println!("{:?}",parameters)
}


pub fn select_device()->  String {
    let mut line = String::new();
    println!("Enter the number of the network adapter you want to analyze");
    print!("  > ");
    stdout().flush().unwrap();
    std::io::stdin().read_line(&mut line).unwrap();
    println!("You have selected: {}", line);
    return line.trim().to_string();
}

pub fn check_device_available( selected : i32, list:  Vec<Device>) -> bool {
     selected < list.len() as i32
}


pub fn progress_bar (){
    let pb = indicatif::ProgressBar::new(100);
    for i in 0..100 {
        std::thread::sleep(std::time::Duration::from_secs(2));
        pb.println(format!("[+] finished #{}", i));
        pb.inc(1);
    }
    pb.finish_with_message("done");
}

pub fn capture_packet (selected_device : Device) {
    println!("Capture is starting....");
    let mut cap = selected_device.open().unwrap();
    while let Ok(packet) = cap.next_packet() {
        println!("received packet! {:?}", packet);
        //println!("Data: {}", std::str::from_utf8(packet.data).unwrap())
    }
}
/*
use log::{info, warn};
pub fn logging (){
    env_logger::init();
    info!("starting up");
    warn!("oops, nothing implemented!");
}
*/
