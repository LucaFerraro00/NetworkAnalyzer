
use std::env::Args;
use std::fs::File;
use std::io::{stdout, Write, BufReader, BufWriter};
use std::path::Path;
use std::time::Duration;
use pcap::Device;
use rpcap::read::PcapReader;
use rpcap::write::{PcapWriter, WriteOptions};
use pdu::*;


//Stampa a video la lista di ttutti i network adapter e ritorna al main tale lista.
pub fn print_all_devices (list : Vec<Device>){
    let mut i =1;
    println!("The available devices are:");
    for d in list.clone() {
        println!("{}) NAME: {} -- DESCRIPTION: {}",i,d.name, d.desc.unwrap());
        i=i+1;
    }
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

pub fn create_file(file_name : String) -> File{
    let mut path = "results/".to_string();
    path.push_str(file_name.as_str());
    println!("{}",path);
    let mut f = File::create(path).unwrap();
    return f;
}



pub fn capture_packet (selected_device : Device) {
    println!("Capture is starting....");
    let mut cap = selected_device.open().unwrap();

    // open savefile using the capture
    let mut savefile = cap.savefile("testSave.pcap").unwrap();

    while let Ok(packet) = cap.next_packet() {
        println!("received packet! {:?}", packet);
        parse_level2_packet(packet.data)    ;
        // write the packet to the savefile
        savefile.write(& packet);
    }
}

pub fn parse_level2_packet(packet: &[u8]){
    // parse a layer 2 (Ethernet) packet using EthernetPdu::new()

        match EthernetPdu::new(&packet) {
            Ok(ethernet_pdu) => {
                println!("[ethernet] destination_address: {:x?}", ethernet_pdu.destination_address().as_ref());
                println!("[ethernet] source_address: {:x?}", ethernet_pdu.source_address().as_ref());
                println!("[ethernet] ethertype: 0x{:04x}", ethernet_pdu.ethertype());
                if let Some(vlan) = ethernet_pdu.vlan() {
                    println!("[ethernet] vlan: 0x{:04x}", vlan);
                }
                // upper-layer protocols can be accessed via the inner() method
                match ethernet_pdu.inner() {
                    Ok(Ethernet::Ipv4(ipv4_pdu)) => {
                        println!("[ipv4] source_address: {:x?}", ipv4_pdu.source_address().as_ref());
                        println!("[ipv4] destination_address: {:x?}", ipv4_pdu.destination_address().as_ref());
                        println!("[ipv4] protocol: 0x{:02x}", ipv4_pdu.protocol());
                        // upper-layer protocols can be accessed via the inner() method (not shown)
                    }
                    Ok(Ethernet::Ipv6(ipv6_pdu)) => {
                        println!("[ipv6] source_address: {:x?}", ipv6_pdu.source_address().as_ref());
                        println!("[ipv6] destination_address: {:x?}", ipv6_pdu.destination_address().as_ref());
                        println!("[ipv6] protocol: 0x{:02x}", ipv6_pdu.computed_protocol());
                        // upper-layer protocols can be accessed via the inner() method (not shown)
                    }
                    Ok(other) => {
                        panic!("Unexpected protocol {:?}", other);
                    }
                    Err(e) => {
                        panic!("EthernetPdu::inner() parser failure: {:?}", e);
                    }
                }
            }
            Err(e) => {
                panic!("EthernetPdu::new() parser failure: {:?}", e);
            }
        }
}


pub fn read_pcap_file(){
    // read a PCAP file
    let infile = File::open("testSave.pcap").unwrap();
    let reader = BufReader::new(infile);
    let (file_opts, mut pcapr) = PcapReader::new(reader).unwrap();
    println!("file_opts: {:?}", file_opts);
    println!("pcapr: {:?}", pcapr.next().unwrap());
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

/*
use log::{info, warn};
pub fn logging (){
    env_logger::init();
    info!("starting up");
    warn!("oops, nothing implemented!");
}
*/
