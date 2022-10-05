mod structures;

use std::collections::HashMap;
use std::env::Args;
use std::fs::File;
use std::io::{stdout, Write, BufReader, BufWriter};
use std::path::Path;
use std::time::Duration;
use pcap::{Device, Capture};
use rpcap::read::PcapReader;
use rpcap::write::{PcapWriter, WriteOptions};
use pdu::*;
use crate::structures::{CustomPacket, CustomKey, CustomData};


//Stampa a video la lista di ttutti i network adapter e ritorna al main tale lista.
pub fn print_all_devices (list : Vec<Device>){
    let mut i =1;
    println!("The available devices are:");
    for (j, d) in list.clone().iter().enumerate() {
        println!("{}) {:?}", j,d);
        //println!("{}) NAME: {} -- DESCRIPTION: {}",i,d.name, d.desc.unwrap());
        i=i+1;
    }
}


pub fn select_device() -> String {
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
    //let mut cap = selected_device.open().unwrap();
    let mut cap = Capture::from_device(selected_device).unwrap().open().unwrap();
    println!("Data link: {:?}",cap.get_datalink());

    let mut map : HashMap<CustomKey, CustomData> = HashMap::new();
    let mut counter = 0;

        while let Ok(packet) = cap.next_packet() {
            println!("received packet!", );
            let mut custom_packet = CustomPacket::new(
                packet.header.len
            );
            parse_level2_packet(packet.data, &mut custom_packet);
            println!("{:?}", custom_packet);
            let mut key1 = CustomKey::new(custom_packet.src_addr, custom_packet.src_port);
            let mut key2 = CustomKey::new(custom_packet.dest_addr, custom_packet.dest_port);
            let mut custom_data = CustomData::new(custom_packet.len, custom_packet.prtocols_list);

            let r = map.get(&key1);

            match r {
                Some(d) => {
                    let mut old_value = d.clone();
                    old_value.len = old_value.len + custom_data.len;
                    for protocol in old_value.protocols {
                        if !custom_data.protocols.contains(&protocol) {
                            custom_data.protocols.push(protocol)
                        }
                    }
                }
                None => { map.insert(key1, custom_data); }
            }

            counter += 1;
            if counter>50 {    println!("{:?}",map);       }

            }
}

pub fn parse_level2_packet(packet_data: &[u8], custom_packet: & mut CustomPacket){
    // parse a layer 2 (Ethernet) packet using EthernetPdu::new()
    let mut dest_pair= String::new();
    let mut source_pair = String::new();
        match EthernetPdu::new(&packet_data) {
            Ok(ethernet_pdu) => {
                custom_packet.prtocols_list.push("ethernet".to_string());
                //livello 2
                /*println!("[ethernet] destination_address: {:x?}", ethernet_pdu.destination_address().as_ref());
                println!("[ethernet] source_address: {:x?}", ethernet_pdu.source_address().as_ref());*/

                // upper-layer protocols can be accessed via the inner() method
                match ethernet_pdu.inner() {
                    Ok(Ethernet::Ipv4(ipv4_pdu)) => {
                        //livello 3
                        /*println!("[ipv4] source_address: {:x?}", ipv4_pdu.source_address().as_ref());
                        println!("[ipv4] destination_address: {:x?}", ipv4_pdu.destination_address().as_ref());
                        println!("[ipv4] protocol: 0x{:02x}", ipv4_pdu.protocol());*/
                        custom_packet.src_addr= ipv4_pdu.source_address();
                        custom_packet.dest_addr= ipv4_pdu.destination_address();
                        custom_packet.prtocols_list.push("ipv4".to_string());

                        match ipv4_pdu.inner() {
                            //livello 4
                            Ok(Ipv4::Icmp(icmp_pdu)) =>{
                                println!("[ICMP]  {:?}", icmp_pdu);
                                custom_packet.prtocols_list.push("ICMP".to_string());

                            }
                            Ok(Ipv4::Gre(gre_pdu)) =>{
                                println!("[GRE] {:?}", gre_pdu);
                                custom_packet.prtocols_list.push("GRE".to_string());
                            }

                            Ok(Ipv4::Tcp(tcp_pdu)) =>{
                                custom_packet.prtocols_list.push("TCP".to_string());
                                custom_packet.src_port = tcp_pdu.source_port();
                                custom_packet.dest_port = tcp_pdu.destination_port();
                                /*println!("[TCP] source port: {:?}", tcp_pdu.source_port());
                                println!("[TCP] destination port: {:?}", tcp_pdu.destination_port());*/
                            }
                            Ok(Ipv4::Udp(udp_pdu)) =>{
                                custom_packet.prtocols_list.push("UDP".to_string());
                                custom_packet.src_port = udp_pdu.source_port();
                                custom_packet.dest_port = udp_pdu.destination_port();
                                /*println!("[UDP] source port: {:?}", udp_pdu.source_port());
                                println!("[TCP] destination port: {:?}", udp_pdu.destination_port());*/
                            }


                            Ok(other) => {
                                panic!("Unexpected protocol inside Ipv4Pdu {:?}", other);
                            }

                            Err(e) => {
                                panic!("Ipv4pdu::inner() parser failure: {:?}", e);
                            }
                        }

                    }
                    Ok(Ethernet::Ipv6(ipv6_pdu)) => {
                        //livello 3
                        println!("[ipv6] source_address: {:x?}", ipv6_pdu.source_address().as_ref());
                        println!("[ipv6] destination_address: {:x?}", ipv6_pdu.destination_address().as_ref());
                        println!("[ipv6] protocol: 0x{:02x}", ipv6_pdu.computed_protocol());
                        // upper-layer protocols can be accessed via the inner() method (not shown)

                        match ipv6_pdu.inner() {
                            //livello 4
                            Ok(Ipv6::Tcp(tcp_pdu)) =>{
                                println!("[TCP] source port: {:?}", tcp_pdu.source_port());
                                println!("[TCP] destination port: {:?}", tcp_pdu.destination_port());
                            }
                            Ok(Ipv6::Udp(udp_pdu)) =>{
                                println!("[UDP] source port: {:?}", udp_pdu.source_port());
                                println!("[UDP] destination port: {:?}", udp_pdu.destination_port());
                            }
                            Ok(Ipv6::Icmp(icmp_pdu)) =>{
                                println!("[ICMP]  {:?}", icmp_pdu);
                            }
                            Ok(Ipv6::Gre(gre_pdu)) =>{
                                println!("[GRE] {:?}", gre_pdu);
                            }

                            Ok(other) => {
                                panic!("Unexpected protocol inside Ipv6Pdu {:?}", other);
                            }

                            Err(e) => {
                                panic!("Ipv6pdu::inner() parser failure: {:?}", e);
                            }
                        }
                    }

                    Ok(Ethernet::Arp(arp_pdu)) => {
                        //livello 3
                        custom_packet.prtocols_list.push("ARP".to_string());
                        println!("[ARP] sender hardware address: {:x?}", arp_pdu.sender_hardware_address().as_ref());
                        println!("[ARP] sender protocol address: {:x?}", arp_pdu.sender_protocol_address().as_ref());
                        println!("[ARP] target hardware address: {:x?}", arp_pdu.target_hardware_address().as_ref());
                        println!("[ARP] targer protocol address: {:x?}", arp_pdu.target_protocol_address().as_ref());
                        //ARP al contrario di ip non consente di vedere cosa c'è nei livelli sucessivi.
                        //Non ha il metodo inner, è giusto?
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
