pub mod structures;
pub mod argparse;
use csv::Writer;

pub mod network_features {
    use std::collections::HashMap;
    use std::env::Args;
    use std::fs::File;
    use std::io::{stdout, Write, BufReader, BufWriter};
    use std::path::Path;
    use pcap::{Device, Capture};
    use rpcap::read::PcapReader;
    use rpcap::write::{PcapWriter, WriteOptions};
    use pdu::*;
    use pdu::Tcp::Raw;
    use crate::structures::{CustomPacket, CustomKey, CustomData};
    use serde::{Serialize, Deserialize};
    use dns_parser::{Packet};
    use chrono::{DateTime, Local, NaiveDate, NaiveDateTime};
    //Stampa a video la lista di ttutti i network adapter e ritorna al main tale lista.

    pub fn print_all_devices(list: Vec<Device>) {
        let mut i = 1;
        println!("The available devices are:");
        for (j, d) in list.clone().iter().enumerate() {
            println!("{}) {:?}", j, d);
            //println!("{}) NAME: {} -- DESCRIPTION: {}",i,d.name, d.desc.unwrap());
            i = i + 1;
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

    pub fn check_device_available(selected: i32, list: Vec<Device>) -> bool {
        selected < list.len() as i32
    }

    pub fn capture_packet(selected_device: Device, file_name : String, print_report: bool, mut map: HashMap<String, CustomData>) -> HashMap<String, CustomData> {
        //let mut cap = selected_device.open().unwrap();
        let mut cap = Capture::from_device(selected_device).unwrap().open().unwrap();
        //println!("Data link: {:?}",cap.get_datalink());


        while let Ok(packet) = cap.next_packet() {
            //println!("received packet!", );
            let mut custom_packet = CustomPacket::new(
                packet.header.len
            );
            parse_level2_packet(packet.data, &mut custom_packet);
            //println!("{:?}", custom_packet);
            let mut key1 = CustomKey::new(custom_packet.src_addr, custom_packet.src_port);
            let key_string = serde_json::to_string(&key1).unwrap();
            let mut key2 = CustomKey::new(custom_packet.dest_addr, custom_packet.dest_port); //va aggiunta o no??
            let timestamp = now_date_hour();
            let mut custom_data = CustomData::new(custom_packet.len, custom_packet.prtocols_list, timestamp.clone());

            let r = map.get(&key_string);

            match r {
                Some(d) => {
                    let mut old_value = d.clone();
                    old_value.len = old_value.len + custom_data.len;
                    let timestamp2 = now_date_hour();
                    old_value.end_timestamp = timestamp2;
                    /*for protocol in custom_data.protocols {
                        if !old_value.protocols.contains(&protocol) {
                            println!("new protocol");
                            old_value.protocols.push(protocol)
                        }
                    }*/
                    old_value.protocols = custom_data.protocols;
                    map.insert(key_string, old_value);
                }
                None => {
                    let timestamp_start = now_date_hour();
                    custom_data.start_timestamp = timestamp_start.clone();
                    custom_data.end_timestamp = timestamp_start;
                    map.insert(key_string, custom_data);
                }
            }
            if print_report {
                write_to_file(map.clone(),file_name );
            }
            break
        }
        return map;
    }


    pub fn parse_level2_packet(packet_data: &[u8], custom_packet: &mut CustomPacket) {
        // parse a layer 2 (Ethernet) packet using EthernetPdu::new()

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
                        let src_vec = Vec::from(ipv4_pdu.source_address());
                        let dst_vec = Vec::from(ipv4_pdu.destination_address());
                        custom_packet.src_addr = src_vec;
                        custom_packet.dest_addr = dst_vec;
                        custom_packet.prtocols_list.push("ipv4".to_string());

                        match ipv4_pdu.inner() {
                            //livello 4
                            Ok(Ipv4::Icmp(icmp_pdu)) => {
                                custom_packet.prtocols_list.push("ICMP".to_string());
                            }
                            Ok(Ipv4::Gre(gre_pdu)) => {
                                custom_packet.prtocols_list.push("GRE".to_string());
                            }

                            Ok(Ipv4::Tcp(tcp_pdu)) => {
                                custom_packet.prtocols_list.push("TCP".to_string());
                                custom_packet.src_port = tcp_pdu.source_port();
                                custom_packet.dest_port = tcp_pdu.destination_port();
                                /*println!("[TCP] source port: {:?}", tcp_pdu.source_port());
                                println!("[TCP] destination port: {:?}", tcp_pdu.destination_port());*/

                                let tcp_payload = tcp_pdu.inner().unwrap();

                                match tcp_payload {
                                    Raw(payload) => {
                                        match Packet::parse(payload) {
                                            Ok(dns_packet) => {
                                                custom_packet.prtocols_list.push("DNS".to_string());
                                            }
                                            Err(e) => { /*println!("Packet is not DNS:{:?}",e)*/ }
                                        }
                                    }
                                }
                            }

                            Ok(Ipv4::Udp(udp_pdu)) => {
                                custom_packet.prtocols_list.push("UDP".to_string());
                                custom_packet.src_port = udp_pdu.source_port();
                                custom_packet.dest_port = udp_pdu.destination_port();
                                /*println!("[UDP] source port: {:?}", udp_pdu.source_port());
                                println!("[TCP] destination port: {:?}", udp_pdu.destination_port());*/

                                let udp_payload = udp_pdu.inner().unwrap();

                                match udp_payload {
                                    Udp::Raw(payloadd) => {
                                        match Packet::parse(payloadd) {
                                            Ok(dns_packet) => {
                                                custom_packet.prtocols_list.push("DNS".to_string());
                                            }
                                            Err(e) => { /*println!("Packet is not DNS:{:?}",e)*/ }
                                        }
                                    }
                                }
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
                        let src_vec = Vec::from(ipv6_pdu.source_address());
                        let dst_vec = Vec::from(ipv6_pdu.destination_address());
                        custom_packet.src_addr = src_vec;
                        custom_packet.dest_addr = dst_vec;
                        custom_packet.prtocols_list.push("ipv6".to_string());
                        // upper-layer protocols can be accessed via the inner() method (not shown)

                        match ipv6_pdu.inner() {
                            Ok(Ipv6::Icmp(icmp_pdu)) => {
                                custom_packet.prtocols_list.push("ICMP".to_string());
                            }
                            Ok(Ipv6::Gre(gre_pdu)) => {
                                custom_packet.prtocols_list.push("GRE".to_string());
                            }


                            //livello 4
                            Ok(Ipv6::Tcp(tcp_pdu)) => {
                                custom_packet.prtocols_list.push("TCP".to_string());
                                custom_packet.src_port = tcp_pdu.source_port();
                                custom_packet.dest_port = tcp_pdu.destination_port();
                                /*println!("[TCP] source port: {:?}", tcp_pdu.source_port());
                                println!("[TCP] destination port: {:?}", tcp_pdu.destination_port());*/

                                let tcp_payload = tcp_pdu.inner().unwrap();

                                match tcp_payload {
                                    Raw(payload) => {
                                        match Packet::parse(payload) {
                                            Ok(dns_packet) => {
                                                custom_packet.prtocols_list.push("DNS".to_string());
                                                //println!("{:?}",dns_packet);
                                            }
                                            Err(e) => { /*println!("Packet is not DNS:{:?}",e)*/ }
                                        }
                                    }
                                }
                            }

                            Ok(Ipv6::Udp(udp_pdu)) => {
                                custom_packet.prtocols_list.push("UDP".to_string());
                                custom_packet.src_port = udp_pdu.source_port();
                                custom_packet.dest_port = udp_pdu.destination_port();
                                /*println!("[UDP] source port: {:?}", udp_pdu.source_port());
                                println!("[TCP] destination port: {:?}", udp_pdu.destination_port());*/

                                let udp_payload = udp_pdu.inner().unwrap();

                                match udp_payload {
                                    Udp::Raw(payloadd) => {
                                        match Packet::parse(payloadd) {
                                            Ok(dns_packet) => {
                                                custom_packet.prtocols_list.push("DNS".to_string());
                                                //println!("{:?}",dns_packet);
                                            }
                                            Err(e) => { /*println!("Packet is not DNS:{:?}",e)*/ }
                                        }
                                    }
                                }
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
                        /*println!("[ARP] sender hardware address: {:x?}", arp_pdu.sender_hardware_address().as_ref());
                        println!("[ARP] sender protocol address: {:x?}", arp_pdu.sender_protocol_address().as_ref());
                        println!("[ARP] target hardware address: {:x?}", arp_pdu.target_hardware_address().as_ref());
                        println!("[ARP] targer protocol address: {:x?}", arp_pdu.target_protocol_address().as_ref());*/
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


    pub fn progress_bar() {
        let pb = indicatif::ProgressBar::new(100);
        for i in 0..100 {
            std::thread::sleep(std::time::Duration::from_secs(2));
            pb.println(format!("[+] finished #{}", i));
            pb.inc(1);
        }
        pb.finish_with_message("done");
    }


    pub fn write_to_file(mut map: HashMap<String, CustomData>, file_name: String) {

        //fake filters
        let min_len = 100 as u32;
        let port = "443".to_string();
        let protocol = "UDP".to_string();
        let mut path_name = file_name.clone();
        //path_name.push_str(".txt");
        path_name.push_str(".csv");
        let path_file = Path::new(&path_name);
        //let mut file = File::create(path_file).unwrap();
        let mut file = csv::Writer::from_path(path_file).unwrap();

        //filter the hashmap
        let mut map_to_print: HashMap<String, CustomData> = HashMap::new();
        //map_to_print = filter_len(map,min_len );
        //map_to_print = filter_protocol(map_to_print, protocol);
        //map_to_print= filter_address(map, port);
        map_to_print = map;
        //print on a file. Must be converted in a csv file
        //serde_json::to_writer(file, &map_to_print).unwrap();
        file.write_record(&["c", "i", "a", "o"]);
    }

    pub fn filter_len(mut map: HashMap<String, CustomData>, len_minimum: u32) -> HashMap<String, CustomData> {
        let mut filtered_map: HashMap<String, CustomData> = HashMap::new();
        for raw in map {
            let keyy = raw.0;
            let vall = raw.1;
            if vall.len > len_minimum {
                filtered_map.insert(keyy, vall);
            }
        }
        return filtered_map
    }

    //filter based on ip address or port number
    pub fn filter_address(mut map: HashMap<String, CustomData>, address_required: String) -> HashMap<String, CustomData> {
        let mut filtered_map: HashMap<String, CustomData> = HashMap::new();
        for raw in map {
            let keyy = raw.0;
            let vall = raw.1;
            if keyy.as_str().contains(address_required.clone().as_str()) {
                filtered_map.insert(keyy, vall);
            }
        }
        return filtered_map
    }

    //filter based on a protocol name
    pub fn filter_protocol(mut map: HashMap<String, CustomData>, protocol_required: String) -> HashMap<String, CustomData> {
        let mut filtered_map: HashMap<String, CustomData> = HashMap::new();
        for raw in map {
            let mut insert = false;
            let keyy = raw.0;
            let vall = raw.1.clone();
            let mut protocols = vall.protocols.clone();
            for p in protocols {
                if p.to_lowercase().eq(&protocol_required.clone().to_lowercase()) {
                    insert = true;
                }
            }
            if insert {
                filtered_map.insert(keyy, vall);
            }
        }
        return filtered_map
    }

    pub fn now_date_hour() -> String {
        let local1: DateTime<Local> = Local::now(); // e.g. `2014-11-28T21:45:59.324310806+09:00`
        let mut formatted_date = format!("{}", local1.date().format("%d/%m/%Y"));
        let formatted_hour = format!("{}", local1.time().format("%H:%M:%S%.3f"));
        formatted_date.push_str(" - ");
        formatted_date.push_str(formatted_hour.as_str());
        formatted_date
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
