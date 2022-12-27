//! network_analyzer_lib aims at providing the features to intercept incoming and outgoing traffic
//! through the network interfaces of a computer.
//! This crate contains also the functions to interact with an user through command line parameters and to print a report of the
//! sniffed traffic into a file.
//!
//!
//! # Requirements
//! pcap should be installed to use this library: https://crates.io/crates/pcap
//!
//! # Examples
//! An easy way to use this library is to create a thread to sniff and parse packet, while the main thread
//! listen and updates commands inserted by user:
//!```no_run
//!let mut matched_arguments = argparse::initialize_cli_parser();
//!     let mut parameters = argparse::matches_arguments(matched_arguments);
//!     argparse::print_title();
//!     network_features::print_menu();
//!
//!    let mut pause = Arc::new(Mutex::new(false));
//!     let mut pause_copy= pause.clone();
//!     let mut pause_copy2= pause.clone();
//!     let mut end = Arc::new(Mutex::new(false));
//!     let mut end_copy= end.clone();
//!     let mut end_copy2= end.clone();
//!
//!     let th1 = thread::spawn(move||{
//!
//!         let list = Device::list().unwrap();
//!         /*match parameters.show {
//!             true => { network_features::print_all_devices(list.clone())}
//!             false => { () }
//!         }*/
//!         let mut selected_code = parameters.nic_id;
//!
//!         let mut available = network_features::check_device_available( selected_code as i32,list.clone());
//!         while !available {
//!             println!("The selected network adapter is not available!");
//!             println!("The available network adapter are: ");
//!             network_features::print_all_devices(list.clone());
//!             selected_code = network_features::select_device().parse::<u64>().unwrap();
//!             available = network_features::check_device_available( selected_code as i32, list.clone());
//!         }
//!
//!         let mut now = SystemTime::now();
//!         let mut print_report = false;
//!
//!
//!         let mut map : HashMap<structures::CustomKey, structures::CustomData> = HashMap::new();
//!
//!         loop {
//!             let mut e = end_copy.clone();
//!             let mut p = pause_copy.clone();
//!             let selected_device = list[(selected_code as usize) -1].clone();
//!             if *p.lock().unwrap()==false {
//!                 let interval = Duration::from_secs(parameters.time_interval);
//!                 let mut diff = now.elapsed().unwrap();
//!                 if diff > interval {
//!                     print_report=true;
//!                     now = SystemTime::now();
//!                 }
//!                 map = network_features::capture_packet(selected_device, parameters.file_name.clone(), print_report, map);
//!                 print_report=false;
//!             }
//!             //println!("dentro loop thread secondario: end={}",*end.lock().unwrap());
//!             if *e.lock().unwrap() {break}
//!         }
//!     });
//!
//!
//!     loop {
//!         let mut end_copy= end.clone();
//!         let mut line = String::new();
//!         println!("Enter your command :");
//!         let mut std_lock = std::io::stdin();
//!         std_lock.read_line(&mut line).unwrap();
//!         //let b1 = std::io::stdin().read_line(&mut line).unwrap();
//!         if line.contains("end") {
//!             *end.lock().unwrap() = true;
//!             println!("goodbye");
//!         }
//!         if line.contains("pause") {
//!             *pause.lock().unwrap() = true;
//!             println!("CAPTURE IS WAITING FOR RESUMING");
//!         }
//!         if line.contains("resume") {
//!             *pause.lock().unwrap() = false;
//!             println!("CAPTURE IS GOING ON");
//!         }
//!         if *end_copy.lock().unwrap() {break}
//!     }
//! ```
//!

pub mod structures;
pub mod argparse;

pub mod network_features {
    //!Contains all the functions to capture, parse and store the informations sniffed in network packets
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::{stdout, Write};
    use std::path::Path;
    use pcap::{Device, Capture};
    use pdu::{Ethernet, Ipv4, Ipv6, Udp, Tcp::Raw};
    use pdu::{EthernetPdu};
    use crate::structures::{CustomPacket, CustomKey, CustomData};
    use serde::{Serialize};
    use dns_parser::{Packet};
    use chrono::{DateTime, Local};
    use std::string::String;
    use csv::{Writer, WriterBuilder};
    use crate::argparse;
    use colored::*;
    use crate::argparse::ArgsParameters;


    ///Print the list of the available network adapters of PC
    pub fn print_all_devices(list: Vec<Device>) {
        let mut i = 1;
        //println!("The available devices are:");
        println!("| {0:-^7} | {1:-^20} | {2:-^20} | {3:-^50} |",
                 "Index".bold(), "Name".bold(), "Addresses".bold(), "Description".bold());
        for (j, d) in list.clone().iter().enumerate() {
            let addresses : Vec<String> = d.addresses.iter()
                .map(|addr_struct | addr_struct.addr.to_string())
                .collect();
            let addresses_str = addresses.join(", ");
            let description = match &d.desc{
                Some(des) => String::from(des),
                _ => String::new()
            };
            println!("| {0: ^7} | {1: <20} | {2: <20 } | {3: <30} ", j, d.name, addresses_str, description);
            //println!("{}) NAME: {} -- DESCRIPTION: {}",i,d.name, d.desc.unwrap());
            i = i + 1;
        }
        println!("{:-<110}", "");
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

    ///Check if the selected network adapter exists and is available.
    /// Return true if avaialable, otherwise false
    pub fn check_device_available(selected: i32, list: Vec<Device>) -> bool {
        selected < list.len() as i32
    }

    ///Start the capture session using pcap features.
    /// When a packet is received it is passed to function parser_level2_packet which cares about parsing packets byte.
    ///The function capture_packet also updates the HashMap<CustomKey, CustomData> which contains the informations of the captured packets.
    ///Furthermore this functions check the interval previosuly provided by the user. If the interval is elapsed capture_packet calls write_to_file function to store to the file the updated informations about ntwork analisys
    pub fn capture_packet(selected_device: Device, _arguments : &argparse::ArgsParameters, mut map: HashMap<CustomKey, CustomData>) -> Result<HashMap<CustomKey, CustomData>, String> {

        match Capture::from_device(selected_device).unwrap().open() {
            Ok(mut cap) => {
                while let Ok(packet) = cap.next_packet() {
                    //println!("{:?}",packet);
                    let mut custom_packet = CustomPacket::new(
                        packet.header.len
                    );
                    parse_level2_packet(packet.data, &mut custom_packet);
                    let key1 = CustomKey::new(custom_packet.src_addr, custom_packet.src_port, custom_packet.dest_addr, custom_packet.dest_port);
                    let mut custom_data = CustomData::new(custom_packet.len, custom_packet.prtocols_list);

                    let r = map.get(&key1);//let r = map.get(&key_string);
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
                            map.insert(key1, old_value);
                        }
                        None => {
                            let timestamp_start = now_date_hour();
                            custom_data.start_timestamp = timestamp_start.clone();
                            custom_data.end_timestamp = timestamp_start;
                            map.insert(key1, custom_data);
                        }
                    }
                    break
                }
                return Ok(map);
            }//fine ok
            Err(_e) => { return Err(String::new()) }
        }//fine match
    }

    ///This function exploits the features provide by pdu library.
    /// It takes as input a stream of byte &[u8] and parse it. Starts from the network layer pdu and then goes deep up to transport layer.
    /// At each level of the stack the struct CustomPacket is updated with the information spotted (protocol name, protocol, address).
    /// When pdu of level 4 is reached the dns_parser external library is used to check if packet is carrying DNS protocol. Finally the updated struct CustomPacket is returned
    pub fn parse_level2_packet(packet_data: &[u8], custom_packet: &mut CustomPacket) {
        // parse a layer 2 (Ethernet) packet using EthernetPdu::new()

        match EthernetPdu::new(&packet_data) {
            Ok(ethernet_pdu) => {
                custom_packet.prtocols_list.push("ethernet".to_string());
                //layer 2
                // upper-layer protocols can be accessed via the inner() method
                match ethernet_pdu.inner() {
                    Ok(Ethernet::Ipv4(ipv4_pdu)) => {
                        //layer 3
                        let src_vec = Vec::from(ipv4_pdu.source_address());
                        let dst_vec = Vec::from(ipv4_pdu.destination_address());
                        custom_packet.src_addr = src_vec;
                        custom_packet.dest_addr = dst_vec;
                        custom_packet.prtocols_list.push("ipv4".to_string());

                        match ipv4_pdu.inner() {
                            //layer 4
                            Ok(Ipv4::Icmp(_icmp_pdu)) => {
                                custom_packet.prtocols_list.push("ICMP".to_string());
                            }
                            Ok(Ipv4::Gre(_gre_pdu)) => {
                                custom_packet.prtocols_list.push("GRE".to_string());
                            }

                            Ok(Ipv4::Tcp(tcp_pdu)) => {
                                custom_packet.prtocols_list.push("TCP".to_string());
                                custom_packet.src_port = tcp_pdu.source_port();
                                custom_packet.dest_port = tcp_pdu.destination_port();

                                let tcp_payload = tcp_pdu.inner().unwrap();
                                match tcp_payload {
                                    Raw(payload) => {
                                        match Packet::parse(payload) {
                                            Ok(_dns_packet) => {
                                                custom_packet.prtocols_list.push("DNS".to_string());
                                            }
                                            Err(_e) => { /*Packet is not DNS*/ }
                                        }
                                    }
                                }
                            }

                            Ok(Ipv4::Udp(udp_pdu)) => {
                                custom_packet.prtocols_list.push("UDP".to_string());
                                custom_packet.src_port = udp_pdu.source_port();
                                custom_packet.dest_port = udp_pdu.destination_port();

                                let udp_payload = udp_pdu.inner().unwrap();
                                match udp_payload {
                                    Udp::Raw(payloadd) => {
                                        match Packet::parse(payloadd) {
                                            Ok(_dns_packet) => {
                                                custom_packet.prtocols_list.push("DNS".to_string());
                                            }
                                            Err(_e) => { /*Packet is not DNS*/ }
                                        }
                                    }
                                }
                            }

                            Ok(other) => {
                                println!("Unrecognized protocol inside Ipv4Pdu {:?}", other);
                            }

                            Err(e) => {
                                println!("Parser failure of the inner content of Ipv4pdu : {:?}", e);
                            }
                        }
                    }
                    Ok(Ethernet::Ipv6(ipv6_pdu)) => {
                        //layer 3
                        let src_vec = Vec::from(ipv6_pdu.source_address());
                        let dst_vec = Vec::from(ipv6_pdu.destination_address());
                        custom_packet.src_addr = src_vec;
                        custom_packet.dest_addr = dst_vec;
                        custom_packet.prtocols_list.push("ipv6".to_string());
                        // upper-layer protocols can be accessed via the inner() method (not shown)

                        match ipv6_pdu.inner() {
                            Ok(Ipv6::Icmp(_icmp_pdu)) => {
                                custom_packet.prtocols_list.push("ICMP".to_string());
                            }
                            Ok(Ipv6::Gre(_gre_pdu)) => {
                                custom_packet.prtocols_list.push("GRE".to_string());
                            }

                            //layer 4
                            Ok(Ipv6::Tcp(tcp_pdu)) => {
                                custom_packet.prtocols_list.push("TCP".to_string());
                                custom_packet.src_port = tcp_pdu.source_port();
                                custom_packet.dest_port = tcp_pdu.destination_port();

                                let tcp_payload = tcp_pdu.inner().unwrap();
                                match tcp_payload {
                                    Raw(payload) => {
                                        match Packet::parse(payload) {
                                            Ok(_dns_packet) => {
                                                custom_packet.prtocols_list.push("DNS".to_string());
                                            }
                                            Err(_e) => { /*Packet is not DNS*/ }
                                        }
                                    }
                                }
                            }

                            Ok(Ipv6::Udp(udp_pdu)) => {
                                custom_packet.prtocols_list.push("UDP".to_string());
                                custom_packet.src_port = udp_pdu.source_port();
                                custom_packet.dest_port = udp_pdu.destination_port();

                                let udp_payload = udp_pdu.inner().unwrap();
                                match udp_payload {
                                    Udp::Raw(payloadd) => {
                                        match Packet::parse(payloadd) {
                                            Ok(_dns_packet) => {
                                                custom_packet.prtocols_list.push("DNS".to_string());
                                            }
                                            Err(_e) => { /*Packet is not DNS*/ }
                                        }
                                    }
                                }
                            }

                            Ok(other) => {
                                println!("Unrecognized protocol inside Ipv6Pdu {:?}", other);
                            }

                            Err(e) => {
                                println!("Parser failure of the inner content of Ipv6pdu : {:?}", e);
                            }
                        }
                    }

                    Ok(Ethernet::Arp(_arp_pdu)) => {
                        //layer 3
                        custom_packet.prtocols_list.push("ARP".to_string());
                    }

                    Ok(other) => {
                        println!("Unrecognized protocol for packet: {:?}", other);
                    }
                    Err(e) => {
                        println!("Parser failure of EthernetPdu: {:?}", e);
                    }
                }
            }
            Err(e) => {
                println!("Parser failure for packet: {:?}", e);
            }
        }
    }



    pub fn write_to_file( map: HashMap<CustomKey, CustomData>, arguments : &argparse::ArgsParameters)  {
        let mut f_name = arguments.file_name.clone();
        //path_name.push_str(".txt");
        f_name.push_str(".csv");
        let mut path_name = "results/".to_string();
        path_name.push_str(&*f_name);
        let path_file = Path::new(&path_name);
        //let mut file = File::create(path_file).unwrap();
        let mut file : Writer<File>;
        match csv::Writer::from_path(path_file) {
            Ok(f)=>{  file = f;}
            Err(e) => {
                              let msg = "Error in report file generation/update: ".red();
                              println!( "{} {}", msg, e.to_string().as_str().red() );
                              let msg ="Please check the error and start the application again".red();
                              println!("{}",msg);
                              std::process::exit(0);
            }
        }
        //filter the hashmap
        let mut map_to_print: HashMap<CustomKey, CustomData> = map.clone();
        if arguments.filter_address_set_source {
            map_to_print = filter_ip_address_source(map_to_print, arguments.filter_address_source.clone())
        }
        if arguments.filter_address_set_dest {
            map_to_print = filter_ip_address_dest(map_to_print, arguments.filter_address_dest.clone());
        }
        if arguments.filter_port_set_source {
            map_to_print = filter_port_source(map_to_print, arguments.port_source);
        }
        if arguments.filter_port_set_dest {
            map_to_print = filter_port_dest(map_to_print, arguments.port_dest);
        }
        if arguments.filter_bytes_set {
            map_to_print = filter_len(map_to_print, arguments.bytes_threshold);
        }
        if arguments.filter_protocols_set{
            map_to_print = filter_protocol(map_to_print, arguments.protocol_name.clone());
        }
        //print on a file. Must be converted in a csv file
        //serde_json::to_writer(file, &map_to_print).unwrap();
        //file.write_record(&["ip address/Port", "        Length","    Protocols", "      Start Time", "      End Time"]);
        #[derive (Serialize)]
        struct Record {
            ip_port_source : String,
            ip_port_dest : String,
            length : String,
            protocols : String,
            start_timestamp: String,
            end_timestamp:String,
        }

        let mut wtr = WriterBuilder::new()
            //.delimiter(b',')
            .has_headers(true)
            .from_writer(vec![]);

        for key in map_to_print.keys() {
            let (source,dest) = format_key(key);
            /*file.serialize(formatted_key);
            file.serialize(map_to_print.get(key));
            file.write_record(&[""]);*/

            wtr.serialize(Record {
                ip_port_source : source,
                ip_port_dest : dest,
                length: map_to_print.get(key).unwrap().len.clone().to_string(),
                protocols: map_to_print.get(key).unwrap().protocols.clone().join("-"),
                start_timestamp: map_to_print.get(key).unwrap().start_timestamp.clone(),
                end_timestamp: map_to_print.get(key).unwrap().end_timestamp.clone()
            }).unwrap();
        }
        wtr.flush().unwrap();
        let row_string = String::from_utf8(wtr.into_inner().unwrap()).unwrap();

        //println!("{}",row_string);
       match file.serialize(&[row_string]){
           Err(e)=>{println!("{:?}",e)}
           _ => {}
           }
        }

    pub fn format_key( k : &CustomKey) -> (String,String){
        let  ip_s = k.ip_source.clone();
        let mut s = String::new();
        for n in ip_s{
            s.push_str(n.to_string().as_str());
            s.push('.');
        }
        s.pop();
        let port_s = k.port_source.clone();
        s.push('/');
        s.push_str(port_s.to_string().as_str());

        let mut d = String::new();
        let  ip_d = k.ip_dest.clone();
        for n in ip_d{
            d.push_str(n.to_string().as_str());
            d.push('.');
        }
        d.pop();
        let port_d = k.port_dest.clone();
        d.push('/');
        d.push_str(port_d.to_string().as_str());
        return (s,d)
    }

    ///Receive the HashMap<String, CustomData> and the filter on the required source address provided by the user. Drops all the rows
    ///of the HashMamp which don't contains that address.
    pub fn filter_ip_address_source( map: HashMap<CustomKey, CustomData>, ip_filter: Vec<u8> ) -> HashMap<CustomKey, CustomData> {
        let mut filtered_map: HashMap<CustomKey, CustomData> = HashMap::new();
        for raw in map {
            let keyy = raw.0;
            let vall = raw.1;
            if keyy.ip_source.clone().eq(&ip_filter){
                filtered_map.insert(keyy, vall);
            }
        }
        return filtered_map
    }

    ///Receive the HashMap<String, CustomData> and the filter on the required destination address provided by the user. Drops all the rows
    ///of the HashMamp which don't contains that address
    pub fn filter_ip_address_dest( map: HashMap<CustomKey, CustomData>, ip_filter: Vec<u8> ) -> HashMap<CustomKey, CustomData> {
        let mut filtered_map: HashMap<CustomKey, CustomData> = HashMap::new();
        for raw in map {
            let keyy = raw.0;
            let vall = raw.1;
            if keyy.ip_dest.clone().eq(&ip_filter){
                filtered_map.insert(keyy, vall);
            }
        }
        return filtered_map
    }

    ///Receive the HashMap<String, CustomData> and the filter on the required source port provided by the user. Drops all the rows
    ///of the HashMamp which don't contains that port
    pub fn filter_port_source( map: HashMap<CustomKey, CustomData>, port: u16) -> HashMap<CustomKey, CustomData> {
        let mut filtered_map: HashMap<CustomKey, CustomData> = HashMap::new();
        for raw in map {
            let keyy = raw.0;
            let vall = raw.1;
            if keyy.port_source.clone()== port {
                filtered_map.insert(keyy, vall);
            }
        }
        return filtered_map
    }

    ///Receive the HashMap<String, CustomData> and the filter on the required destination port provided by the user. Drops all the rows
    ///of the HashMamp which don't contains that port
    pub fn filter_port_dest( map: HashMap<CustomKey, CustomData>, port: u16) -> HashMap<CustomKey, CustomData> {
        let mut filtered_map: HashMap<CustomKey, CustomData> = HashMap::new();
        for raw in map {
            let keyy = raw.0;
            let vall = raw.1;
            if keyy.port_dest.clone()== port {
                filtered_map.insert(keyy, vall);
            }
        }
        return filtered_map
    }

    ///Receive the HashMap<String, CustomData> and the filter on the minimum byte threshold provided by the user. Drops all the rows
    ///of th HashMamp with cumulative byte lenght lower than threshold
    pub fn filter_len( map: HashMap<CustomKey, CustomData>, len_minimum: u64) -> HashMap<CustomKey, CustomData> {
        let mut filtered_map: HashMap<CustomKey, CustomData> = HashMap::new();
        for raw in map {
            let keyy = raw.0;
            let vall = raw.1;
            if vall.len as u64> len_minimum {
                filtered_map.insert(keyy, vall);
            }
        }
        return filtered_map
    }

    ///Receive the HashMap<String, CustomData> and the protocol name filter provided by the user. Drops all the rows
    ///of th HashMamp which don't contains the specifie protocol
    pub fn filter_protocol( map: HashMap<CustomKey, CustomData>, protocol_required: String) -> HashMap<CustomKey, CustomData> {
        let mut filtered_map: HashMap<CustomKey, CustomData> = HashMap::new();
        for raw in map {
            let mut insert = false;
            let keyy = raw.0;
            let vall = raw.1.clone();
            let protocols = vall.protocols.clone();
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

    ///Exploits the chrono library's features and return actual date an hour in formatted format:
    /// day/month/year - hours:minutes:seconds
    ///
    /// For example: "28/10/2022 - 18:31:34.286"
    /// It is used to store initial and final timestamp of the captured packet.
    pub fn now_date_hour() -> String {
        let local1: DateTime<Local> = Local::now(); // e.g. `2014-11-28T21:45:59.324310806+09:00`
        let mut formatted_date = format!("{}", local1.date().format("%d/%m/%Y"));
        let formatted_hour = format!("{}", local1.time().format("%H:%M:%S%.3f"));
        formatted_date.push_str(" - ");
        formatted_date.push_str(formatted_hour.as_str());
        formatted_date
    }

    ///Print the basic menu of available commands on the terminal
    pub fn print_menu(parameters: ArgsParameters, capturing: bool) {
        if capturing {
            println!("{}", "\nCAPTURE IS GOING ON..".bold().green());
            if !parameters.filter_port_set_dest && !parameters.filter_port_set_source && !parameters.filter_address_set_source && !parameters.filter_address_set_dest && !parameters.filter_bytes_set && !parameters.filter_protocols_set {
                println!("(You are running the capture {})", "without filters".underline().bold());
            }
            if parameters.filter_address_set_source {
                let v = parameters.filter_address_source;
                let mut s = String::new();
                for n in v {
                    s.push_str(n.to_string().as_str());
                    s.push('.')
                }
                println!("\tYou are running the capture with filter on {}: {}",
                         "Source ip address".bold().yellow(), s.bold());
            }

            if parameters.filter_address_set_dest {
                let v = parameters.filter_address_dest;
                let mut s = String::new();
                for n in v {
                    s.push_str(n.to_string().as_str());
                    s.push('.')
                }
                println!("\tYou are running the capture with filter on {}: {}",
                         "Destination ip address".bold().yellow(), s.bold());
            }

            if parameters.filter_port_set_source {
                let port = parameters.port_source;
                println!("\tYou are running the capture with filter on {}: {}",
                         "Source port".bold().yellow(), port.to_string().bold());
            }

            if parameters.filter_port_set_dest {
                let port = parameters.port_dest;
                println!("\tYou are running the capture with filter on {}: {}",
                         "Destination port".bold().yellow(), port.to_string().bold());
            }

            if parameters.filter_bytes_set {
                println!("\t-You are using the filter on the {} {}",
                         "byte threshold:".bold().yellow(),
                         parameters.bytes_threshold.to_string().bold());
            }
            if parameters.filter_protocols_set {
                println!("\t-You are using the filter on the {} {}", "protocol:".bold().yellow(),
                         parameters.protocol_name.bold());
            }
            println!("");
        }
        println!("{}", "Available comands are:".bold());
        println!("\t-digit {} to temporaly stop the sniffing", "pause".bold().underline());
        println!("\t-digit {} to resume the sniffing", "resume".bold().underline());
        println!("\t-digit {} to finish the sniffing", "end".bold().underline());
    }

}


