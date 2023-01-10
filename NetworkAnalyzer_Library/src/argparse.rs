//! Manage and parse CLI parameters

use clap::{Arg, Command, ArgMatches};
use colored::*;
use crate::network_features::print_all_devices;
use pcap::Device;



/// Collect the cli parameters into the struct clap::parser::ArgMatches
pub fn initialize_cli_parser() -> ArgMatches {
    let parser = Command::new("Network Sniffer")
        .arg(Arg::new("nic_id").help("The target network interface card to be user").required(true))
        .arg(Arg::new("file_name").help("The output file where a complete report should be provided").required(true))
        .arg(Arg::new("time_interval").help("Define the time interval after wihich the report is updated").required(true))
        .arg(Arg::new("ip_filter_source").short('a').long("ip_filter_source").value_name("ip_address_source").help("Keep only data that contains selected ip_address as source (ip address should have xxx.xxx.xxx.xxx format). Example of available ip address to filter:\n\t172.22.32.37"))
        .arg(Arg::new("ip_filter_dest").short('b').long("ip_filter_dest").value_name("ip_address_destination").help("Keep only data that contains selected ip_address as destination (ip address should have xxx.xxx.xxx.xxx format). Example of available ip address to filter:\n\t172.22.32.37"))
        .arg(Arg::new("port_filter_source").short('c').long("port_filter_source").value_name("port_source").help("Keep only data that contains selected port as source.\nMUST BE A NUMBER!"))
        .arg(Arg::new("port_filter_dest").short('d').long("port_filter_dest").value_name("port_destination").help("Keep only data that contains selected port as destination.\nMUST BE A NUMBER!"))
        .arg(Arg::new("byte_threshold").short('e').long("byte_threshold").value_name("Threshold").help("Drop all the data with cumulative number of bytes below the inserted threshold.\nMUST BE A NUMBER!"))
        .arg(Arg::new("protocol_filter").short('f').long("protocol_filter").value_name("Protocol name").help("Keep only data that contains selected protocol"))
        .arg(Arg::new("list").short('l').long("list")
            .help("List all possible interfaces available to be sniffed")
            .conflicts_with_all(&["nic_id", "file_name", "time_interval"]));
    return parser.get_matches();
}

#[derive(Debug, Clone)]
/// This structure aims to contain all the parameters that can be provided by the user through CLI
pub struct ArgsParameters {
    pub nic_id : isize,
    pub time_interval : u64,
    pub file_name: String,
    pub filter_address_set_source: bool,
    pub filter_address_set_dest: bool,
    pub filter_port_set_source : bool,
    pub filter_port_set_dest : bool,
    pub filter_bytes_set : bool,
    pub filter_protocols_set: bool,
    pub filter_address_source : Vec<u8>,
    pub filter_address_dest : Vec<u8>,
    pub port_source : u16,
    pub port_dest : u16,
    pub bytes_threshold : u64,
    pub protocol_name : String,
    pub list: bool
}

impl ArgsParameters {
    pub fn new(
                nic_id : isize,
                time_interval : u64,
                file_name: String,
                filter_address_set_source: bool,
                filter_address_set_dest: bool,
                filter_port_set_source : bool,
                filter_port_set_dest: bool,
                filter_bytes_set : bool,
                filter_protocols_set: bool,
                filter_address_source : Vec<u8>,
                filter_address_dest : Vec<u8>,
                port_source : u16,
                port_dest : u16,
                bytes_threshold : u64,
                protocol_name : String,
                list: bool) -> ArgsParameters
    {
        ArgsParameters {
            nic_id,
            time_interval,
            file_name,
            filter_address_set_source,
            filter_address_set_dest,
            filter_port_set_source,
            filter_port_set_dest,
            filter_bytes_set ,
            filter_protocols_set,
            filter_address_source,
            filter_address_dest,
            port_source,
            port_dest,
            bytes_threshold,
            protocol_name,
            list
        }
    }
}

/// Take the ArgMatches struct and trasforms it into a ArgsParameters struct which is more handleable.
/// Panic if some the CLI parameters is invalid
pub fn matches_arguments (matches : ArgMatches) -> ArgsParameters {

    if matches.contains_id("list") {
        let list = Device::list().unwrap();
        print_all_devices(list.clone());
        std::process::exit(0);
    }

    let mut nic_id = 999;
    if let Some(nic) = matches.get_one::<String>("nic_id") {
        match (*nic).parse::<isize>()  {
            Ok(n) => {nic_id = n;}
            Err(_e) => {let msg = "nic_id must be a number! \nPlease run again the application".red();
                        println!("{}",msg);
                        panic!("");}
        }
    }

    let mut file_name = String::from("NOT_PROVIDED");
    if let Some(fname) = matches.get_one::<String>("file_name") {
        match (*fname.clone()).parse()  {
            Ok(f) => {file_name = f;}
            Err(_e) => {let msg = "file_name must be a String! \nPlease run again the application".red();
                println!("{}",msg);
                panic!("");}
        }
    }

    let mut time_interval= 666;
    if let Some(t_interval) = matches.get_one::<String>("time_interval") {
        match (*t_interval).parse::<u64>() {
            Ok(t) => { time_interval = t;}
            Err(_e) => {let msg = "time_interval must be a number! \nPlease run again the application".red();
                println!("{}",msg);
                panic!("");}
        }

    }

    let mut address_set_source = false;
    let mut address_filter_source  =Vec::<u8>::new();
    if let Some(add) = matches.get_one::<String>("ip_filter_source") {
        address_set_source= true;
        address_filter_source= check_ip_addres((*add).clone());
        }

    let mut address_set_dest = false;
    let mut address_filter_dest  =Vec::<u8>::new();
    if let Some(add) = matches.get_one::<String>("ip_filter_dest") {
        address_set_dest= true;
        address_filter_dest= check_ip_addres((*add).clone());
    }

    let mut port_set_source = false;
    let mut port_filter_source=0 as u16;
    if let Some(port) = matches.get_one::<String>("port_filter_source") {
        port_set_source= true;
        match (*port).parse::<u16>() {
            Ok(p) => { port_filter_source = p;}
            Err(_e) => {let msg = "port_filter must be a number! \nPlease run again the application".red();
                println!("{}",msg);
                panic!("");}
        }
    }

    let mut port_set_dest = false;
    let mut port_filter_dest=0 as u16;
    if let Some(port) = matches.get_one::<String>("port_filter_dest") {
        port_set_dest= true;
        match (*port).parse::<u16>() {
            Ok(p) => { port_filter_dest = p;}
            Err(_e) => {let msg = "port_filter must be a number! \nPlease run again the application".red();
                println!("{}",msg);
                panic!("");}
        }
    }

    let mut byte_set = false;
    let mut byte_threshold=0 as u64;
    if let Some(byte_t) = matches.get_one::<String>("byte_threshold") {
        byte_set= true;
        match (*byte_t).parse::<u64>() {
            Ok(t) => { byte_threshold = t;}
            Err(_e) => {let msg = "byte_threshold must be a number! \nPlease run again the application".red();
                println!("{}",msg);
                panic!("");}
        }

    }

    let mut protocol_set = false;
    let mut protocol_name=String::new();
    if let Some(prot) = matches.get_one::<String>("protocol_filter") {
        protocol_set= true;
        match (*prot.clone().to_string()).parse() {
            Ok(p) => { protocol_name = p;}
            Err(_e) => {let msg = "protocol_filter must be a number! \nPlease run again the application".red();
                println!("{}",msg);
                panic!("");}
        }
    }

    let list_par = false;
    if matches.contains_id("list") {
        let list = Device::list().unwrap();
        print_all_devices(list.clone());
        std::process::exit(0);
    }

    let arg_parameters = ArgsParameters::new(
                                            nic_id,
                                            time_interval,
                                            file_name,
                                            address_set_source,
                                            address_set_dest,
                                            port_set_source,
                                            port_set_dest,
                                            byte_set,
                                            protocol_set,
                                            address_filter_source,
                                            address_filter_dest,
                                            port_filter_source,
                                            port_filter_dest,
                                            byte_threshold,
                                                        protocol_name,
                                            list_par);
    arg_parameters
}

/// Print "Network Analyzer" in a cool way in to the user terminal
pub fn print_title() {
    let title =
        " _  _       _                       _                    _   __   __           \n\
        | \\| | ___ | |_  _ __ __  ___  _ _ | |__       ___ _ _  (_) / _| / _| ___  _ _ \n\
        | .  |/ -_)|  _| \\ V  V // _ \\| '_|| / /      (_-/| ' \\ | ||  _||  _|/ -_)| '_|\n\
        |_|\\_|\\___| \\__|  \\_/\\_/ \\___/|_|  |_\\_\\      /__/|_||_||_||_|  |_|  \\___||_|  \n";
    println!("{}", title.red().green());
}

/// Check if the ip inserted as filter is valid
pub fn check_ip_addres( add : String) -> Vec<u8>{
    let a : String= (*add.clone().to_string()).parse().unwrap();
    let split = a.as_str().split(".");
    let mut address_vec = Vec::<u8>::new();
    for s in split {
    match  s.to_string().parse::<u8>() {
        Ok(n) => {
        address_vec.push(n);
        }
        Err(_e) => {
        let msg1 = "Error: ip_filter must be composed only by numbers !".red();
        let msg2 = "Example of address formats available:\n\t172.22.32.37\n\t157.240.231.16".green();
        println!("{}",msg1);
        println!("{}",msg2);
            panic!("");}
        }
    }
    address_vec
}

