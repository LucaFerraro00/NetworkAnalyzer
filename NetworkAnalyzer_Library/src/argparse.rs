//! Manage and parse CLI parameters

use clap::{Arg, Command, ArgMatches};
use colored::*;
use crate::network_features::print_all_devices;
use pcap::Device;


///Collect the cli parameters in to the struct clap::parser::ArgMatches
pub fn initialize_cli_parser() -> ArgMatches {
    let parser = Command::new("Network Sniffer")
        .arg(Arg::new("nic_id").help("The target network interface card to be user").required(true))
        .arg(Arg::new("file_name").help("The output file where a complete report should be provided").required(true))
        .arg(Arg::new("time_interval").help("Define the time interval after wihich the report is updated").required(true))
        .arg(Arg::new("byte_threshold").short('b').long("byte_threshold").value_name("Threshold").help("Drop all the data with cumulative number of bytes below the inserted threshold"))
        .arg(Arg::new("protocol_filter").short('p').long("protocol_filter").value_name("Protocol name").help("Keep only data that contains selected protocol"))
        .arg(Arg::new("port_filter").short('s').long("port_filter").value_name("port").help("Keep only data that contains selected port"))
        .arg(Arg::new("list").short('l').long("list")
            .help("It provide a list of all possible interfaces available")
            .conflicts_with_all(&["nic_id", "file_name", "time_interval"]));
    return parser.get_matches();
}

    /*pub fn manage_cli_parameters() -> ArgMatches {
        let matches = command!() // requires `cargo` feature
            .arg(arg!([nic_id] "Network adapter to operate on").value_parser(value_parser!(u8)))
            .arg(arg!([file_name] "File name to print the report").value_parser(value_parser!(String)))
            .arg(arg!([time_interval] "Time interval for printing the report").value_parser(value_parser!(u8)))
            .arg(
                arg!(
                -a --address <id> "Sets an address/port you want to filter"
                )       // We don't have syntax yet for optional options, so manually calling `required`
                    .required(false)
            )
            .arg(
                arg!(
                -b --byte_threshold <bytes> "Sets a minimum threshold of nyte len to filter"
                )       // We don't have syntax yet for optional options, so manually calling `required`
                    .required(false)
                    .value_parser(value_parser!(u8))
            )
            .arg(
                arg!(
                -p --protocols <name> "Sets a protocol name you want to filter"
                )       // We don't have syntax yet for optional options, so manually calling `required`
                    .required(false)
            )
            .arg(arg!(
            -l --list ... "List available adapters"
              )
            )
            .get_matches();
        return matches
    }*/

#[derive(Debug)]
///This structure aims to conatin all the parameters that can be provided by the user through CLI
pub struct ArgsParameters {
    pub nic_id : u64,
    pub time_interval : u64,
    pub file_name: String,
    pub filter_address_set: bool,
    pub filter_port_set : bool,
    pub filter_bytes_set : bool,
    pub filter_protocols_set: bool,
    pub address : String,
    pub port : u16,
    pub bytes_threshold : u64,
    pub protocol_name : String,
    pub list: bool
}

impl ArgsParameters {
    pub fn new( nic_id : u64,
                time_interval : u64,
                file_name: String,
                filter_address_set: bool,
                filter_port_set : bool,
                filter_bytes_set : bool,
                filter_protocols_set: bool,
                address : String,
                port : u16,
                bytes_threshold : u64,
                protocol_name : String,
                list: bool) -> ArgsParameters
    {
        ArgsParameters {
            nic_id,
            time_interval,
            file_name,
            filter_address_set,
            filter_port_set,
            filter_bytes_set ,
            filter_protocols_set,
            address,
            port,
            bytes_threshold,
            protocol_name,
            list
        }
    }
}

///Take the ArgMatches struct and trasforms it into a ArgsParameters struct which is more handleable
pub fn matches_arguments (matches : ArgMatches) -> ArgsParameters {

    let mut nic_id = 999;
    if let Some(nic) = matches.get_one::<String>("nic_id") {
        let nic_numer = (*nic).parse::<u64>().expect("nic_id must be a number");
        nic_id = nic_numer;
    }

    let mut file_name = String::from("NOT_PROVIDED");
    if let Some(fname) = matches.get_one::<String>("file_name") {
        file_name= (*fname.clone()).parse().unwrap();
    }

    let mut time_interval= 666;
    if let Some(t_interval) = matches.get_one::<String>("time_interval") {
        let t_number = (*t_interval).parse::<u64>().expect("nic_id must be a number");
        time_interval = t_number;
    }


    let mut address_set = false;
    let mut address_filter=String::new();
    /*
    if let Some(add) = matches.get_one::<String>("filter_address") {
        address_set= true;
        address_filter= (*add.clone().to_string()).parse().unwrap();
    }*/

    if matches.contains_id("list") {
        let list = Device::list().unwrap();
        print_all_devices(list.clone());
        std::process::exit(0);
    }

    let mut byte_set = false;
    let mut byte_threshold=0 as u64;
    if let Some(byte_t) = matches.get_one::<String>("byte_threshold") {
        byte_set= true;
        let t_number = (*byte_t).parse::<u64>().expect("byte threshold must be a number");
        byte_threshold=t_number;
    }

    let mut port_set = false;
    let mut port_filter=0 as u16;
    if let Some(port) = matches.get_one::<String>("port_filter") {
        port_set= true;
        let p_number = (*port).parse::<u16>().expect("byte threshold must be a number");
        port_filter=p_number;
    }

    let mut protocol_set = false;
    let mut protocol_name=String::new();
    if let Some(prot) = matches.get_one::<String>("protocol_filter") {
        protocol_set= true;
        protocol_name=(*prot.clone().to_string()).parse().unwrap();
    }

    if matches.contains_id("list") {
        let list = Device::list().unwrap();
        print_all_devices(list.clone());
        std::process::exit(0);
    }
    let mut list = matches.get_flag("list");

    ArgsParameters::new(nic_id, time_interval, file_name,address_set, port_set, byte_set, protocol_set, address_filter, port_filter, byte_threshold, protocol_name, list )
}

///Print "Network Analyzer" in a cool way in to the user terminal
pub fn print_title() {
    let title =
        " _  _       _                       _                    _   __   __           \n\
        | \\| | ___ | |_  _ __ __  ___  _ _ | |__       ___ _ _  (_) / _| / _| ___  _ _ \n\
        | .  |/ -_)|  _| \\ V  V // _ \\| '_|| / /      (_-/| ' \\ | ||  _||  _|/ -_)| '_|\n\
        |_|\\_|\\___| \\__|  \\_/\\_/ \\___/|_|  |_\\_\\      /__/|_||_||_||_|  |_|  \\___||_|  \n";
    println!("{}", title.red().green());
}

