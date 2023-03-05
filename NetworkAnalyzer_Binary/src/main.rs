
use std::{thread};
use std::io::{Write};
use std::sync::{Arc, Mutex};
use pcap::Device;
use network_analyzer_lib::{network_features, argparse};
use colored::Colorize;

fn main() {

    //Set custom format for information printed when there is a panic
    std::panic::set_hook(Box::new(|_| {
        println!("Exiting..");
    }));

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
            return;
        }  num => num as usize
    } as usize;
    argparse::print_title();
    let mut _capturing = true;
    network_features::print_menu(parameters.clone(), _capturing);

    let pause = Arc::new(Mutex::new(false));
    let pause_copy= pause.clone();
    let end = Arc::new(Mutex::new(false));
    let end_copy= end.clone();



    let _user_command_thread = thread::spawn(move ||
        {
            let end_copy = end.clone();
            loop{
                let mut line = String::new();
                let stdin_ref = std::io::stdin();
                print!("\nEnter your command :\n>");
                std::io::stdout().flush().expect("Cannot write on stdout");
                stdin_ref.read_line(& mut line).expect("Cannot read from stdin");

                match line.trim().to_lowercase().as_str() {
                    "end" =>{ *end.lock().unwrap() = true;
                        println!("{}","\nGoodbye".bold().green());},
                    "pause" =>{
                        *pause.lock().unwrap() = true;
                        println!("{}","\nCAPTURE SNIFFING PAUSED..".bold().yellow());
                        _capturing = false;
                        network_features::print_menu(parameters_cloned.clone(), _capturing);
                    },
                    "resume" =>{
                        *pause.lock().unwrap() = false;
                        println!("{}","\nCAPTURE RESUMED..".bold().green());
                        _capturing = true;
                        network_features::print_menu(parameters_cloned.clone(), _capturing);
                    },
                    _ => {
                        let msg ="Unrecognized command, please check available commands in the menu and try again".red();
                        println!( "\n{}", msg );
                    }
                }
                if *end_copy.lock().unwrap() {break}

            }
        });

    let e = end_copy.clone();
    let p = pause_copy.clone();
    let selected_device = device_list[selected_code].clone();
    match network_features::capture_packet(selected_device, &parameters, e, p){
        Ok(_r) => { }
        Err(_e)=> {
            let msg ="ERROR: pcap is not able to open the capture on the selected device!".red();
            println!( "\n{}", msg );
            panic!("");
        }
    }

    // devo aspettare che il thread del packet sniffing termini in uno stato coerente.
    match _user_command_thread.join()
    {
        Ok(_result) => (),
        Err(_err) => ()
    }
}
