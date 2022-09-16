use clap::{Parser, Args, Subcommand};

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct InputArgs {
    /// Name of the person to greet
    pub device_number: usize,

    /// Number of times to greet
    pub fileName: String,

    /// Show all the device available
    #[clap(short, long)]
    pub show: bool,
}
// i commenti con /// apparirano sull'interfaccia video all'utente!