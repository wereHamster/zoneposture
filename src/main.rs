use clap::Parser;

#[derive(Parser)]
#[command(name = "zoneposture", about)]
struct Cli {}

fn main() {
    Cli::parse();
}
