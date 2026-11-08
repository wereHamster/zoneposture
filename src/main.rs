mod zone;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "zoneposture", about, arg_required_else_help = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Audit all hosts in a DNS zone
    Audit {
        /// Path to the zone file, in standard BIND format
        #[arg(long, value_name = "FILE")]
        zone: PathBuf,
    },
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Audit { zone } => {
            let records = match zone::read_host_records(&zone) {
                Ok(records) => records,
                Err(err) => {
                    eprintln!("error: {}: {err}", zone.display());
                    return ExitCode::FAILURE;
                }
            };

            let name_width = records.iter().map(|r| r.name.len()).max().unwrap_or(0);
            for record in &records {
                println!(
                    "{:name_width$}  {:5}  {}",
                    record.name,
                    record.data.record_type(),
                    record.data
                );
            }

            ExitCode::SUCCESS
        }
    }
}
