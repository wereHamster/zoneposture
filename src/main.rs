mod email;
mod finding;
mod zone;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::finding::Finding;
use crate::zone::Zone;

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
            let zone = match Zone::read(&zone) {
                Ok(zone) => zone,
                Err(err) => {
                    eprintln!("error: {}: {err}", zone.display());
                    return ExitCode::FAILURE;
                }
            };

            print_hosts(&zone);
            println!();
            print_findings("Email", &email::audit(&zone));

            ExitCode::SUCCESS
        }
    }
}

fn print_hosts(zone: &Zone) {
    let hosts: Vec<_> = zone.records.iter().filter(|r| r.data.is_host()).collect();
    let name_width = hosts.iter().map(|r| r.name.len()).max().unwrap_or(0);

    println!("Hosts");
    for record in hosts {
        println!(
            "  {:name_width$}  {:5}  {}",
            record.name,
            record.data.record_type(),
            record.data
        );
    }
}

fn print_findings(title: &str, findings: &[Finding]) {
    let check_width = findings.iter().map(|f| f.check.len()).max().unwrap_or(0);

    println!("{title}");
    let mut subject = None;
    for finding in findings {
        if subject != Some(&finding.subject) {
            subject = Some(&finding.subject);
            println!("  {}", finding.subject);
        }
        println!(
            "    {}  {:check_width$}  {}",
            finding.severity, finding.check, finding.message
        );
    }
}
