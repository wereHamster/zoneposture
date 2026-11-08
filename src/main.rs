mod caa;
mod email;
mod finding;
mod headers;
mod http;
mod security_txt;
mod web;
mod zone;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use jiff::Timestamp;

use crate::finding::Finding;
use crate::http::Clients;
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

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Audit { zone } => {
            let zone = match Zone::read(&zone) {
                Ok(zone) => zone,
                Err(err) => {
                    eprintln!("error: {}: {err}", zone.display());
                    return ExitCode::FAILURE;
                }
            };
            let clients = match Clients::new() {
                Ok(clients) => clients,
                Err(err) => {
                    eprintln!("error: cannot create HTTP client: {err}");
                    return ExitCode::FAILURE;
                }
            };

            print_hosts(&zone);
            println!();
            print_findings("Email", &email::audit(&zone));
            println!();
            print_findings("TLS", &caa::audit(&zone));

            let web = web::audit(&clients, &zone, Timestamp::now()).await;
            println!();
            print_findings("HTTPS", &web.https);
            println!();
            print_findings("Security headers", &web.headers);
            println!();
            print_findings("Vulnerability disclosure", &web.disclosure);

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
