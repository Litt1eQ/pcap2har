use clap::Parser;
use pcap2har::convert_pcap_to_har;
use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(name = "pcap2har")]
#[command(about = "Convert PCAP files to HAR format")]
#[command(version)]
struct Cli {
    /// Input PCAP file
    #[arg(value_name = "PCAP_FILE")]
    input: PathBuf,

    /// Output HAR file (stdout if not specified)
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();

    let har = match convert_pcap_to_har(cli.input.to_str().unwrap_or_default()) {
        Ok(har) => har,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };

    let json = match serde_json::to_string_pretty(&har) {
        Ok(json) => json,
        Err(e) => {
            eprintln!("Error serializing HAR: {}", e);
            process::exit(1);
        }
    };

    let result: Result<(), String> = match &cli.output {
        Some(path) => {
            File::create(path)
                .and_then(|mut file| file.write_all(json.as_bytes()))
                .map_err(|e| e.to_string())
        }
        None => io::stdout()
            .write_all(json.as_bytes())
            .map_err(|e| e.to_string()),
    };

    if let Err(e) = result {
        eprintln!("Error writing output: {}", e);
        process::exit(1);
    }
}
