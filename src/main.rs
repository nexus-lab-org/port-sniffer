#[macro_use]
extern crate log;
extern crate env_logger;

use clap::Parser;
use nexuslab_port_sniffer::constants::{DEFAULT_THREADS, DEFAULT_TIMEOUT, MAX_PORT, MIN_PORT};
use nexuslab_port_sniffer::models::{IpOrDomain, Ports, LogLevel};
use std::io::{self, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{channel, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// IP address or domain name. Domain name will be looked up and resolved to ip
    #[clap(index = 1)]
    ip_or_domain: IpOrDomain,

    /// Number of threads
    #[clap(short = 't', long = "threads", default_value_t = DEFAULT_THREADS)]
    threads: u32,

    /// Expected Timeout over each TCP connect
    #[clap(long, default_value_t = DEFAULT_TIMEOUT)]
    timeout: u64,

    /// Ports to be scanned (optional,
    /// if unspecified, all ports will be
    /// scanned)
    #[clap(short = 'p', long, num_args=1..)]
    ports: Option<Ports>,

    /// add a verbose flag
    #[clap(long="log_level", default_value = "info")]
    log_level: LogLevel,
}

fn main() {
    let cli = Cli::parse();

    env_logger::Builder::new()
        .filter_level(match cli.log_level {
            LogLevel::INFO => log::LevelFilter::Info,
            LogLevel::DEBUG => log::LevelFilter::Debug,
        })
        .init();
    
    let ip_addr = match cli.ip_or_domain.resolve_to_ip() {
        Some(ip_addr) => ip_addr,
        None => {
            error!("Invalid domain or ip provided, please provide a valid one");
            return;
        }
    };
    debug!("Resolved to ip: {}", ip_addr);
    let ports_to_scan: Arc<Vec<u32>> = match cli.ports {
        Some(ports) => Arc::new(ports.0),
        None => Arc::new((MIN_PORT..MAX_PORT + 1).collect()),
    };

    debug!("Scanning {} with {:?} threads", ip_addr, cli.threads);

    let (tx, rx) = channel::<u32>();

    for i in 0..cli.threads {
        let tx = tx.clone();
        let ports_to_scan = ports_to_scan.clone();
        thread::spawn(move || {
            scan(tx, ports_to_scan, i, ip_addr, cli.threads, cli.timeout);
        });
    }
    drop(tx);
    let mut open: Vec<u32> = rx.iter().collect();

    println!("");
    open.sort();

    if open.is_empty() {
        info!("None of the analysed ports were open");
    } else {
        for port in open {
            println!("{} is open", port);
        }
    }
}

fn scan(
    tx: Sender<u32>,
    ports_to_scan: Arc<Vec<u32>>,
    start_port_index: u32,
    addr: IpAddr,
    total_threads: u32,
    timeout: u64,
) {
    // This function scans ports at positions
    // start_port_index,
    // start_port_index + threads,
    // start_port_index + 2 * threads ..
    // in ports_to_scan

    let duration = Duration::new(timeout, 0);
    let mut port_index = start_port_index;
    loop {
        if port_index >= ports_to_scan.len() as u32 {
            break;
        }
        let port = ports_to_scan[port_index as usize];
        let address = format!("{}:{}", addr, port);
        let socket_add = address.to_socket_addrs().unwrap().next().unwrap();
        debug!("Scanning port {}", port);
        if TcpStream::connect_timeout(&socket_add, duration).is_ok() {
            print!(".");
            io::stdout().flush().unwrap();
            tx.send(port).unwrap();
        }
        port_index += total_threads;
    }
}
