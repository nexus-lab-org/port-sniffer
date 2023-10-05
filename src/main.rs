mod constants;

use clap::Parser;
use dns_lookup::lookup_host;
use std::io::{self, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{channel, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use constants::{DEFAULT_THREADS, DEFAULT_TIMEOUT, MIN_PORT, MAX_PORT};


#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// IP address
    #[clap(short = 'i', long = "ip")]
    ip: Option<IpAddr>,

    /// Number of threads
    #[clap(short = 't', long = "threads", default_value_t = DEFAULT_THREADS)]
    threads: u32,

    /// Domain name
    #[clap(long)]
    domain: Option<String>,

    /// Expected Timeout over each TCP connect
    #[clap(long, default_value_t = DEFAULT_TIMEOUT)]
    timeout: u64,

    /// Ports to be scanned (optional,
    /// if unspecified, all ports will be
    /// scanned)
    #[clap(long, num_args=1..)]
    ports: Option<Vec<u32>>,
}

fn main() {
    let cli = Cli::parse();

    let ip_addr = match (&cli.ip, &cli.domain) {
        (Some(ip), _) => Some(*ip),
        (_, Some(domain)) => {
            match hostname_to_ip(domain) {
                Ok(ips) => {
                    let mut resolved_ip_addr: Option<IpAddr> = None;
                    for ip in ips {
                        if let IpAddr::V4(_ipv4) = ip {
                            // here ipv4 is of type IpV4Addr
                            resolved_ip_addr = Some(ip);
                            break;
                        }
                    }
                    resolved_ip_addr
                }

                Err(e) => {
                    eprintln!("Error getting the IP: {}", e);
                    None
                }
            }
        }
        _ => {
            eprintln!("Either 'ip' or 'domain' must be provided");
            return; // Print error and return from the function
        }
    };

    let ip_addr = match ip_addr {
        Some(ip) => ip,
        None => {
            return; // Exit
        }
    };

    // The ports to scan
    let ports_to_scan: Arc<Vec<u32>> = match &cli.ports {
        Some(ports) => {
            // Some ports have been specified
            // on the command line
            let mut valid_ports: Vec<u32> = Vec::new();
            for port in ports {
                if *port < MIN_PORT || *port > MAX_PORT {
                    // Invalid port number
                    eprintln!(
                        "Invalid port number specified. Port numbers should be in the range: {}-{}",
                        MIN_PORT, MAX_PORT
                    );
                    return;
                } else {
                    valid_ports.push(*port);
                }
            }
            Arc::new(valid_ports)
        }
        None => {
            // No ports specified, scan all
            Arc::new((MIN_PORT..MAX_PORT + 1).collect())
        }
    };

    println!("Scanning {} with {:?} threads", ip_addr, cli.threads);

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

    println!();
    open.sort();

    if open.is_empty() {
        println!("None of the analysed ports were open");
    } else {
        for port in open {
            println!("{} is open", port);
        }
    }
}

fn hostname_to_ip(hostname: &str) -> Result<Vec<IpAddr>, std::io::Error> {
    lookup_host(hostname)
}

fn scan(
    tx: Sender<u32>,
    ports_to_scan: Arc<Vec<u32>>,
    start_port_index: u32,
    addr: IpAddr,
    threads: u32,
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
        if TcpStream::connect_timeout(&socket_add, duration).is_ok() {
            print!(".");
            io::stdout().flush().unwrap();
            tx.send(port).unwrap();
        }
        port_index += threads;
    }
}
