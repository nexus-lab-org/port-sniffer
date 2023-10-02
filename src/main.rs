use clap::Parser;
use dns_lookup::lookup_host;
use std::io::{self, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::time::Duration;

const MAX_PORT: u32 = 65535;
const DEFAULT_TIMEOUT: u32 = 2;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// IP address
    #[clap(short = 'i', long = "ip")]
    ip: Option<IpAddr>,

    /// Number of threads
    #[clap(short = 't', long = "threads", default_value_t = DEFAULT_TIMEOUT)]
    threads: u32,

    /// Domain name
    #[clap(long)]
    domain: Option<String>,

    // Expected Timeout over each TCP connect
    #[clap(long, default_value = "10")]
    timeout: u64,
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
            eprintln!("Either 'ip' or 'domain' must be provided.");
            return; // Print error and return from the function
        }
    };

    let ip_addr = match ip_addr {
        Some(ip) => ip,
        None => {
            return; // Exit
        }
    };

    println!("Scanning {} with {:?} threads", ip_addr, cli.threads);
    let (tx, rx) = channel::<u32>();

    for i in 0..cli.threads {
        let tx = tx.clone();
        thread::spawn(move || {
            scan(tx, i, ip_addr, cli.threads, cli.timeout);
        });
    }
    drop(tx);
    let mut open: Vec<u32> = rx.iter().collect();

    println!();
    open.sort();
    for port in open {
        println!("{} is open", port);
    }
}

fn hostname_to_ip(hostname: &str) -> Result<Vec<IpAddr>, std::io::Error> {
    lookup_host(hostname)
}

fn scan(tx: Sender<u32>, start_port: u32, addr: IpAddr, threads: u32, timeout: u64) {
    let mut port: u32 = start_port + 1;
    let duration = Duration::new(timeout, 0);
    loop {
        let address = format!("{}:{}", addr, port);
        let socket_add = address.to_socket_addrs().unwrap().next().unwrap();
        if TcpStream::connect_timeout(&socket_add, duration).is_ok() {
            print!(".");
            io::stdout().flush().unwrap();
            tx.send(port).unwrap();
        }

        if (MAX_PORT - port) <= threads {
            break;
        }
        port += threads;
    }
}
