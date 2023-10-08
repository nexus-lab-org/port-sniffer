#[macro_use]
extern crate log;
extern crate env_logger;

use clap::Parser;
use ctrlc;
use nexuslab_port_sniffer::constants::{DEFAULT_THREADS, DEFAULT_TIMEOUT, MAX_PORT, MIN_PORT};
use nexuslab_port_sniffer::models::{IpOrDomain, Ports, LogLevel};
use std::io::{self, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::Arc;
use std::sync::Mutex;
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
        None => Arc::new((MIN_PORT..=MAX_PORT).collect()),
    };

    debug!("Scanning {} with {:?} threads", ip_addr, cli.threads);

    let (tx, rx) = channel::<u32>();
    let rx = Arc::new(Mutex::new(rx));
    let rx_clone = rx.clone();
    let terminating = Arc::new(AtomicBool::new(false));
    let terminating_clone = terminating.clone();

    ctrlc::set_handler(move || {
        terminating_clone.store(true, Ordering::Relaxed);
        print!("\nReceived <Ctrl+C> scan halted, displaying results...");
        display_results(rx_clone.lock().unwrap().try_iter().collect());
        std::process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    let ports_scanned = Arc::new(AtomicUsize::new(0));
    let timeouts_count = Arc::new(AtomicUsize::new(0));
    let open_ports_count = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();

    for i in 0..cli.threads {
        let tx = tx.clone();
        let ports_to_scan = ports_to_scan.clone();
        let ports_scanned = ports_scanned.clone();
        let timeouts_count = timeouts_count.clone();
        let open_ports_count = open_ports_count.clone();
        let terminating_thread = terminating.clone();
        let handle = thread::spawn(move || {
            scan(
                tx,
                ports_to_scan,
                i,
                ip_addr,
                cli.threads,
                cli.timeout,
                ports_scanned,
                timeouts_count,
                open_ports_count,
                terminating_thread,
            );
        });
        handles.push(handle);
    }
    drop(tx);

    for handle in handles {
        handle.join().unwrap();
    }

    display_results(rx.lock().unwrap().iter().collect());
}

fn display_results(open_ports: Vec<u32>) {
    println!();
    let mut open = open_ports;
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
    ports_scanned: Arc<AtomicUsize>,
    timeouts_count: Arc<AtomicUsize>,
    open_ports_count: Arc<AtomicUsize>,
    terminating: Arc<AtomicBool>,
) {
    // This function scans ports at positions
    // start_port_index,
    // start_port_index + threads,
    // start_port_index + 2 * threads ..
    // in ports_to_scan

    let duration = Duration::new(timeout, 0);
    let mut port_index = start_port_index;
    let total_ports = ports_to_scan.len();
    loop {
        if port_index >= total_ports as u32 {
            break;
        }
        let port = ports_to_scan[port_index as usize];
        let address = format!("{}:{}", addr, port);
        let socket_add = address.to_socket_addrs().unwrap().next().unwrap();
        debug!("Scanning port {}", port);
        if TcpStream::connect_timeout(&socket_add, duration).is_ok() {
            tx.send(port).unwrap();
            open_ports_count.fetch_add(1, Ordering::Relaxed);
        } else {
            timeouts_count.fetch_add(1, Ordering::Relaxed);
        }

        let scanned = ports_scanned.fetch_add(1, Ordering::Relaxed) + 1;
        let progress = (scanned as f64 / total_ports as f64) * 100.0;

        if !terminating.load(Ordering::Relaxed) {
            print!(
                "\rProgress: {:.2}% (Scanned Ports: {}/{}, Open Ports: {}, Closed Ports: {})",
                progress,
                scanned,
                total_ports,
                open_ports_count.load(Ordering::Relaxed),
                timeouts_count.load(Ordering::Relaxed)
            );
        }

        io::stdout().flush().unwrap();

        port_index += total_threads;
    }
}
