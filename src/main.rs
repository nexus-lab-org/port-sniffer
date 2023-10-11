#[macro_use]
extern crate log;
extern crate env_logger;

use clap::Parser;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use nexuslab_port_sniffer::constants::{DEFAULT_THREADS, DEFAULT_TIMEOUT, MAX_PORT, MIN_PORT};
use nexuslab_port_sniffer::models::{IpOrDomain, LogLevel, PortRange};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use std::collections::HashSet;

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

    /// Port ranges to be scanned (optional,
    /// if unspecified, all ports will be
    /// scanned). A single port is also
    /// considered a port range.
    #[clap(short = 'p', long, num_args=1..)]
    port_ranges: Option<Vec<PortRange>>,

    /// add a verbose flag
    #[clap(long = "log_level", default_value = "info")]
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
    let mut unique_ports: HashSet<u32> = HashSet::new(); 
    match cli.port_ranges {
        Some(port_ranges) => {
            for port_range in port_ranges {
                unique_ports.extend(port_range.0);
            }
        },
        None => {
            unique_ports.extend(MIN_PORT..MAX_PORT + 1);
        }
    };
    let ports_to_scan: Arc<Vec<u32>> = Arc::new(unique_ports.into_iter().collect());
    let pb: Option<Arc<Mutex<ProgressBar>>> = if cli.log_level != LogLevel::DEBUG {
        let progress_bar = ProgressBar::new(ports_to_scan.len() as u64).with_tab_width(4);
        progress_bar.set_style(
            ProgressStyle::with_template("{bar:50.white/red} {percent}% {msg:.green}").unwrap(),
        );
        Some(Arc::new(Mutex::new(progress_bar)))
    } else {
        None
    };
    debug!("Scanning {} with {:?} threads", ip_addr, cli.threads);
    let (tx, rx) = channel::<u32>();
    let rx = Arc::new(Mutex::new(rx));
    let rx_clone = rx.clone();
    let terminating = Arc::new(AtomicBool::new(false));
    let terminating_clone = terminating.clone();
    let log_level_ctrlc = cli.log_level.clone(); // This might be unnecessary if cli.log_level implements Copy
    ctrlc::set_handler(move || {
        terminating_clone.store(true, Ordering::Relaxed);
        if log_level_ctrlc != LogLevel::DEBUG {
            print!(
                "{}",
                "\nReceived <Ctrl+C> scan halted".red().underline().bold()
            );
            display_results(rx_clone.lock().unwrap().try_iter().collect());
        } else {
            debug!("Received <Ctrl+C> scan halted.");
        }
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
        let pb = pb.clone();
        let ports_scanned = ports_scanned.clone();
        let timeouts_count = timeouts_count.clone();
        let open_ports_count = open_ports_count.clone();
        let terminating_thread = terminating.clone();
        let log_level = cli.log_level.clone();
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
                pb,
                log_level,
            );
        });
        handles.push(handle);
    }
    for handle in handles {
        handle.join().unwrap();
    }
    drop(tx);
    if !terminating.load(Ordering::Relaxed) {
        if let Some(progress_bar) = &pb {
            progress_bar.lock().unwrap().finish();
        }
        if cli.log_level != LogLevel::DEBUG {
            print!("{}", " Scanning Complete - Results ".bold().underline());
            display_results(rx.lock().unwrap().iter().collect());
        } else {
            debug!("Scanning Complete");
        }
    }
}

fn display_results(open_ports: Vec<u32>) {
    println!();
    let mut open = open_ports;
    open.sort();
    if open.is_empty() {
        println!(
            "{}",
            format!("None of the analysed ports were open")
                .bold()
                .dimmed()
        );
    } else {
        for port in open {
            println!("{}", format!("  + Port {} is open", port).blue().bold());
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
    pb: Option<Arc<Mutex<ProgressBar>>>,
    log_level: LogLevel,
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
        if port_index >= ports_to_scan.len() as u32 {
            break;
        }
        let port = ports_to_scan[port_index as usize];
        let address = format!("{}:{}", addr, port);
        let socket_add = address.to_socket_addrs().unwrap().next().unwrap();
        debug!("Scanning port {}", port);
        if TcpStream::connect_timeout(&socket_add, duration).is_ok() {
            tx.send(port).unwrap();
            open_ports_count.fetch_add(1, Ordering::Relaxed);
            if log_level == LogLevel::DEBUG {
                debug!("Port {} is open", port);
            }
        } else {
            timeouts_count.fetch_add(1, Ordering::Relaxed);
            if log_level == LogLevel::DEBUG {
                debug!("Port {} is closed or unreachable", port);
            }
        }
        let scanned = ports_scanned.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some(progress_bar) = &pb {
            if !terminating.load(Ordering::Relaxed) {
                let msg = format!(
                    "\n [*] Scanned Ports: {}/{}\n [*] Open Ports:\t{}\n [*] Closed Ports:  {}",
                    scanned,
                    total_ports,
                    open_ports_count.load(Ordering::Relaxed),
                    timeouts_count.load(Ordering::Relaxed)
                );
                let progress_bar_lock = progress_bar.lock().unwrap();
                progress_bar_lock.set_message(msg);
                progress_bar_lock.inc(1);
            }
        }
        port_index += total_threads;
    }
}
