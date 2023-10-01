use std::net::{IpAddr, TcpStream};
use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::io::{self, Write};
use clap::Parser;
use std::net::ToSocketAddrs;
use std::time::Duration;

const MAX_PORT: u32 = 65535;

#[derive(Parser, Clone, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short='i', long="ip")]
    ip: Option<IpAddr>,
    #[arg(short='d', long="domain")]
    domain: Option<String>,
    #[arg(short='t', long="threads", default_value_t = 10)]
    threads: u32,
}


impl Cli {
    fn get_socket_address(&self) -> Result<std::net::SocketAddr, std::io::Error> {
        if let Some(ip) = self.ip {
            Ok((ip, 0).into())
        } else if let Some(domain) = &self.domain {
            let mut addrs = domain.to_socket_addrs()?;
            if let Some(addr) = addrs.next() {
                Ok(addr)
            } else {
                Err(std::io::Error::new(std::io::ErrorKind::Other, "No address found for domain"))
            }
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::Other, "Either IP or domain name must be provided"))
        }
    }
}


fn main() {
    let cli = Cli::parse();

    let ip_address = match cli.get_socket_address() {
        Ok(socket_addr) => socket_addr.ip(),
        Err(e) => {
            println!("Error: {}", e);
            return;
        }
    };

    println!("Scanning {} with {:?} threads", ip_address, cli.threads);
    let (tx, rx) = channel::<u32>();

    for i in 0..cli.threads {
        let tx = tx.clone();
        thread::spawn(move || {
            scan(tx, i, ip_address, cli.threads);
        });
    }
    drop(tx);
    let mut open: Vec<u32> = rx.iter().collect();

    println!("");
    open.sort();
    for port in open {
        println!("{} is open", port);
    }
}

fn scan(tx: Sender<u32>, start_port: u32, ip: IpAddr, threads: u32) {
    let mut port: u32 = start_port + 1;
    let duration = Duration::new(2, 0);
    loop {
        let address = format!("{}:{}", ip, port);
        let socket_addr = address.to_socket_addrs().unwrap().next().unwrap();
        // debug!("Connecting: {}", address);
        match TcpStream::connect_timeout(&socket_addr, duration) {
            Ok(_) => {
                print!(".");
                io::stdout().flush().unwrap();
                tx.send(port).unwrap();
            }
            Err(_) => {}
        }
        if (MAX_PORT - port) <= threads {
            break;
        }
        port += threads;
    }
}
