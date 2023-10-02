use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::io::{self, Write};
use clap::Parser;
use std::time::Duration;

const MAX_PORT: u32 = 65535;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short='i', long="ip")]
    ip: IpAddr,
    #[arg(short='t', long="threads", default_value_t = 10)]
    threads: u32,
}

fn main() {
    let cli = Cli::parse();
    println!("Scanning {} with {:?} threads", cli.ip, cli.threads);
    let (tx, rx) = channel::<u32>();

    for i in 0..cli.threads {
        let tx = tx.clone();
        thread::spawn(move || {
            scan(tx, i, cli.ip, cli.threads);
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

fn scan(tx: Sender<u32>, start_port: u32, addr: IpAddr, threads: u32) {
    let mut port: u32 = start_port + 1;
    let duration = Duration::new(10, 0);
    loop {
        let address = format!("{}:{}", addr, port);
        let socket_add = address.to_socket_addrs().unwrap().next().unwrap();
        match TcpStream::connect_timeout(&socket_add, duration) {
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
