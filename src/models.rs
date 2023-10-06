use super::constants::{MAX_PORT, MIN_PORT};
use std::net::IpAddr;
use std::str::FromStr;

use dns_lookup::lookup_host;

#[derive(Clone, Debug)]
pub enum IpOrDomain {
    Ip(IpAddr),
    Domain(String),
}

impl IpOrDomain {
    pub fn resolve_to_ip(&self) -> Option<IpAddr> {
        match self {
            IpOrDomain::Ip(ip) => Some(*ip),
            IpOrDomain::Domain(domain) => {
                // Resolve domain name to IP address
                match lookup_host(domain) {
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
        }
    }
}

// Clap uses FromStr to attempt to parse the text provided as args to the cmd
impl FromStr for IpOrDomain {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Check if it's a valid ip address
        if let Ok(ip) = s.parse() {
            Ok(IpOrDomain::Ip(ip))
        } else {
            // Otherwise, treat it as a domain that will then be looked up
            Ok(IpOrDomain::Domain(s.to_string()))
        }
    }
}

#[derive(Clone, Debug)]
pub struct Ports(pub Vec<u32>);

impl FromStr for Ports {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Allow port range format of x-yyyyy
        if s.contains('-') {
            let parts: Vec<&str> = s.split('-').collect();
            if parts.len() != 2 {
                return Err(String::from(
                    "Invalid range format. Expected format: start-end",
                ));
            }

            let start = parts[0].parse::<u32>().map_err(|e| e.to_string())?;
            let end = parts[1].parse::<u32>().map_err(|e| e.to_string())?;

            if end > MAX_PORT {
                return Err(format!(
                    "Invalid port range: start and end must be within the limits of {}-{}",
                    MIN_PORT, MAX_PORT
                ));
            }

            if start >= end {
                return Err(String::from("Invalid range: start must be less than end"));
            }

            Ok(Ports((start..end).collect()))
        } else {
            let list: Result<Vec<u32>, _> = s
                .split_whitespace()
                .map(|p| p.parse::<u32>().map_err(|e| e.to_string()))
                .collect();

            match list {
                Ok(ports) => {
                    for port in ports.clone() {
                        if !(MIN_PORT..MAX_PORT).contains(&port) {
                            return Err(format!(
                        "Invalid port number specified. Port numbers should be in the range: {}-{}",
                        MIN_PORT, MAX_PORT));
                        }
                    }
                    Ok(Ports(ports))
                }
                Err(e) => Err(e),
            }
        }
    }
}
