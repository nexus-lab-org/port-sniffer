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
