use super::constants::{MAX_PORT, MIN_PORT};
use std::net::IpAddr;
use std::str::FromStr;

use clap::ValueEnum;
use dns_lookup::lookup_host;

#[derive(Clone, Debug, PartialEq, ValueEnum)]
pub enum LogLevel {
    INFO,
    DEBUG,
}

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

#[derive(Clone, Debug, PartialEq)]

// A PortRange maybe specified on the
// command line as a single port number
// say a, where a is a valid port number
// or maybe specified on the command
// line as a-b where a and b are valid 
// port numbers. The inner parameter
// stores all the ports represented by 
// the range.
pub struct PortRange(pub Vec<u32>);

impl FromStr for PortRange {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('-') {

            // Port range is of the form a-b
            let parts: Vec<&str> = s.split('-').collect();
            if parts.len() != 2 {
                return Err(String::from(
                    "Invalid range format: Expected format: start-end",
                ));
            }

            let start = parts[0].parse::<u32>().map_err(|e| e.to_string())?;
            let end = parts[1].parse::<u32>().map_err(|e| e.to_string())?;

            if end > MAX_PORT {
                return Err(format!(
                    "Invalid port range: start and end port numbers must be in the range {}-{}",
                    MIN_PORT, MAX_PORT
                ));
            }

            if start >= end {
                return Err(String::from(
                    "Invalid port range: start port number must be less than the end port number",
                ));
            }

            Ok(PortRange((start..end + 1).collect()))
        } else {

            // The port range consists of a single port
            // number.
            match s.parse::<u32>() {
                Ok(port) => {
                    if (MIN_PORT..MAX_PORT + 1).contains(&port) {
                        Ok(PortRange(vec![port]))
                    }
                    else {
                        Err(format!(
                            "Invalid port number: Port numbers should be in the range {}-{}",
                            MIN_PORT, MAX_PORT
                        ))
                    }
                }
                Err(_) => {
                    Err(String :: from("Invalid port number"))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn test_from_str() {
        // // Test valid port list
        // let input = "80 443 8080";
        // let expected_output = Ports(vec![80, 443, 8080]);
        // assert_eq!(Ports::from_str(input).unwrap(), expected_output);

        // Test valid port range
        let input = "1000-2000";
        let expected_output = PortRange((1000..2001).collect());
        assert_eq!(PortRange::from_str(input).unwrap(), expected_output);

        // Test invalid port range
        let input = "2000-1000";
        let expected_error = "Invalid port range: start port number must be less than the end port number";
        assert_eq!(PortRange::from_str(input).unwrap_err(), expected_error);

        // Test invalid port number
        let input = "65536";
        let expected_error =
            format!("Invalid port number: Port numbers should be in the range {}-{}", MIN_PORT, MAX_PORT);
        assert_eq!(PortRange::from_str(input).unwrap_err(), expected_error);

        // Test invalid range format
        let input = "1000-2000-3000";
        let expected_error = "Invalid range format: Expected format: start-end";
        assert_eq!(PortRange::from_str(input).unwrap_err(), expected_error);

        // Test invalid port range
        let input = "65535-65536";
        let expected_error =
            format!("Invalid port range: start and end port numbers must be in the range {}-{}",
            MIN_PORT, MAX_PORT);
        assert_eq!(PortRange::from_str(input).unwrap_err(), expected_error);
    }

    #[test]
    fn test_resolve_to_ip() {
        // Test IP address
        let input = IpOrDomain::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        let expected_output = Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(input.resolve_to_ip(), expected_output);

        // Test domain name with IPv4 address
        let input = IpOrDomain::Domain("example.com".to_string());
        let expected_output = Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(input.resolve_to_ip(), expected_output);

        // Test invalid domain name
        let input = IpOrDomain::Domain("invalid-domain-name".to_string());
        let expected_output = None;
        assert_eq!(input.resolve_to_ip(), expected_output);
    }
}
