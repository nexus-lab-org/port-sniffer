# Port Sniffer

Port Sniffer is a command-line tool built with Rust that helps you find all the open ports on a given host. It uses native OS threads to try all the ports concurrently, making it faster than sequential port scanning tools.

## Installation

You can install Port Sniffer using [Cargo](https://doc.rust-lang.org/cargo/), the Rust package manager. First, make sure you have Rust installed on your system. Then, run the following command:
```sh
cargo install port-sniffer
```


This will download the source code, compile it, and install the `port-sniffer` binary in your system's binary directory (usually `~/.cargo/bin/`).

## Usage

To use Port Sniffer, simply run the `port-sniffer` command followed by the hostname or IP address you want to scan. For example:

```sh
port-sniffer 127.0.0.1
```

This will scan all the ports on `127.0.0.1` and print the open ones to the console.

## License

Port Sniffer is licensed under the [MIT License](LICENSE).
