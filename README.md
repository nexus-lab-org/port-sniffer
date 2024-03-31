# Port Sniffer

Port Sniffer is a command-line tool built with Rust that helps you find all the open ports on a given host. It uses native OS threads to try all the ports concurrently, making it faster than sequential port scanning tools.

## Installation

You can install Port Sniffer using [Cargo](https://doc.rust-lang.org/cargo/), the Rust package manager. First, make sure you have Rust installed on your system. Then, run the following command:

```sh
cargo install nexuslab_port_sniffer --name port_sniffer
```

This will download the source code, compile it, and install the `port-sniffer` binary in your system's binary directory (usually `~/.cargo/bin/`).

## Usage

To use Port Sniffer, simply run the `port_sniffer` command followed by the hostname or IP address you want to scan.

`port_sniffer [OPTIONS] <IP_OR_DOMAIN>`

### Options

| Option            | Short | Long          | Description        | Possible values                                                                                             | Default |
| ----------------- | ----- | ------------- | ------------------ | ----------------------------------------------------------------------------------------------------------- | ------- |
| Number of threads | `-t`  | `--threads`   | Number of threads  | Any natural number                                                                                          | `10`    |
| Timeout           |       | `--timeout`   | Timeout in seconds | Any positive number                                                                                         | `2`     |
| Ports             | `-p`  | `--ports`     | Ports to scan      | A hostname to resolve or whitespace-separated list or dash-separated (`U+2010`) range of valid port numbers | All     |
| Log level         |       | `--log_level` | Log level          | `info` or `debug`                                                                                           | `info`  |

### Flags

| Flag    | Short | Long        | Description                                   |
| ------- | ----- | ----------- | --------------------------------------------- |
| Bare    | `-b`  | `--bare`    | Output plain port numbers (newline-separated) |
| Help    | `-h`  | `--help`    | Print help                                    |
| Version | `-V`  | `--version` | Print version                                 |

### Examples

For example:

```sh
port-sniffer 127.0.0.1
```

This will scan all the ports on `127.0.0.1` and print the open ones to the console.

## Contributing

Guidelines for contributing can be found [here](CONTRIBUTING.md).

1. Fork the repository. ([What's that?](https://help.github.com/articles/fork-a-repo/))
2. [Clone](https://help.github.com/articles/cloning-a-repository/) the forked repository locally with [`git`](https://git-scm.com/).

    ```sh
    git clone https://github.com/nexus-lab-org/port-sniffer

    # or use GitHub's CLI (https://cli.github.com/)
    gh repo clone nexus-lab-org/port-sniffer
    ```

3. Create a new branch for your changes.

    ```sh
    git checkout -b my-new-branch
    ```

4. Make your changes with your favourite editor.
5. Commit your changes.

    ```sh
    git commit -m "Make Port Sniffer better than ever!"
    ```

6. Push your changes to your forked repository.

    ```sh
    git push origin my-new-branch
    ```

7. Open a pull request and wait for us to review and merge it. ([What's that?](https://help.github.com/articles/about-pull-requests/))

## License

Port Sniffer is licensed under the MIT License.
