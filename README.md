# Rshark

![CI](https://github.com/pmk21/rshark/workflows/CI/badge.svg)

A terminal UI based packet monitoring tool written in Rust.

![Example UI](images/example.png)

## Installation

**Works only on Unix-like OSes for now.**

**Prerequisites**: `rust` and `cargo`.

1. `git clone` this repository.
2. `cd rshark`
3. `cargo install --path .` should install the binary. Make sure `$HOME/.cargo/bin` is in your `$PATH` variable.

## Usage

```output
USAGE:
    rshark [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -i, --interface <INTERFACE>    Sets network interface to capture packets on
```

**Note that since `rshark` sniffs network packets, it requires root privileges**

### How to Run
1. Find a network device to monitor. To find one using OSX:

`networksetup -listallhardwareports`

2. Run the binary on a device, e.g. WiFi, must run as root.
`sudo cargo run -- -i en0`

## Support

Please open an issue and we'll try to help.

## Roadmap

* [x] Add code formatting check in CI.
* [x] Add `clippy` checks for better and idiomatic Rust code.
* [ ] Maybe a separate thread for running a timer, to get time of arrival of packets.
* [ ] Use the `insta` crate for snapshot testing(or UI testing).
* [ ] Gracefully handle errors instead of just panicking.
* [ ] Maybe add a logging functionality for catching errors.

## Contributing

Please check out the contribution guide [here](CONTRIBUTING.md).

## Authors and Acknowledgement

This project is running thanks to all the contributors.

## License

Apache License 2.0
