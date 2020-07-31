# Contributing

## Things to Know

**All the things mentioned below will benefit you greatly if your learn them. However, this is not necessary to contribute.**

1. Rust -
   * The concept of ownership and lifetimes.
   * Various data types in Rust - structs, unions, enums, vectors etc.
   * Concurrency features in Rust - threads, locks, smart pointers, atomic reference counters etc.
   * Rust's module system.
   * Few good sources -
     * [Official docs](https://doc.rust-lang.org/book/index.html)
     * [Programming Rust: Fast, Safe Systems Development](https://www.amazon.com/_/dp/1491927283?tag=oreilly20-20)

2. Computer Networking -
   * Various protocols involved like IPv4, IPv6, ARP, TCP, UDP, etc.
   * Packet formats based on the protocol.

3. Concepts of concurrency, threading, synchronisation etc.

## Developer Dependencies

1. Install Rust using [`rustup`](https://www.rust-lang.org/tools/install).
2. [`cargo`](https://doc.rust-lang.org/cargo/guide/index.html) is a command line utility that is part of the Rust toolchain that can be used to install additional tools.
3. Install [`rustfmt`](https://github.com/rust-lang/rustfmt#quick-start) on the stable toolchain. `rustfmt` will be used to format code.

## Developing Process

1. Select an issue to work on.
2. Fork the project.
3. `git clone` the forked version of the project.
4. It is important that you **create another branch** and work on the issue in the new branch. Use `git checkout -b <branch-name>` in the master branch.
5. After writing some code, run `cargo fmt` and `cargo test`.
6. If all tests are passing, push the changes to your remote repository.
7. Use the GitHub website to create a Pull Request and wait for the maintainers to review it.

## Developer Notes

* To build the binary, run `cargo build`. This will place a binary in `target/debug` folder.
* Recommended way to run the binary would be `sudo ./target/debug/rshark`.
* Please run `cargo test` and `cargo fmt` before commiting any code.
* If you run into any problems, please feel free to ask the maintainers or other contributors.
