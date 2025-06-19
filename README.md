# getifaddrs

[![Documentation](https://docs.rs/getifaddrs/badge.svg)](https://docs.rs/getifaddrs)
[![Crates.io](https://img.shields.io/crates/v/getifaddrs.svg)](https://crates.io/crates/getifaddrs)
[![Rust](https://github.com/mmastrac/getifaddrs/actions/workflows/rust.yml/badge.svg)](https://github.com/mmastrac/getifaddrs/actions/workflows/rust.yml)

A cross-platform library for retrieving network interface information.

This crate provides a simple and consistent API for querying network interface details
across different operating systems. It supports Unix-like systems (Linux, macOS, *BSD)
and Windows.

## Features

- Retrieve network interface information (name, IP address, netmask, flags, etc.)
- Filter interfaces based on various criteria (loopback, IPv4/IPv6, name, index)
- Cross-platform support (Unix-like systems and Windows)
- Provides a cross-platform implementation of [`if_indextoname`](https://docs.rs/getifaddrs/latest/getifaddrs/fn.if_indextoname.html) and [`if_nametoindex`](https://docs.rs/getifaddrs/latest/getifaddrs/fn.if_nametoindex.html)

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
getifaddrs = "0.1"
```

## Example

```rust
use getifaddrs::{getifaddrs, InterfaceFlags};

fn main() -> std::io::Result<()> {
    for interface in getifaddrs()? {
        println!("Interface: {}", interface.name);
        println!("  Address: {}", interface.address);
        if let Some(netmask) = interface.netmask {
            println!("  Netmask: {}", netmask);
        }
        println!("  Flags: {:?}", interface.flags);
        if interface.flags.contains(InterfaceFlags::UP) {
            println!("  Status: Up");
        } else {
            println!("  Status: Down");
        }
        println!();
    }
    Ok(())
}
```

## License

This project is licensed under the [MIT](https://github.com/mmastrac/getifaddrs/blob/master/LICENSE-MIT) or [APACHE](https://github.com/mmastrac/getifaddrs/blob/master/LICENSE-APACHE) license.
