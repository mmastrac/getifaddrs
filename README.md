# getifaddrs

[![Documentation](https://docs.rs/getifaddrs/badge.svg)](https://docs.rs/getifaddrs)
[![Crates.io](https://img.shields.io/crates/v/getifaddrs.svg)](https://crates.io/crates/getifaddrs)
[![Rust](https://github.com/mmastrac/getifaddrs/actions/workflows/rust.yml/badge.svg)](https://github.com/mmastrac/getifaddrs/actions/workflows/rust.yml)

A cross-platform library for retrieving network interface information.

This crate provides a simple and consistent API for querying network interface details
across different operating systems. It supports Unix-like systems (Linux, macOS, *BSD)
and Windows.

## Features

- Retrieve network interface information (name, IP address, netmask, flags, mac
  address,etc.)
- Filter interfaces based on various criteria (loopback, IPv4/IPv6, name, index)
- Cross-platform support (Unix-like systems and Windows)
- Provides a cross-platform implementation of
  [`if_indextoname`](https://docs.rs/getifaddrs/latest/getifaddrs/fn.if_indextoname.html)
  and
  [`if_nametoindex`](https://docs.rs/getifaddrs/latest/getifaddrs/fn.if_nametoindex.html)

## License

This project is licensed under the
[MIT](https://github.com/mmastrac/getifaddrs/blob/master/LICENSE-MIT) or
[APACHE](https://github.com/mmastrac/getifaddrs/blob/master/LICENSE-APACHE)
license.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
getifaddrs = "0.4"
```

## Example

Iterate over all network interfaces:

```rust
use getifaddrs::{getifaddrs, InterfaceFlags};

fn main() -> std::io::Result<()> {
    for interface in getifaddrs()? {
        println!("Interface: {}", interface.name);
        if let Some(ip_addr) = interface.address.ip_addr() {
            println!("  IP Address: {}", ip_addr);
        }
        if let Some(mac_addr) = interface.address.mac_addr() {
            println!("  MAC Address: {:?}", mac_addr);
        }
        if let Some(netmask) = interface.address.netmask() {
            println!("  Netmask: {}", netmask);
        }
        if let Some(associated_address) = interface.address.associated_address() {
            println!("  Associated Address: {}", associated_address);
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

Collect all network interfaces and print the associated items in the rough style
of the `ifconfig` command:

```rust
use getifaddrs::{getifaddrs, Address, Interfaces};

let interfaces = getifaddrs().unwrap().collect::<Interfaces>();
for (index, interface) in interfaces {
    println!("{}", interface.name);
    println!("  Flags: {:?}", interface.flags);
    for address in &interface.address {
        match address {
            Address::V4(..) | Address::V6(..) => {
                println!("  IP{:?}: {:?}", address.family(), address.ip_addr().unwrap());
                if let Some(netmask) = address.netmask() {
                    println!("    Netmask: {}", netmask);
                }
                #[cfg(not(windows))]
                if let Some(associated_address) = address.associated_address() {
                    println!("    Associated: {}", associated_address);
                }
            }
            Address::Mac(addr) => {
                println!(
                    "  Ether: {}",
                    addr.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")
                );
            }
        }
    }
    println!("  Index: {}", index);
    println!();
}
```
