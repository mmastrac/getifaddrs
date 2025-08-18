use getifaddrs::{getifaddrs, Address, Interfaces};

fn main() {
    let interfaces = getifaddrs().unwrap().collect::<Interfaces>();
    for (index, interface) in interfaces {
        println!("{}", interface.name);
        println!("  Flags: {:?}", interface.flags);
        for address in &interface.address {
            match address {
                Address::V4(..) | Address::V6(..) => {
                    println!(
                        "  IP{:?}: {:?}",
                        address.family(),
                        address.ip_addr().unwrap()
                    );
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
                        addr.iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join(":")
                    );
                }
            }
        }
        println!("  Index: {}", index);
        println!();
    }
}
