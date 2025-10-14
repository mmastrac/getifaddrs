use getifaddrs::{getifaddrs, Interface};

pub fn main() {
    let mut last: Vec<Interface> = Vec::default();
    loop {
        let interfaces = getifaddrs().unwrap().collect::<Vec<_>>();
        if interfaces != last {
            println!("Interfaces changed:");
            for interface in &interfaces {
                println!("  {interface:?}");
            }
            last = interfaces;
        }
    }
}
