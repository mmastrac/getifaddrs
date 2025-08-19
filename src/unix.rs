use crate::Address;

use super::{
    AddressFamily, Interface, InterfaceFilter, InterfaceFilterCriteria, InterfaceFlags,
    InterfaceIndex, NetworkAddress,
};
use std::ffi::CStr;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct InterfaceIterator {
    ifaddrs: *mut libc::ifaddrs,
    current: *mut libc::ifaddrs,
    filter: InterfaceFilter,
}

impl InterfaceIterator {
    pub fn new(filter: InterfaceFilter) -> Result<Self, io::Error> {
        let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
        let result = unsafe { libc::getifaddrs(&mut ifaddrs) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(InterfaceIterator {
            ifaddrs,
            current: ifaddrs,
            filter,
        })
    }
}

impl Iterator for InterfaceIterator {
    type Item = Interface;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.current.is_null() {
            let ifaddr = unsafe { &*self.current };
            self.current = ifaddr.ifa_next;
            let Some(addr) = (unsafe { ifaddr.ifa_addr.as_ref() }) else {
                continue;
            };

            let family = match addr.sa_family as _ {
                libc::AF_INET => AddressFamily::V4,
                libc::AF_INET6 => AddressFamily::V6,
                #[cfg(any(
                    target_vendor = "apple",
                    target_os = "freebsd",
                    target_os = "openbsd",
                    target_os = "netbsd"
                ))]
                libc::AF_LINK => AddressFamily::Mac,
                #[cfg(any(target_os = "linux", target_os = "android"))]
                libc::AF_PACKET => AddressFamily::Mac,
                _ => continue,
            };

            if !self.filter.family_filter(family) {
                continue;
            }

            if let Some(InterfaceFilterCriteria::Name(name)) = &self.filter.criteria {
                let ifname = unsafe { CStr::from_ptr(ifaddr.ifa_name) };
                if !name.as_bytes().eq(ifname.to_bytes()) {
                    continue;
                }
            }

            let flags = {
                let mut flags = InterfaceFlags::empty();
                // Platforms have varying size for ifa_flags, so just work in usize
                let raw_flags = ifaddr.ifa_flags as usize;
                if raw_flags & (libc::IFF_UP as usize) != 0 {
                    flags |= InterfaceFlags::UP;
                }
                if raw_flags & (libc::IFF_RUNNING as usize) != 0 {
                    flags |= InterfaceFlags::RUNNING;
                }
                if raw_flags & (libc::IFF_LOOPBACK as usize) != 0 {
                    flags |= InterfaceFlags::LOOPBACK;
                }
                if raw_flags & (libc::IFF_POINTOPOINT as usize) != 0 {
                    flags |= InterfaceFlags::POINTTOPOINT;
                }
                if raw_flags & (libc::IFF_BROADCAST as usize) != 0 {
                    flags |= InterfaceFlags::BROADCAST;
                }
                if raw_flags & (libc::IFF_MULTICAST as usize) != 0 {
                    flags |= InterfaceFlags::MULTICAST;
                }
                flags
            };

            if let Some(InterfaceFilterCriteria::Loopback) = &self.filter.criteria {
                if !flags.contains(InterfaceFlags::LOOPBACK) {
                    continue;
                }
            }

            let index = unsafe {
                let index = libc::if_nametoindex(ifaddr.ifa_name);
                if index != 0 {
                    Some(index as InterfaceIndex)
                } else {
                    None
                }
            };

            if let Some(InterfaceFilterCriteria::Index(filter_index)) = &self.filter.criteria {
                if index != Some(*filter_index) {
                    continue;
                }
            }

            let name = unsafe { CStr::from_ptr(ifaddr.ifa_name) }
                .to_string_lossy()
                .into_owned();

            let address = match family {
                AddressFamily::V4 | AddressFamily::V6 => {
                    let address = match unsafe { sockaddr_to_ipaddr(addr) } {
                        Ok(addr) => addr,
                        Err(_) => continue, // Skip invalid address families
                    };

                    let netmask = unsafe {
                        ifaddr
                            .ifa_netmask
                            .as_ref()
                            .and_then(|sa| sockaddr_to_ipaddr(sa).ok())
                    };

                    // https://docs.rs/libc/latest/aarch64-unknown-linux-gnu/libc/struct.ifaddrs.html
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    let associated_address = unsafe {
                        ifaddr
                            .ifa_ifu
                            .as_ref()
                            .and_then(|sa| sockaddr_to_ipaddr(sa).ok())
                    };

                    // https://docs.rs/libc/latest/aarch64-unknown-openbsd/libc/struct.ifaddrs.html
                    #[cfg(not(any(target_os = "linux", target_os = "android")))]
                    let associated_address = unsafe {
                        ifaddr
                            .ifa_dstaddr
                            .as_ref()
                            .and_then(|sa| sockaddr_to_ipaddr(sa).ok())
                    };

                    match family {
                        AddressFamily::V4 => {
                            let IpAddr::V4(address) = address else {
                                continue;
                            };
                            Address::V4(NetworkAddress {
                                address,
                                netmask: match netmask {
                                    Some(IpAddr::V4(netmask)) => Some(netmask),
                                    _ => continue,
                                },
                                associated_address: match associated_address {
                                    Some(IpAddr::V4(addr)) => Some(addr),
                                    _ => None,
                                },
                            })
                        }
                        AddressFamily::V6 => {
                            let IpAddr::V6(address) = address else {
                                continue;
                            };
                            Address::V6(NetworkAddress {
                                address,
                                netmask: match netmask {
                                    Some(IpAddr::V6(netmask)) => Some(netmask),
                                    _ => continue,
                                },
                                associated_address: match associated_address {
                                    Some(IpAddr::V6(addr)) => Some(addr),
                                    _ => None,
                                },
                            })
                        }
                        _ => unreachable!(),
                    }
                }
                AddressFamily::Mac => {
                    #[allow(unused_assignments, unused_mut)]
                    let mut mac_address = None;

                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    {
                        mac_address = unsafe {
                            let sll = addr as *const _ as *const libc::sockaddr_ll;
                            let mac = (*sll).sll_addr;
                            Some([mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]])
                        }
                    }

                    #[cfg(any(
                        target_vendor = "apple",
                        target_os = "freebsd",
                        target_os = "openbsd",
                        target_os = "netbsd"
                    ))]
                    {
                        mac_address = unsafe {
                            let sdl = addr as *const _ as *const libc::sockaddr_dl;
                            let mac_offset = (*sdl).sdl_nlen as usize;
                            let mac_len = (*sdl).sdl_alen as usize;
                            if mac_len == 6 {
                                let mac_ptr = (*sdl).sdl_data.as_ptr().add(mac_offset);
                                let mut mac = [0u8; 6];
                                #[allow(clippy::needless_range_loop)]
                                for i in 0..6 {
                                    mac[i] = *mac_ptr.add(i) as u8;
                                }
                                Some(mac)
                            } else {
                                None
                            }
                        };
                    }

                    if let Some(mac) = mac_address {
                        if mac != [0u8; 6] {
                            Address::Mac(mac)
                        } else {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }
            };
            return Some(Interface {
                name,
                address,
                flags,
                index,
            });
        }
        None
    }
}

impl Drop for InterfaceIterator {
    fn drop(&mut self) {
        unsafe { libc::freeifaddrs(self.ifaddrs) };
    }
}

unsafe fn sockaddr_to_ipaddr(sa: *const libc::sockaddr) -> Result<IpAddr, io::Error> {
    match (*sa).sa_family as i32 {
        libc::AF_INET => {
            let addr_in = sa as *const libc::sockaddr_in;
            let ip_bytes = (*addr_in).sin_addr.s_addr.to_ne_bytes();
            Ok(IpAddr::V4(Ipv4Addr::from(ip_bytes)))
        }
        libc::AF_INET6 => {
            let addr_in6 = sa as *const libc::sockaddr_in6;
            let ip_bytes = (*addr_in6).sin6_addr.s6_addr;
            Ok(IpAddr::V6(Ipv6Addr::from(ip_bytes)))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid address family",
        )),
    }
}

pub fn _if_indextoname(index: InterfaceIndex) -> std::io::Result<String> {
    let mut buffer = vec![0u8; libc::IF_NAMESIZE];
    let result = unsafe {
        libc::if_indextoname(
            index as libc::c_uint,
            buffer.as_mut_ptr() as *mut libc::c_char,
        )
    };
    if result.is_null() {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe {
            std::ffi::CStr::from_ptr(result)
                .to_string_lossy()
                .into_owned()
        })
    }
}

pub fn _if_nametoindex(name: impl AsRef<str>) -> std::io::Result<InterfaceIndex> {
    let name_cstr = std::ffi::CString::new(name.as_ref()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid interface name")
    })?;
    let result = unsafe { libc::if_nametoindex(name_cstr.as_ptr()) };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(result as _)
    }
}
