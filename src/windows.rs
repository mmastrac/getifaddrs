use super::{
    Address, AddressFamily, Interface, InterfaceFilter, InterfaceFilterCriteria, InterfaceFlags,
    InterfaceIndex, NetworkAddress,
};
use std::{
    ffi::OsString,
    io,
    net::{IpAddr, Ipv6Addr},
    os::windows::prelude::OsStringExt,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    if_indextoname, if_nametoindex, ConvertInterfaceLuidToIndex, ConvertLengthToIpv4Mask,
    GetAdaptersAddresses, GetNumberOfInterfaces, GET_ADAPTERS_ADDRESSES_FLAGS, IF_TYPE_IEEE80211,
    IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_IPV4_ENABLED, IP_ADAPTER_IPV6_ENABLED,
    IP_ADAPTER_NO_MULTICAST, IP_ADAPTER_RECEIVE_ONLY, IP_ADAPTER_UNICAST_ADDRESS_LH,
    MIB_IF_TYPE_ETHERNET, MIB_IF_TYPE_LOOPBACK, MIB_IF_TYPE_PPP,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
};
use windows_sys::Win32::{
    Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NOT_ENOUGH_MEMORY, ERROR_NO_DATA, NO_ERROR},
    NetworkManagement::Ndis::NET_LUID_LH,
};

// Larger than necessary
const IF_NAMESIZE: usize = 1024;

#[derive(Clone, Copy)]
enum InterfaceIteratorState {
    Mac(*const IP_ADAPTER_ADDRESSES_LH),
    Address(
        *const IP_ADAPTER_ADDRESSES_LH,
        *const IP_ADAPTER_UNICAST_ADDRESS_LH,
    ),
}

pub struct InterfaceIterator {
    #[allow(unused)]
    adapters: AdaptersAddresses,
    state: Option<InterfaceIteratorState>,
    filter: InterfaceFilter,
}

impl InterfaceIterator {
    pub fn new(filter: InterfaceFilter) -> io::Result<Self> {
        // We can only use this as an optimization if not looking for mac addresses
        let family = match (
            filter.family_filter(AddressFamily::V4),
            filter.family_filter(AddressFamily::V6),
            filter.family_filter(AddressFamily::Mac),
        ) {
            (true, false, false) => AF_INET,
            (false, true, false) => AF_INET6,
            _ => AF_UNSPEC,
        };
        let adapters = AdaptersAddresses::try_new(family, GET_ADAPTERS_ADDRESSES_FLAGS::default())?;
        let current = adapters.buf.ptr;
        Ok(InterfaceIterator {
            adapters,
            state: if current.is_null() {
                None
            } else {
                Some(InterfaceIteratorState::Mac(current))
            },
            filter,
        })
    }

    /// Advance to the next record.
    fn advance(&mut self) -> Option<InterfaceIteratorState> {
        // Wedge this iterator at the end
        let state = self.state?;
        let next = state;
        let (current, current_unicast) = match next {
            InterfaceIteratorState::Mac(current) => {
                (current, unsafe { (*current).FirstUnicastAddress })
            }
            InterfaceIteratorState::Address(current, current_unicast) => {
                (current, unsafe { (*current_unicast).Next })
            }
        };
        if current_unicast.is_null() {
            let next = unsafe { (*current).Next };
            self.state = if next.is_null() {
                None
            } else {
                Some(InterfaceIteratorState::Mac(next))
            };
        } else {
            self.state = Some(InterfaceIteratorState::Address(current, current_unicast));
        }
        Some(next)
    }
}

impl Iterator for InterfaceIterator {
    type Item = Interface;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.advance()? {
                InterfaceIteratorState::Mac(adapter) => {
                    if self.filter.family_filter(AddressFamily::Mac) {
                        let adapter = unsafe { &*adapter };
                        if let Some(InterfaceFilterCriteria::Loopback) = &self.filter.criteria {
                            if adapter.IfType != MIB_IF_TYPE_LOOPBACK {
                                continue;
                            }
                        }

                        if let Ok(Some(interface)) = convert_to_interface_mac(adapter) {
                            if let Some(InterfaceFilterCriteria::Name(name)) = &self.filter.criteria
                            {
                                if name != &interface.name {
                                    continue;
                                }
                            }
                            if let Some(InterfaceFilterCriteria::Index(index)) =
                                &self.filter.criteria
                            {
                                if Some(*index) != interface.index {
                                    continue;
                                }
                            }

                            return Some(interface);
                        }
                    }
                }
                InterfaceIteratorState::Address(current, current_unicast) => {
                    let sa_family = unsafe { (*(*current_unicast).Address.lpSockaddr).sa_family };
                    if sa_family == AF_INET && !self.filter.family_filter(AddressFamily::V4) {
                        continue;
                    }
                    if sa_family == AF_INET6 && !self.filter.family_filter(AddressFamily::V6) {
                        continue;
                    }

                    let adapter = unsafe { &*current };
                    let unicast_addr = unsafe { &*current_unicast };

                    if let Some(InterfaceFilterCriteria::Loopback) = &self.filter.criteria {
                        if adapter.IfType != MIB_IF_TYPE_LOOPBACK {
                            continue;
                        }
                    }

                    if let Ok(interface) = convert_to_interface(adapter, unicast_addr) {
                        if let Some(InterfaceFilterCriteria::Name(name)) = &self.filter.criteria {
                            if name != &interface.name {
                                continue;
                            }
                        }
                        if let Some(InterfaceFilterCriteria::Index(index)) = &self.filter.criteria {
                            if Some(*index) != interface.index {
                                continue;
                            }
                        }

                        return Some(interface);
                    }
                }
            }
        }
    }
}

struct AdaptersAddresses {
    buf: AdapterAddressBuf,
}

struct AdapterAddressBuf {
    ptr: *mut IP_ADAPTER_ADDRESSES_LH,
    size: usize,
}

impl AdapterAddressBuf {
    fn new(bytes: usize) -> io::Result<Self> {
        let layout = std::alloc::Layout::from_size_align(
            bytes,
            std::mem::align_of::<IP_ADAPTER_ADDRESSES_LH>(),
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let ptr = unsafe { std::alloc::alloc(layout) };
        if ptr.is_null() {
            Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "Failed to allocate memory",
            ))
        } else {
            Ok(Self {
                ptr: ptr as *mut IP_ADAPTER_ADDRESSES_LH,
                size: bytes,
            })
        }
    }
}

impl Drop for AdapterAddressBuf {
    fn drop(&mut self) {
        let layout = std::alloc::Layout::from_size_align(
            self.size,
            std::mem::align_of::<IP_ADAPTER_ADDRESSES_LH>(),
        )
        .unwrap();
        unsafe { std::alloc::dealloc(self.ptr as *mut u8, layout) };
    }
}

impl AdaptersAddresses {
    fn try_new(family: ADDRESS_FAMILY, flags: GET_ADAPTERS_ADDRESSES_FLAGS) -> io::Result<Self> {
        let mut num_interfaces = 0u32;
        unsafe {
            if GetNumberOfInterfaces(&mut num_interfaces) != NO_ERROR {
                num_interfaces = 16; // Estimate if GetNumberOfInterfaces fails
            } else {
                num_interfaces = num_interfaces.max(8);
            }
        };

        let mut out_buf_len =
            num_interfaces * std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>() as u32;
        let mut adapter_addresses = Self {
            buf: AdapterAddressBuf::new(out_buf_len as usize)?,
        };

        // The recommended method of calling the GetAdaptersAddresses function is to pre-allocate
        // a 15KB working buffer pointed to by the AdapterAddresses parameter. On typical computers,
        // this dramatically reduces the chances that the GetAdaptersAddresses function returns
        // ERROR_BUFFER_OVERFLOW, which would require calling GetAdaptersAddresses function multiple
        // times.
        const MAX_MEMORY_SIZE: u32 = 128 * 1024; // 128kB
        loop {
            if out_buf_len > MAX_MEMORY_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "Failed to allocate buffer: exceeded maximum memory size",
                ));
            }

            match unsafe {
                GetAdaptersAddresses(
                    family as u32,
                    flags,
                    std::ptr::null_mut(),
                    adapter_addresses.buf.ptr,
                    &mut out_buf_len,
                )
            } {
                NO_ERROR => {
                    return Ok(adapter_addresses);
                }
                ERROR_BUFFER_OVERFLOW | ERROR_NOT_ENOUGH_MEMORY => {
                    if out_buf_len == MAX_MEMORY_SIZE {
                        return Err(io::Error::new(
                            io::ErrorKind::OutOfMemory,
                            "Failed to allocate buffer: exceeded maximum memory size",
                        ));
                    }
                    out_buf_len = (out_buf_len * 2).min(MAX_MEMORY_SIZE);
                    adapter_addresses.buf = AdapterAddressBuf::new(out_buf_len as usize)?;
                    continue;
                }
                ERROR_NO_DATA => return Err(io::Error::new(io::ErrorKind::NotFound, "No data")),
                other => {
                    return Err(io::Error::other(format!(
                        "GetAdaptersAddresses failed: {other:x}"
                    )))
                }
            }
        }
    }
}

/// Converts an adapter LUID to a (name, index) pair.
///
/// Tries LUID → index → name. Falls back to a hex LUID string when the OS
/// calls fail, so callers always receive a usable name.
fn luid_to_name_and_index(luid: NET_LUID_LH) -> (String, Option<u32>) {
    let mut if_index: u32 = 0;
    let result = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut if_index) };
    let luid_value = unsafe { luid.Value };
    if result == NO_ERROR {
        let mut buffer = [0u8; IF_NAMESIZE];
        let ptr = unsafe { if_indextoname(if_index, buffer.as_mut_ptr()) };
        if !ptr.is_null() {
            let name = unsafe { std::ffi::CStr::from_ptr(ptr as *const i8) }
                .to_string_lossy()
                .into_owned();
            (name, Some(if_index))
        } else {
            (format!("if{:#x}", luid_value), Some(if_index))
        }
    } else {
        (format!("if{:#x}", luid_value), None)
    }
}

/// Converts an IPv6 prefix length (0–128) to the corresponding netmask.
fn prefix_length_to_ipv6_mask(prefix_len: u8) -> Ipv6Addr {
    let prefix_len = prefix_len.min(128) as usize;
    let mut bytes = [0u8; 16];
    let full_bytes = prefix_len / 8;
    let remainder = prefix_len % 8;
    bytes[..full_bytes].fill(0xff);
    if remainder > 0 {
        bytes[full_bytes] = 0xffu8 << (8 - remainder);
    }
    Ipv6Addr::from(bytes)
}

fn convert_to_flags(adapter: &IP_ADAPTER_ADDRESSES_LH) -> InterfaceFlags {
    // Unsure if this is the right mapping here
    let mut flags = InterfaceFlags::empty();
    let raw_flags = unsafe { adapter.Anonymous2.Flags };
    if adapter.OperStatus == IfOperStatusUp {
        flags |= InterfaceFlags::UP | InterfaceFlags::RUNNING;
    }
    if adapter.IfType == MIB_IF_TYPE_LOOPBACK {
        flags |= InterfaceFlags::LOOPBACK;
    }
    if adapter.IfType == IF_TYPE_IEEE80211 || adapter.IfType == MIB_IF_TYPE_ETHERNET {
        flags |= InterfaceFlags::BROADCAST | InterfaceFlags::MULTICAST;
    }
    if adapter.IfType == MIB_IF_TYPE_PPP {
        flags |= InterfaceFlags::POINTTOPOINT;
    }
    if raw_flags & IP_ADAPTER_NO_MULTICAST != 0 {
        flags &= !InterfaceFlags::MULTICAST;
    }
    if raw_flags & IP_ADAPTER_IPV4_ENABLED != 0 {
        flags |= InterfaceFlags::UP;
    }
    if raw_flags & IP_ADAPTER_IPV6_ENABLED != 0 {
        flags |= InterfaceFlags::UP;
    }
    if raw_flags & IP_ADAPTER_RECEIVE_ONLY != 0 {
        flags &= !InterfaceFlags::RUNNING;
    }
    flags
}

fn convert_to_interface(
    adapter: &IP_ADAPTER_ADDRESSES_LH,
    unicast_addr: &IP_ADAPTER_UNICAST_ADDRESS_LH,
) -> io::Result<Interface> {
    let description = to_os_string(adapter.FriendlyName)
        .to_string_lossy()
        .into_owned();

    let ip_addr = sockaddr_to_ipaddr(unicast_addr.Address.lpSockaddr)?;

    let flags = convert_to_flags(adapter);

    let netmask = match ip_addr {
        IpAddr::V4(_) => {
            let mut mask: u32 = 0;
            unsafe {
                ConvertLengthToIpv4Mask(unicast_addr.OnLinkPrefixLength as u32, &mut mask);
            }
            Some(IpAddr::V4(std::net::Ipv4Addr::from(mask.to_be())))
        }
        IpAddr::V6(_) => Some(IpAddr::V6(prefix_length_to_ipv6_mask(
            unicast_addr.OnLinkPrefixLength,
        ))),
    };

    let address = match ip_addr {
        IpAddr::V4(addr) => {
            // Calculate associated address (broadcast for broadcast interfaces)
            let associated_address = if flags.contains(InterfaceFlags::LOOPBACK) {
                // For loopback interfaces, we can use the address itself, matching
                // both macOS and Linux behavior.
                Some(addr)
            } else if flags.contains(InterfaceFlags::BROADCAST) {
                // For broadcast interfaces, calculate broadcast address from the subnet mask
                if let Some(IpAddr::V4(netmask)) = netmask {
                    let addr_u32 = u32::from(addr);
                    let netmask_u32 = u32::from(netmask);
                    let network_addr = addr_u32 & netmask_u32;
                    let broadcast_addr = network_addr | (!netmask_u32);
                    Some(std::net::Ipv4Addr::from(broadcast_addr))
                } else {
                    None
                }
            } else {
                None
            };

            Address::V4(NetworkAddress {
                address: addr,
                netmask: netmask.and_then(|n| match n {
                    IpAddr::V4(netmask) => Some(netmask),
                    _ => None,
                }),
                associated_address,
            })
        }
        IpAddr::V6(addr) => {
            // TODO: We can likely hunt for this in the prefixes
            let associated_address = None;

            Address::V6(NetworkAddress {
                address: addr,
                netmask: netmask.and_then(|n| match n {
                    IpAddr::V6(netmask) => Some(netmask),
                    _ => None,
                }),
                associated_address,
            })
        }
    };

    let (name, index) = luid_to_name_and_index(adapter.Luid);

    Ok(Interface {
        name,
        description,
        address,
        flags,
        index,
    })
}

fn convert_to_interface_mac(adapter: &IP_ADAPTER_ADDRESSES_LH) -> io::Result<Option<Interface>> {
    // Extract MAC address from adapter.PhysicalAddress
    let len = adapter.PhysicalAddressLength as usize;
    let mac_address = if len == 6 {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&adapter.PhysicalAddress[..6]);
        if mac.iter().all(|b| *b == 0) {
            return Ok(None);
        }
        mac
    } else {
        return Ok(None);
    };

    let description = to_os_string(adapter.FriendlyName)
        .to_string_lossy()
        .into_owned();

    let flags = convert_to_flags(adapter);

    let (name, index) = luid_to_name_and_index(adapter.Luid);

    Ok(Some(Interface {
        name,
        description,
        address: Address::Mac(mac_address),
        flags,
        index,
    }))
}

fn sockaddr_to_ipaddr(sock_addr: *const SOCKADDR) -> io::Result<IpAddr> {
    if sock_addr.is_null() {
        Err(io::Error::new(io::ErrorKind::InvalidInput, "Null pointer"))
    } else {
        match unsafe { (*sock_addr).sa_family } {
            AF_INET => {
                let sock_addr4 = sock_addr as *const SOCKADDR_IN;
                let ip_bytes = unsafe { (*sock_addr4).sin_addr.S_un.S_addr.to_ne_bytes() };
                Ok(IpAddr::V4(ip_bytes.into()))
            }
            AF_INET6 => {
                let sock_addr6 = sock_addr as *const SOCKADDR_IN6;
                let ip_bytes = unsafe { (*sock_addr6).sin6_addr.u.Byte };
                Ok(IpAddr::V6(ip_bytes.into()))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid address family",
            )),
        }
    }
}

fn to_os_string(p: *mut u16) -> OsString {
    if p.is_null() {
        OsString::new()
    } else {
        let mut i = 0usize;
        while unsafe { *p.add(i) } != 0 {
            i += 1;
        }
        OsString::from_wide(unsafe { std::slice::from_raw_parts(p, i) })
    }
}

pub fn _if_indextoname(index: InterfaceIndex) -> io::Result<String> {
    let mut buffer = vec![0u8; IF_NAMESIZE]; // Allocate buffer for narrow string
    let result = unsafe { if_indextoname(index as _, buffer.as_mut_ptr()) };
    if result.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe {
            std::ffi::CStr::from_ptr(result as _)
                .to_string_lossy()
                .into_owned()
        })
    }
}

pub fn _if_nametoindex(name: impl AsRef<str>) -> io::Result<InterfaceIndex> {
    use std::ffi::CString;
    let name_cstr = CString::new(name.as_ref())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid interface name"))?;
    let result = unsafe { if_nametoindex(name_cstr.as_ptr() as _) };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as _)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_length_to_ipv6_mask() {
        let cases: &[(u8, &str)] = &[
            (0, "::"),
            // Partial first byte
            (1, "8000::"),
            (2, "c000::"),
            (3, "e000::"),
            (4, "f000::"),
            (5, "f800::"),
            (6, "fc00::"),
            (7, "fe00::"),
            // Byte-aligned cases
            (8, "ff00::"),
            (16, "ffff::"),
            (48, "ffff:ffff:ffff::"),
            (64, "ffff:ffff:ffff:ffff::"),
            (96, "ffff:ffff:ffff:ffff:ffff:ffff::"),
            // Crossing a byte boundary
            (9, "ff80::"),
            (10, "ffc0::"),
            (15, "fffe::"),
            // Values near the end
            (127, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"),
            (128, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            // Values above 128 are clamped
            (200, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            (255, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        ];

        for &(prefix, expected) in cases {
            assert_eq!(
                prefix_length_to_ipv6_mask(prefix),
                expected.parse::<Ipv6Addr>().unwrap(),
                "prefix_length_to_ipv6_mask({prefix}) should be {expected}"
            );
        }
    }
}
