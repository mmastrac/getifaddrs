use super::{
    Address, AddressFamily, Interface, InterfaceFilter, InterfaceFilterCriteria, InterfaceFlags,
    InterfaceIndex, NetworkAddress,
};
use std::{ffi::OsString, io, net::IpAddr, os::windows::prelude::OsStringExt};
use windows_sys::Win32::Foundation::{
    ERROR_BUFFER_OVERFLOW, ERROR_NOT_ENOUGH_MEMORY, ERROR_NO_DATA, NO_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    if_indextoname, if_nametoindex, ConvertInterfaceLuidToIndex, ConvertLengthToIpv4Mask,
    GetAdaptersAddresses, GetNumberOfInterfaces, IF_TYPE_IEEE80211, IP_ADAPTER_ADDRESSES_LH,
    IP_ADAPTER_UNICAST_ADDRESS_LH, MIB_IF_TYPE_ETHERNET, MIB_IF_TYPE_LOOPBACK, MIB_IF_TYPE_PPP,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
};

// Larger than necessary
const IF_NAMESIZE: usize = 1024;

pub struct InterfaceIterator {
    #[allow(unused)]
    adapters: AdaptersAddresses,
    yielded_mac: bool,
    current: *const IP_ADAPTER_ADDRESSES_LH,
    current_unicast: *const IP_ADAPTER_UNICAST_ADDRESS_LH,
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
            (true, false, false) => Family::V4,
            (false, true, false) => Family::V6,
            _ => Family::UNSPEC,
        };
        let adapters = AdaptersAddresses::try_new(family, Flags::default())?;
        let current = adapters.buf.ptr;
        let current_unicast = unsafe { (*current).FirstUnicastAddress };
        Ok(InterfaceIterator {
            adapters,
            yielded_mac: false,
            current,
            current_unicast,
            filter,
        })
    }

    /// Advance to the next record.
    fn advance(
        &mut self,
    ) -> Option<(
        *const IP_ADAPTER_ADDRESSES_LH,
        *const IP_ADAPTER_UNICAST_ADDRESS_LH,
    )> {
        // Wedge this iterator at the end
        if self.current.is_null() {
            return None;
        }
        let current = self.current;
        let current_unicast = self.current_unicast;
        loop {
            if self.current_unicast.is_null() {
                self.yielded_mac = false;
                self.current = unsafe { (*self.current).Next };
                if self.current.is_null() {
                    return Some((current, current_unicast));
                }
                self.current_unicast = unsafe { (*self.current).FirstUnicastAddress };
            } else {
                self.current_unicast = unsafe { (*self.current_unicast).Next };
            }

            if self.current_unicast.is_null() {
                continue;
            }

            return Some((current, current_unicast));
        }
    }
}

impl Iterator for InterfaceIterator {
    type Item = Interface;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Yield the mac address first for any adapter
            if !self.yielded_mac && !self.current.is_null() {
                self.yielded_mac = true;

                if self.filter.family_filter(AddressFamily::Mac) {
                    let adapter = unsafe { &*self.current };
                    if let Some(InterfaceFilterCriteria::Loopback) = &self.filter.criteria {
                        if adapter.IfType != MIB_IF_TYPE_LOOPBACK {
                            continue;
                        }
                    }

                    if let Ok(Some(interface)) = convert_to_interface_mac(adapter) {
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

            let (current, current_unicast) = self.advance()?;

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
    fn try_new(family: Family, flags: Flags) -> io::Result<Self> {
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
                    family.into(),
                    flags.into(),
                    std::ptr::null_mut(),
                    adapter_addresses.buf.ptr,
                    &mut out_buf_len,
                )
            } {
                NO_ERROR => return Ok(adapter_addresses),
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

fn convert_to_flags(adapter: &IP_ADAPTER_ADDRESSES_LH) -> InterfaceFlags {
    // Unsure if this is the right mapping here
    let mut flags = InterfaceFlags::empty();
    let raw_flags = unsafe { adapter.Anonymous2.Flags };
    if adapter.OperStatus == 1 {
        // IfOperStatusUp
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
    if raw_flags & (1 << 4) != 0 {
        // !NoMulticast
        flags &= !InterfaceFlags::MULTICAST;
    }
    if raw_flags & (1 << 7) != 0 {
        // Ipv4Enabled
        flags |= InterfaceFlags::UP;
    }
    if raw_flags & (1 << 8) != 0 {
        // Ipv6Enabled
        flags |= InterfaceFlags::UP;
    }
    if raw_flags & (1 << 3) != 0 {
        // ReceiveOnly
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
        IpAddr::V6(_) => {
            // For IPv6, we can use the prefix length directly
            Some(IpAddr::V6(std::net::Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0,
            )))
        }
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
            let associated_address = if flags.contains(InterfaceFlags::BROADCAST) {
                // TODO: We can likely hunt for this in the prefixes
                None
            } else {
                None
            };

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

    // Get the LUID and convert it to an index
    let luid = adapter.Luid;
    let mut if_index: u32 = 0;
    let result = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut if_index) };
    let luid = unsafe { adapter.Luid.Value };
    let (name, index) = if result == NO_ERROR {
        // Call if_indextoname with the converted index
        let mut buffer = [0u8; IF_NAMESIZE];
        let result = unsafe { if_indextoname(if_index, buffer.as_mut_ptr()) };
        if !result.is_null() {
            let name = unsafe { std::ffi::CStr::from_ptr(result as *const i8) }
                .to_string_lossy()
                .into_owned();
            (name, Some(if_index))
        } else {
            (format!("if{:#x}", luid), Some(if_index))
        }
    } else {
        (format!("if{:#x}", luid), None)
    };

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

    // Get the LUID and convert it to an index
    let luid = adapter.Luid;
    let mut if_index: u32 = 0;
    let result = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut if_index) };
    let luid = unsafe { adapter.Luid.Value };
    let (name, index) = if result == NO_ERROR {
        // Call if_indextoname with the converted index
        let mut buffer = [0u8; IF_NAMESIZE];
        let result = unsafe { if_indextoname(if_index, buffer.as_mut_ptr()) };
        if !result.is_null() {
            let name = unsafe { std::ffi::CStr::from_ptr(result as *const i8) }
                .to_string_lossy()
                .into_owned();
            (name, Some(if_index))
        } else {
            (format!("if{:#x}", luid), Some(if_index))
        }
    } else {
        (format!("if{:#x}", luid), None)
    };

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

#[derive(Copy, Clone)]
struct Family(u32);

impl Family {
    const UNSPEC: Self = Self(0);
    const V4: Self = Self(2);
    const V6: Self = Self(23);
}

impl From<Family> for u32 {
    fn from(family: Family) -> Self {
        family.0
    }
}

#[derive(Copy, Clone)]
struct Flags(u32);

impl Flags {
    fn default() -> Self {
        Self(0)
    }
}

impl From<Flags> for u32 {
    fn from(flags: Flags) -> Self {
        flags.0
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
