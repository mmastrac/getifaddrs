#![doc=include_str!("../README.md")]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bitflags::bitflags;

#[cfg(unix)]
mod unix;

#[cfg(windows)]
mod windows;

/// This represents the index of a network interface.
pub type InterfaceIndex = u32;

bitflags! {
    /// Flags representing the status and capabilities of a network interface.
    ///
    /// These flags provide information about the current state and features of a network interface.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct InterfaceFlags: u32 {
        /// The interface is up and running.
        const UP = 0x1;
        /// The interface is in a running state.
        const RUNNING = 0x2;
        /// The interface supports broadcast.
        const BROADCAST = 0x4;
        /// The interface is a loopback interface.
        const LOOPBACK = 0x8;
        /// The interface is a point-to-point link.
        const POINTTOPOINT = 0x10;
        /// The interface supports multicast.
        const MULTICAST = 0x20;
    }
}

/// Represents a network interface.
///
/// This struct contains information about a network interface, including its name,
/// IP address, netmask, flags, and index.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Interface<A: sealed::Addressable = Address> {
    /// The name of the interface.
    pub name: String,
    /// The description of the interface (Windows-specific).
    #[cfg(windows)]
    pub description: String,
    /// The address(es) associated with the interface.
    pub address: A,
    /// The flags indicating the interface's properties and state.
    pub flags: InterfaceFlags,
    /// The index of the interface, if available.
    pub index: Option<InterfaceIndex>,

    _unconstructable: std::marker::PhantomData<A>,
}

impl<A: sealed::Addressable> Interface<A> {
    #[cfg(test)]
    pub fn new(name: impl Into<String>, address: A) -> Self {
        Self {
            name: name.into(),
            #[cfg(windows)]
            description: String::new(),
            address,
            flags: InterfaceFlags::empty(),
            index: None,
            _unconstructable: std::marker::PhantomData,
        }
    }

    #[cfg(test)]
    pub fn with_index(self, index: InterfaceIndex) -> Self {
        Self {
            index: Some(index),
            ..self
        }
    }
}

/// A map of interface index to interface addresses.
///
/// Each interface may contain multiple addresses for a given family. Use
/// [`Addresses::get_all`] or iterate the [`Addresses`] value to access them all.
///
/// ```
/// # use getifaddrs::{getifaddrs, Interface, Interfaces};
/// # fn main() -> std::io::Result<()> {
/// let interfaces: Interfaces = getifaddrs()?.collect();
/// # Ok(())
/// # }
/// ```
#[allow(type_alias_bounds)]
pub type Interfaces<A: sealed::Addressable = Addresses<Address>> =
    BTreeMap<InterfaceIndex, Interface<A>>;

impl<A: sealed::Addressable> FromIterator<Interface<A>> for Interfaces<Addresses<A::Address>> {
    fn from_iter<T: IntoIterator<Item = Interface<A>>>(iter: T) -> Self {
        let mut map = BTreeMap::new();
        for interface in iter {
            if let Some(index) = interface.index {
                let addresses = &mut map
                    .entry(index)
                    .or_insert_with(|| Interface {
                        name: interface.name,
                        #[cfg(windows)]
                        description: interface.description,
                        address: Addresses::new(),
                        flags: interface.flags,
                        index: Some(index),
                        _unconstructable: std::marker::PhantomData,
                    })
                    .address;

                for (family, address) in A::iter(interface.address) {
                    addresses.insert(family, address);
                }
            }
        }
        map
    }
}

/// A collection of addresses, keyed by [`AddressFamily`].
#[derive(Default, Debug)]
pub struct Addresses<A: sealed::SingleAddressable = Address> {
    addresses: BTreeMap<AddressFamily, Vec<A>>,
}

impl<A: sealed::SingleAddressable> Addresses<A> {
    pub const fn new() -> Self {
        Self {
            addresses: BTreeMap::new(),
        }
    }

    /// Returns the first address associated with the given address family.
    pub fn get(&self, family: AddressFamily) -> Option<&A> {
        self.addresses.get(&family).map(|addresses| &addresses[0])
    }

    /// Returns the addresses associated with the given address family.
    pub fn get_all(&self, family: AddressFamily) -> Option<&[A]> {
        self.addresses.get(&family).map(|v| &**v)
    }

    /// Returns `true` if the collection contains an address of the given
    /// family.
    pub fn has(&self, family: AddressFamily) -> bool {
        self.addresses.contains_key(&family)
    }

    /// Returns `true` if the collection is empty.
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty() || self.len() == 0
    }

    /// Returns the number of address families represented in the collection.
    /// To count total individual addresses, iterate and sum the slice lengths.
    pub fn len(&self) -> usize {
        self.addresses
            .values()
            .map(|addresses| addresses.len())
            .sum()
    }

    /// Returns an iterator over the addresses in the collection.
    pub fn iter(&self) -> AddressesIter<'_, A> {
        AddressesIter {
            iter: self.addresses.values(),
        }
    }

    /// Inserts an address into the collection in sorted order.
    fn insert(&mut self, family: AddressFamily, address: A) {
        let entry = self.addresses.entry(family).or_default();
        match entry.binary_search(&address) {
            Ok(_) => {
                // Address already exists, don't insert duplicate
            }
            Err(pos) => {
                entry.insert(pos, address);
            }
        }
    }
}

impl<A: sealed::Addressable> FromIterator<A> for Addresses<A::Address> {
    fn from_iter<T: IntoIterator<Item = A>>(iter: T) -> Self {
        let mut map: BTreeMap<AddressFamily, Vec<A::Address>> = BTreeMap::new();
        for address in iter {
            for (family, address) in A::iter(address) {
                map.entry(family).or_default().push(address);
            }
        }
        Addresses { addresses: map }
    }
}

impl<X, A: sealed::Addressable> FromIterator<(X, A)> for Addresses<A::Address> {
    fn from_iter<T: IntoIterator<Item = (X, A)>>(iter: T) -> Self {
        let mut map: BTreeMap<AddressFamily, Vec<A::Address>> = BTreeMap::new();
        for (_, address) in iter {
            for (family, address) in A::iter(address) {
                map.entry(family).or_default().push(address);
            }
        }
        Addresses { addresses: map }
    }
}

/// An iterator over the addresses in a [`Addresses`] collection.
pub struct AddressesIter<'a, A = Address> {
    iter: std::collections::btree_map::Values<'a, AddressFamily, Vec<A>>,
}

impl<'a> Iterator for AddressesIter<'a> {
    type Item = &'a [Address];

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|v| &**v)
    }
}

impl<'a> IntoIterator for &'a Addresses {
    type Item = &'a [Address];
    type IntoIter = AddressesIter<'a>;
    fn into_iter(self) -> Self::IntoIter {
        AddressesIter {
            iter: self.addresses.values(),
        }
    }
}

impl FromIterator<Address> for Vec<IpAddr> {
    fn from_iter<T: IntoIterator<Item = Address>>(iter: T) -> Self {
        iter.into_iter()
            .filter_map(|address| address.ip_addr())
            .collect()
    }
}

impl<'a> FromIterator<&'a Address> for Vec<IpAddr> {
    fn from_iter<T: IntoIterator<Item = &'a Address>>(iter: T) -> Self {
        iter.into_iter()
            .filter_map(|address| address.ip_addr())
            .collect()
    }
}

impl FromIterator<Address> for Vec<Ipv4Addr> {
    fn from_iter<T: IntoIterator<Item = Address>>(iter: T) -> Self {
        iter.into_iter()
            .filter_map(|address| address.ipv4_addr())
            .collect()
    }
}

impl<'a> FromIterator<&'a Address> for Vec<Ipv4Addr> {
    fn from_iter<T: IntoIterator<Item = &'a Address>>(iter: T) -> Self {
        iter.into_iter()
            .filter_map(|address| address.ipv4_addr())
            .collect()
    }
}

impl FromIterator<Address> for Vec<Ipv6Addr> {
    fn from_iter<T: IntoIterator<Item = Address>>(iter: T) -> Self {
        iter.into_iter()
            .filter_map(|address| address.ipv6_addr())
            .collect()
    }
}

impl<'a> FromIterator<&'a Address> for Vec<Ipv6Addr> {
    fn from_iter<T: IntoIterator<Item = &'a Address>>(iter: T) -> Self {
        iter.into_iter()
            .filter_map(|address| address.ipv6_addr())
            .collect()
    }
}

/// Represents a network address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AddressFamily {
    /// An IPv4 address.
    V4,
    /// An IPv6 address.
    V6,
    /// A MAC (aka Ethernet) address.
    Mac,
}

/// IPv6 CIDR netmask: the first `prefix_len` bits are one, the rest zero
/// (`Ipv6Addr::from(u128)` is IETF / big-endian).
fn ipv6_netmask_from_prefix_len(prefix_len: u8) -> Ipv6Addr {
    let prefix_len = prefix_len.min(128);
    let mask = match prefix_len {
        0 => 0u128,
        p => u128::MAX << (128 - u32::from(p)),
    };
    Ipv6Addr::from(mask)
}

/// Represents a network address of a given type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Address {
    /// An IPv4 address.
    V4(NetworkAddress<Ipv4Addr>),
    /// An IPv6 address.
    V6(NetworkAddress<Ipv6Addr>),
    /// A MAC (aka Ethernet) address.
    Mac([u8; 6]),
}

impl Address {
    /// Returns `true` if the address is an IPv4 address.
    pub fn is_ipv4(&self) -> bool {
        matches!(self, Address::V4(_))
    }

    /// Returns `true` if the address is an IPv6 address.
    pub fn is_ipv6(&self) -> bool {
        matches!(self, Address::V6(_))
    }

    /// Returns `true` if the address is a MAC (aka Ethernet) address.
    pub fn is_mac(&self) -> bool {
        matches!(self, Address::Mac(_))
    }

    /// Returns the address family of the address.
    pub fn family(&self) -> AddressFamily {
        match self {
            Address::V4(_) => AddressFamily::V4,
            Address::V6(_) => AddressFamily::V6,
            Address::Mac(_) => AddressFamily::Mac,
        }
    }

    /// Returns the MAC address of the address, if this is a MAC address.
    pub fn mac_addr(&self) -> Option<[u8; 6]> {
        match self {
            Address::Mac(addr) => Some(*addr),
            _ => None,
        }
    }

    /// Returns the IP address of the address, if this is an IPv4 or IPv6 address.
    pub fn ip_addr(&self) -> Option<IpAddr> {
        match self {
            Address::V4(addr) => Some(IpAddr::V4(addr.address)),
            Address::V6(addr) => Some(IpAddr::V6(addr.address)),
            Address::Mac(_) => None,
        }
    }

    /// Returns the IPv4 address of the address, if this is an IPv4 address.
    pub fn ipv4_addr(&self) -> Option<Ipv4Addr> {
        match self {
            Address::V4(addr) => Some(addr.address),
            Address::V6(_) => None,
            Address::Mac(_) => None,
        }
    }

    /// Returns the IPv6 address of the address, if this is an IPv6 address.
    pub fn ipv6_addr(&self) -> Option<Ipv6Addr> {
        match self {
            Address::V6(addr) => Some(addr.address),
            Address::V4(_) => None,
            Address::Mac(_) => None,
        }
    }

    /// Returns the netmask of the address, if this is an IPv4 or IPv6 address.
    pub fn netmask(&self) -> Option<IpAddr> {
        match self {
            Address::V4(addr) => addr.netmask.map(IpAddr::V4),
            Address::V6(addr) => addr.netmask.map(IpAddr::V6),
            Address::Mac(_) => None,
        }
    }

    /// Returns the associated address of the address, if this is an IPv4 or IPv6 address.
    pub fn associated_address(&self) -> Option<IpAddr> {
        match self {
            Address::V4(addr) => addr.associated_address.map(IpAddr::V4),
            Address::V6(addr) => addr.associated_address.map(IpAddr::V6),
            Address::Mac(_) => None,
        }
    }

    pub fn v4(address: Ipv4Addr, netmask: Ipv4Addr) -> Self {
        Address::V4(NetworkAddress {
            address,
            netmask: Some(netmask),
            associated_address: None,
        })
    }

    pub fn v6(address: Ipv6Addr, prefix: u8) -> Self {
        assert!(prefix <= 128);
        Address::V6(NetworkAddress {
            address,
            netmask: Some(ipv6_netmask_from_prefix_len(prefix)),
            associated_address: None,
        })
    }

    pub fn mac(address: [u8; 6]) -> Self {
        Address::Mac(address)
    }
}

impl PartialEq<IpAddr> for Address {
    fn eq(&self, other: &IpAddr) -> bool {
        match self {
            Address::V4(addr) => addr.address == *other,
            Address::V6(addr) => addr.address == *other,
            Address::Mac(_) => false,
        }
    }
}

impl From<NetworkAddress<Ipv4Addr>> for Address {
    fn from(addr: NetworkAddress<Ipv4Addr>) -> Self {
        Address::V4(addr)
    }
}

impl From<NetworkAddress<Ipv6Addr>> for Address {
    fn from(addr: NetworkAddress<Ipv6Addr>) -> Self {
        Address::V6(addr)
    }
}

impl From<[u8; 6]> for Address {
    fn from(addr: [u8; 6]) -> Self {
        Address::Mac(addr)
    }
}

mod sealed {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// A trait for types that can be converted to and from `IpAddr`.
    pub trait NetworkAddressable: Into<IpAddr> + Addressable {}

    impl NetworkAddressable for IpAddr {}
    impl NetworkAddressable for Ipv4Addr {}
    impl NetworkAddressable for Ipv6Addr {}
    impl NetworkAddressable for super::NetworkAddress<Ipv4Addr> {}
    impl NetworkAddressable for super::NetworkAddress<Ipv6Addr> {}
    impl NetworkAddressable for super::NetworkAddress<IpAddr> {}

    pub trait SingleAddressable: Ord + Clone {
        fn family(&self) -> super::AddressFamily;
    }
    impl SingleAddressable for super::Address {
        fn family(&self) -> super::AddressFamily {
            match self {
                super::Address::V4(_) => super::AddressFamily::V4,
                super::Address::V6(_) => super::AddressFamily::V6,
                super::Address::Mac(_) => super::AddressFamily::Mac,
            }
        }
    }
    impl<A: Addressable> SingleAddressable for super::Interface<A>
    where
        A: SingleAddressable,
    {
        fn family(&self) -> super::AddressFamily {
            self.address.family()
        }
    }
    impl SingleAddressable for IpAddr {
        fn family(&self) -> super::AddressFamily {
            match self {
                IpAddr::V4(_) => super::AddressFamily::V4,
                IpAddr::V6(_) => super::AddressFamily::V6,
            }
        }
    }
    impl SingleAddressable for Ipv4Addr {
        fn family(&self) -> super::AddressFamily {
            super::AddressFamily::V4
        }
    }
    impl SingleAddressable for Ipv6Addr {
        fn family(&self) -> super::AddressFamily {
            super::AddressFamily::V6
        }
    }
    impl SingleAddressable for super::NetworkAddress<Ipv4Addr> {
        fn family(&self) -> super::AddressFamily {
            super::AddressFamily::V4
        }
    }
    impl SingleAddressable for super::NetworkAddress<Ipv6Addr> {
        fn family(&self) -> super::AddressFamily {
            super::AddressFamily::V6
        }
    }
    impl SingleAddressable for super::NetworkAddress<IpAddr> {
        fn family(&self) -> super::AddressFamily {
            match self.address {
                IpAddr::V4(_) => super::AddressFamily::V4,
                IpAddr::V6(_) => super::AddressFamily::V6,
            }
        }
    }

    pub trait Addressable {
        type Address: SingleAddressable;
        fn iter(self) -> impl IntoIterator<Item = (super::AddressFamily, Self::Address)>;
    }

    impl Addressable for super::Address {
        type Address = super::Address;
        fn iter(self) -> impl IntoIterator<Item = (super::AddressFamily, Self::Address)> {
            match self {
                super::Address::V4(addr) => [(super::AddressFamily::V4, (addr).into())].into_iter(),
                super::Address::V6(addr) => [(super::AddressFamily::V6, (addr).into())].into_iter(),
                super::Address::Mac(addr) => {
                    [(super::AddressFamily::Mac, (addr).into())].into_iter()
                }
            }
        }
    }

    impl<A: SingleAddressable> Addressable for super::Addresses<A> {
        type Address = A;
        fn iter(self) -> impl IntoIterator<Item = (super::AddressFamily, Self::Address)> {
            self.addresses.into_iter().flat_map(|(family, addresses)| {
                addresses.into_iter().map(move |address| (family, address))
            })
        }
    }

    impl<A: Addressable> Addressable for super::Interface<A> {
        type Address = A::Address;
        fn iter(self) -> impl IntoIterator<Item = (super::AddressFamily, Self::Address)> {
            self.address.iter()
        }
    }

    impl Addressable for IpAddr {
        type Address = IpAddr;
        fn iter(self) -> impl IntoIterator<Item = (super::AddressFamily, Self::Address)> {
            match self {
                IpAddr::V4(addr) => [(super::AddressFamily::V4, (addr).into())].into_iter(),
                IpAddr::V6(addr) => [(super::AddressFamily::V6, (addr).into())].into_iter(),
            }
        }
    }

    impl Addressable for Ipv4Addr {
        type Address = IpAddr;
        fn iter(self) -> impl IntoIterator<Item = (super::AddressFamily, Self::Address)> {
            [(super::AddressFamily::V4, (self).into())].into_iter()
        }
    }

    impl Addressable for Ipv6Addr {
        type Address = IpAddr;
        fn iter(self) -> impl IntoIterator<Item = (super::AddressFamily, Self::Address)> {
            [(super::AddressFamily::V6, (self).into())].into_iter()
        }
    }

    impl Addressable for super::NetworkAddress<Ipv4Addr> {
        type Address = IpAddr;
        fn iter(self) -> impl IntoIterator<Item = (super::AddressFamily, Self::Address)> {
            [(super::AddressFamily::V4, (self.address).into())].into_iter()
        }
    }
    impl Addressable for super::NetworkAddress<Ipv6Addr> {
        type Address = IpAddr;
        fn iter(self) -> impl IntoIterator<Item = (super::AddressFamily, Self::Address)> {
            [(super::AddressFamily::V6, (self.address).into())].into_iter()
        }
    }
    impl Addressable for super::NetworkAddress<IpAddr> {
        type Address = IpAddr;
        fn iter(self) -> impl IntoIterator<Item = (super::AddressFamily, Self::Address)> {
            let family = match &self.address {
                IpAddr::V4(_) => super::AddressFamily::V4,
                IpAddr::V6(_) => super::AddressFamily::V6,
            };
            [(family, self.address)].into_iter()
        }
    }
}

/// Represents a network address of a given type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NetworkAddress<T: sealed::NetworkAddressable = IpAddr> {
    /// The address associated with the interface.
    pub address: T,
    /// The netmask associated with the interface.
    pub netmask: Option<T>,

    /// The associated address of the interface. For broadcast interfaces, this
    /// is the broadcast address. For point-to-point interfaces, this is the
    /// peer address.
    pub associated_address: Option<T>,
}

impl From<NetworkAddress<Ipv4Addr>> for IpAddr {
    fn from(val: NetworkAddress<Ipv4Addr>) -> Self {
        val.address.into()
    }
}

impl From<NetworkAddress<Ipv6Addr>> for IpAddr {
    fn from(val: NetworkAddress<Ipv6Addr>) -> Self {
        val.address.into()
    }
}

impl From<NetworkAddress<IpAddr>> for IpAddr {
    fn from(val: NetworkAddress<IpAddr>) -> Self {
        val.address
    }
}

enum InterfaceFilterCriteria {
    Loopback,
    Index(InterfaceIndex),
    Name(String),
}

/// A filter for network interfaces.
///
/// This struct allows you to specify criteria for filtering network interfaces.
/// You can chain multiple filter methods to narrow down the selection.
///
/// By default, this returns all types of addresses for all interfaces.
///
/// # Examples
///
/// ```
/// # use std::io;
/// # use getifaddrs::{InterfaceFilter, AddressFamily, Interfaces};
/// # fn main() -> io::Result<()> {
/// // Get all IPv4 interfaces
/// let v4_interfaces = InterfaceFilter::new().v4().get()?;
///
/// // Get all IPv6 interfaces
/// let v6_interfaces = InterfaceFilter::new().v6().get()?;
///
/// // Get all IPv4 interfaces with a MAC address. Note that you need
/// // to collect v4 and mac addresses, then filter for interfaces with both.
/// let v4_mac_interfaces = InterfaceFilter::new().v4().mac().get()?.collect::<Interfaces>()
///     .iter().filter(|(_, interface)| interface.address.has(AddressFamily::Mac) && interface.address.has(AddressFamily::V4));
///
/// // Get loopback interfaces
/// let loopback_interfaces = InterfaceFilter::new().loopback().get()?;
/// # Ok(())
/// # }
/// ```
#[derive(Default)]
pub struct InterfaceFilter {
    criteria: Option<InterfaceFilterCriteria>,
    address: Option<[bool; 3]>,
}

impl InterfaceFilter {
    /// Creates a new `InterfaceFilter` with no criteria set.
    pub fn new() -> Self {
        InterfaceFilter::default()
    }

    /// Filters for loopback interfaces.
    pub fn loopback(mut self) -> Self {
        self.criteria = Some(InterfaceFilterCriteria::Loopback);
        self
    }

    /// Filters for interfaces with the specified index.
    pub fn index(mut self, index: InterfaceIndex) -> Self {
        self.criteria = Some(InterfaceFilterCriteria::Index(index));
        self
    }

    /// Filters for interfaces with the specified name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.criteria = Some(InterfaceFilterCriteria::Name(name.into()));
        self
    }

    /// Filters for interfaces with the specified address family.
    ///
    /// If no address family is specified, no filtering is applied. The first
    /// address filter specified will limit the returned addresses to the
    /// specified family. Further family filters will union the returned
    /// addresses with the given type.
    pub fn family(mut self, family: AddressFamily) -> Self {
        let address = self.address.get_or_insert([false; 3]);
        match family {
            AddressFamily::V4 => address[0] = true,
            AddressFamily::V6 => address[1] = true,
            AddressFamily::Mac => address[2] = true,
        }
        self
    }

    /// Filters for IPv4 interfaces. Equivalent to `family(V4)`.
    ///
    /// If no address family is specified, no filtering is applied. The first
    /// address filter specified will limit the returned addresses to the
    /// specified family. Further family filters will union the returned
    /// addresses with the given type.
    pub fn v4(self) -> Self {
        self.family(AddressFamily::V4)
    }

    /// Filters for IPv6 interfaces. Equivalent to `family(V6)`.
    ///
    /// If no address family is specified, no filtering is applied. The first
    /// address filter specified will limit the returned addresses to the
    /// specified family. Further family filters will union the returned
    /// addresses with the given type.
    pub fn v6(self) -> Self {
        self.family(AddressFamily::V6)
    }

    /// Filters for MAC addresses. Equivalent to `family(Mac)`.
    ///
    /// If no address family is specified, no filtering is applied. The first
    /// address filter specified will limit the returned addresses to the
    /// specified family. Further family filters will union the returned
    /// addresses with the given type.
    pub fn mac(self) -> Self {
        self.family(AddressFamily::Mac)
    }

    fn family_filter(&self, family: AddressFamily) -> bool {
        self.address
            .map(|address| {
                address[match family {
                    AddressFamily::V4 => 0,
                    AddressFamily::V6 => 1,
                    AddressFamily::Mac => 2,
                }]
            })
            .unwrap_or(true)
    }

    /// Applies the filter and returns an iterator over the matching interfaces.
    ///
    /// # Errors
    ///
    /// Returns an `std::io::Error` if there's an issue retrieving the network interfaces.
    pub fn get(self) -> std::io::Result<impl Iterator<Item = Interface>> {
        #[cfg(unix)]
        {
            unix::InterfaceIterator::new(self)
        }
        #[cfg(windows)]
        {
            windows::InterfaceIterator::new(self)
        }
    }

    /// Collects the interfaces into a `BTreeMap` of interface index to
    /// interface addresses.
    ///
    /// ## Limitations
    ///
    /// This will only collect interfaces that contain an non-empty index.
    ///
    /// [`Addresses::get`] returns the first address for a family. Use
    /// [`Addresses::get_all`] or iterate the [`Addresses`] value to access all
    /// collected addresses for that family.
    pub fn collect(self) -> std::io::Result<Interfaces<Addresses>> {
        Ok(self.get()?.collect())
    }
}

/// Returns an iterator for all network interfaces on the system.
///
/// This function creates a new [`InterfaceFilter`] with default settings and
/// uses it to retrieve all network interfaces. It is equivalent to calling
/// `InterfaceFilter::new().get()`.
///
/// # Returns
///
/// Returns a [`Result`] containing an [`Iterator`] over [`Interface`] items on
/// success, or a [`std::io::Error`] if there was a problem retrieving the
/// network interfaces.
///
/// # Collecting
///
/// The output of this function can be collected into a [`Interfaces`]
/// collection using the `collect` method which will return a [`BTreeMap`] of
/// interface index to interface addresses.
///
/// ```rust
/// # use getifaddrs::{getifaddrs, Interfaces};
/// let interfaces = getifaddrs().unwrap().collect::<Interfaces>();
///
/// for (index, interface) in interfaces {
///     eprintln!("Interface {index}: {interface:#?}");
/// }
/// ```
pub fn getifaddrs() -> std::io::Result<impl Iterator<Item = Interface>> {
    InterfaceFilter::new().get()
}

/// Converts a network interface index to its corresponding name.
///
/// This function takes a network interface index and returns the corresponding interface name.
///
/// # Arguments
///
/// * `index` - The index of the network interface.
///
/// # Returns
///
/// Returns a `Result` containing the interface name as a `String` on success, or an `io::Error`
/// if the conversion failed or the index is invalid.
///
/// # Examples
///
/// ```
/// match getifaddrs::if_indextoname(1) {
///     Ok(name) => println!("Interface name: {}", name),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
pub fn if_indextoname(index: InterfaceIndex) -> std::io::Result<String> {
    #[cfg(unix)]
    {
        unix::_if_indextoname(index)
    }
    #[cfg(windows)]
    {
        windows::_if_indextoname(index)
    }
}

/// Converts a network interface name to its corresponding index.
///
/// This function takes a string containing the network interface name or number
/// and returns the corresponding interface index.
///
/// # Arguments
///
/// * `name`: The name of the network interface. This can be any type that can
///   be converted to a string slice (`&str`).
///
/// # Returns
///
/// Returns a `Result` containing the interface index as a [`InterfaceIndex`] on
/// success, or an `io::Error` if the conversion failed or the name is invalid.
///
/// # Examples
///
/// ```
/// match getifaddrs::if_nametoindex("eth0") {
///     Ok(index) => println!("Interface index: {}", index),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
pub fn if_nametoindex(name: impl AsRef<str>) -> std::io::Result<InterfaceIndex> {
    // Any index that can parse as `InterfaceIndex` is returned as-is
    if let Ok(num) = name.as_ref().parse::<InterfaceIndex>() {
        return Ok(num as _);
    }

    #[cfg(unix)]
    {
        unix::_if_nametoindex(name).map(|idx| idx as _)
    }
    #[cfg(windows)]
    {
        windows::_if_nametoindex(name).map(|idx| idx as _)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_interfaces() {
        let interfaces: Vec<Interface> = getifaddrs().unwrap().collect();

        // Print interfaces for debugging
        for interface in &interfaces {
            eprintln!("{interface:#?}");
        }

        // Check for localhost interface
        let localhost = interfaces.iter().find(|i| {
            i.address == IpAddr::V4(Ipv4Addr::LOCALHOST)
                && i.flags.contains(InterfaceFlags::LOOPBACK)
        });
        assert!(localhost.is_some(), "No localhost interface found");

        // Check for at least one non-localhost interface
        let non_localhost = interfaces.iter().find(|i| {
            i.address != IpAddr::V4(Ipv4Addr::LOCALHOST)
                && !i.flags.contains(InterfaceFlags::LOOPBACK)
        });
        assert!(non_localhost.is_some(), "No non-localhost interface found");

        // Sanity check that any interface with an index matches its name
        for interface in &interfaces {
            if let Some(index) = interface.index {
                let name_from_index = if_indextoname(index as _).unwrap_or_default();
                assert_eq!(
                    interface.name, name_from_index,
                    "Interface name mismatch for index {index}"
                );

                let index_from_name = if_nametoindex(&interface.name).unwrap_or_default();
                assert_eq!(
                    index, index_from_name,
                    "Interface index mismatch for name {}",
                    interface.name
                );
            }
        }
    }

    #[test]
    fn test_collect() {
        let interfaces: Interfaces = getifaddrs().unwrap().collect();
        assert!(!interfaces.is_empty());
        eprintln!("{interfaces:#?}");
    }

    #[test]
    fn test_filter_address_type() {
        let total = getifaddrs().unwrap().count();

        let v4 = InterfaceFilter::new()
            .v4()
            .get()
            .unwrap()
            .collect::<Vec<_>>();
        for interface in &v4 {
            assert!(
                interface.address.is_ipv4(),
                "Expected v4 only: {interface:#?}"
            );
        }

        let v6 = InterfaceFilter::new()
            .v6()
            .get()
            .unwrap()
            .collect::<Vec<_>>();
        for interface in &v6 {
            assert!(
                interface.address.is_ipv6(),
                "Expected v6 only: {interface:#?}"
            );
        }

        let mac = InterfaceFilter::new()
            .mac()
            .get()
            .unwrap()
            .collect::<Vec<_>>();
        for interface in &mac {
            assert!(
                interface.address.is_mac(),
                "Expected mac only: {interface:#?}"
            );
        }

        assert_eq!(
            v4.len() + v6.len() + mac.len(),
            total,
            "v4 = {:?} v6 = {:?} mac = {:?} all = {:?}",
            v4,
            v6,
            mac,
            getifaddrs().unwrap().collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_filter_address_type_with_mac() {
        let total = getifaddrs().unwrap().count();

        let v4_mac = InterfaceFilter::new()
            .v4()
            .mac()
            .get()
            .unwrap()
            .collect::<Vec<_>>();
        let v4 = InterfaceFilter::new()
            .v4()
            .get()
            .unwrap()
            .collect::<Vec<_>>();
        let v6_mac = InterfaceFilter::new()
            .v6()
            .mac()
            .get()
            .unwrap()
            .collect::<Vec<_>>();
        let v6 = InterfaceFilter::new()
            .v6()
            .get()
            .unwrap()
            .collect::<Vec<_>>();
        let v4_v6 = InterfaceFilter::new()
            .v4()
            .v6()
            .get()
            .unwrap()
            .collect::<Vec<_>>();
        let mac = InterfaceFilter::new()
            .mac()
            .get()
            .unwrap()
            .collect::<Vec<_>>();

        assert_eq!(
            v4_mac.len(),
            v4.len() + mac.len(),
            "v4_mac = {:?} != v4 = {:?} + mac = {:?}",
            v4_mac,
            v4,
            mac
        );
        assert_eq!(
            v6_mac.len(),
            v6.len() + mac.len(),
            "v6_mac = {:?} != v6 = {:?} + mac = {:?}",
            v6_mac,
            v6,
            mac
        );
        assert_eq!(
            v4_v6.len(),
            v4.len() + v6.len(),
            "v4_v6 = {:?} != v4 = {:?} + v6 = {:?}",
            v4_v6,
            v4,
            v6
        );

        assert_eq!(
            v4_mac.len() + v6.len(),
            total,
            "v4_mac = {:?} + v6 = {:?} != total = {:?}",
            v4_mac,
            v6,
            total
        );
        assert_eq!(
            v6_mac.len() + v4.len(),
            total,
            "v6_mac = {:?} + v4 = {:?} != total = {:?}",
            v6_mac,
            v4,
            total
        );
        assert_eq!(
            v4_v6.len() + mac.len(),
            total,
            "v4_v6 = {:?} + mac = {:?} != total = {:?}",
            v4_v6,
            mac,
            total
        );
    }

    #[test]
    fn test_filter_name_and_index() {
        for interface in getifaddrs().unwrap() {
            // Test filtering by name
            let name = interface.name.clone();
            let v: Vec<_> = InterfaceFilter::new()
                .name(interface.name.clone())
                .get()
                .unwrap()
                .collect();
            eprintln!("Name filter {name}: {v:?}");
            assert!(!v.is_empty());
            for interface in v {
                assert_eq!(name, interface.name);
            }

            // Test filtering by index
            if let Some(index) = interface.index {
                let v: Vec<_> = InterfaceFilter::new().index(index).get().unwrap().collect();
                eprintln!("Index filter {index}: {v:?}");
                assert!(!v.is_empty());
                for interface in v {
                    assert_eq!(Some(index), interface.index);
                }
            }
        }
    }

    #[test]
    fn test_filter_loopback() {
        let loopback_interfaces: Vec<_> =
            InterfaceFilter::new().loopback().get().unwrap().collect();

        assert!(
            !loopback_interfaces.is_empty(),
            "No loopback interfaces found"
        );

        for interface in loopback_interfaces.clone() {
            assert!(
                interface.flags.contains(InterfaceFlags::LOOPBACK),
                "Interface {:?} is not marked as loopback",
                interface.name
            );
        }

        // Verify that non-loopback interfaces are not included
        let all_interfaces: Vec<_> = InterfaceFilter::new().get().unwrap().collect();
        let non_loopback_count = all_interfaces
            .iter()
            .filter(|i| !i.flags.contains(InterfaceFlags::LOOPBACK))
            .count();

        assert_eq!(
            all_interfaces.len() - loopback_interfaces.len(),
            non_loopback_count,
            "Loopback filter included non-loopback interfaces"
        );
    }

    #[test]
    fn test_associated_address() {
        let interfaces: Vec<_> = getifaddrs().unwrap().collect();

        // Test that associated_address method works for all interfaces
        for interface in &interfaces {
            let associated = interface.address.associated_address();

            // For broadcast interfaces, we should have an associated address (broadcast address)
            if interface.flags.contains(InterfaceFlags::BROADCAST) && interface.address.is_ipv4() {
                // Broadcast interfaces should have an associated address
                assert!(
                    associated.is_some(),
                    "Broadcast interface {} should have an associated address",
                    interface.name
                );

                if let Some(associated_addr) = associated {
                    // The associated address should be different from the interface address
                    assert_ne!(
                        interface.address.ip_addr().unwrap(),
                        associated_addr,
                        "Associated address should be different from interface address for broadcast interface {}",
                        interface.name
                    );
                }
            }

            // For loopback interfaces, associated address might be None
            if interface.flags.contains(InterfaceFlags::LOOPBACK) {
                // Loopback interfaces typically don't have associated addresses
                // This is expected behavior
            }
        }
    }

    #[test]
    fn test_iteration() {
        use std::str::FromStr;

        let ipv6_1 = Ipv6Addr::from_str("fec0::f1bf:37fc:1ced:91e6").unwrap();
        let ipv6_2 = Ipv6Addr::from_str("fe80::f1bf:37fc:1ced:91e6").unwrap();

        let iface_1 = Interface::new("iface_1", Address::v6(ipv6_1, 64)).with_index(1);
        let iface_2 = Interface::new("iface_1", Address::v6(ipv6_2, 64)).with_index(1);
        let raw_interfaces = [iface_1, iface_2];

        let interfaces: Interfaces<Addresses> = raw_interfaces.clone().into_iter().collect();
        assert_eq!(interfaces.len(), 1);

        let addresses: Addresses = interfaces.into_values().collect();
        assert_eq!(addresses.len(), 2);
    }

    #[test]
    fn ipv6_netmask_from_prefix_len_known_values() {
        let cases: &[(u8, &str)] = &[
            (0, "::"),
            (1, "8000::"),
            (2, "c000::"),
            (3, "e000::"),
            (4, "f000::"),
            (5, "f800::"),
            (6, "fc00::"),
            (7, "fe00::"),
            (8, "ff00::"),
            (9, "ff80::"),
            (10, "ffc0::"),
            (15, "fffe::"),
            (16, "ffff::"),
            (48, "ffff:ffff:ffff::"),
            (64, "ffff:ffff:ffff:ffff::"),
            (65, "ffff:ffff:ffff:ffff:8000::"),
            (96, "ffff:ffff:ffff:ffff:ffff:ffff::"),
            (127, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"),
            (128, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            (200, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            (255, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        ];

        for &(prefix, expected) in cases {
            assert_eq!(
                ipv6_netmask_from_prefix_len(prefix),
                expected.parse::<Ipv6Addr>().unwrap(),
                "ipv6_netmask_from_prefix_len({prefix}) should be {expected}"
            );
        }
    }
}
