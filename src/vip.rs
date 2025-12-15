use std::{collections::HashMap, hash::Hash};

const MAX_IP_SIZE: usize = 1024;

#[derive(Debug, Copy, Clone)]
struct IpAddr(u32);

impl IpAddr {
    const EMPTY_IP_ADDR: Self = Self(0);
} //big endian u32

impl From<u32> for IpAddr {
    fn from(value: u32) -> Self {
        Self(value.to_be())
    }
}

impl Hash for IpAddr {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

#[derive(Debug)]
struct RealIpMap([IpAddr; MAX_IP_SIZE]);

impl RealIpMap {
    fn new() -> Self {
        let empty_ip = IpAddr::EMPTY_IP_ADDR;
        let empty_array: [IpAddr; 1024] = [empty_ip; 1024];
        Self(empty_array)
    }
}

#[derive(Debug, Default)]
struct IpTable(HashMap<IpAddr, RealIpMap>);
