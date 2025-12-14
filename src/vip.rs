use std::{collections::HashMap, hash::Hash};

const MAX_IP_SIZE: usize = 1024;

#[derive(Debug)]
struct IpAddr(u32);

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

#[derive(Debug, Default)]
struct IpTable(HashMap<IpAddr, RealIpMap>);

impl IpTable {
    fn new() -> Self {
        IpTable::default()
    }
}
