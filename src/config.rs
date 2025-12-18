use anyhow::anyhow;
use core::net;
use std::{collections::HashSet, fs};

use anyhow::{Error, Result, bail};
use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct Config {
    pub vip: Vec<Vip>,
}

#[derive(Debug, Deserialize)]
pub struct Vip {
    pub name: String,
    pub addr: net::IpAddr,
    pub port: u16,
    pub proto: Protocol,
    pub lb: LbConfig,
    pub rip: Vec<RealIp>,
    pub stat: StatConfig,
}

#[derive(Debug, Deserialize)]
pub struct LbConfig {
    pub mode: LbMode,
    pub hash: Option<HashConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Sctp,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LbMode {
    Hash,
    RoundRobin,
    LeastConn,
}

#[derive(Debug, Deserialize)]
pub struct HashConfig {
    pub key: String,
}

#[derive(Debug, Deserialize)]
pub struct RealIp {
    pub addr: net::IpAddr,
    pub port: u16,
    #[serde(rename = "w", default = "default_weight")]
    pub weight: u32,
}

#[derive(Debug, Deserialize)]
pub struct StatConfig {
    pub enable: bool,
    pub out: Option<StatOutputConfig>,
}

#[derive(Debug, Deserialize)]
pub struct StatOutputConfig {
    pub fmt: StatFormat,
    pub path: String,
    #[serde(default = "default_interval")]
    pub interval: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StatFormat {
    Json,
    Prometheus,
    Text,
}

fn default_interval() -> u64 {
    1
}
fn default_weight() -> u32 {
    1
}

impl Config {
    pub fn new(path: String) -> Result<Self> {
        let toml_str = fs::read_to_string(path)?;
        let config = toml::from_str(&toml_str)?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        let mut seen_vips = HashSet::new();

        for vip in &self.vip {
            let endpoint = format!("{}:{}", vip.addr, vip.port);
            if !seen_vips.insert(endpoint.clone()) {
                bail!("Duplicate VIP endpoint found: {}", endpoint)
            }

            for rip in &vip.rip {
                if rip.weight == 0 {
                    bail!("Real IP {}:{} weight cannot be 0", rip.addr, rip.port)
                }
            }

            if vip.stat.enable {
                let output_config = vip.stat.out.as_ref().unwrap();

                let path = std::path::Path::new(&output_config.path);

                if let Some(parent) = path.parent()
                    && !parent.exists()
                {
                    bail!("Stat log directory does not exist: {:?}", parent)
                }

                fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|e| anyhow!("Cannot write to stat path {:?}: {}", path, e))?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_full_config() {
        let toml_content = r#"
            [[vip]]
            name = "web-80"
            addr = "10.0.0.100"
            port = 80
            proto = "tcp"
            [vip.lb]
            mode = "hash"
            [vip.lb.hash]
            key = "src_ip"
            [[vip.rip]]
            addr = "192.168.1.10"
            port = 8080
            w = 5
            [[vip.rip]]
            addr = "192.168.1.11"
            port = 8080
            [vip.stat]
            enable = true
            [vip.stat.out]
            fmt = "json"
            path = "/tmp/test.log"
            interval = 30
        "#;

        let config: Config = toml::from_str(toml_content).unwrap();
        let vip = &config.vip[0];

        assert_eq!(vip.name, "web-80");
        assert_eq!(vip.addr, "10.0.0.100".parse::<std::net::IpAddr>().unwrap());
        assert!(matches!(vip.proto, Protocol::Tcp));
        assert!(matches!(vip.lb.mode, LbMode::Hash));
        assert_eq!(vip.lb.hash.as_ref().unwrap().key, "src_ip");
        assert_eq!(vip.rip.len(), 2);
        assert_eq!(vip.rip[0].weight, 5);
        assert_eq!(vip.rip[1].weight, 1);
        assert_eq!(vip.stat.out.as_ref().unwrap().interval, 30);
    }

    #[test]
    fn test_default_values() {
        let toml_content = r#"
            [[vip]]
            name = "minimal"
            addr = "1.1.1.1"
            port = 443
            proto = "udp"
            [vip.lb]
            mode = "roundrobin"
            [[vip.rip]]
            addr = "2.2.2.2"
            port = 8443
            [vip.stat]
            enable = false
            [vip.stat.out]
            fmt = "text"
            path = "out.txt"
        "#;

        let config: Config = toml::from_str(toml_content).unwrap();
        assert_eq!(config.vip[0].rip[0].weight, 1);
        assert_eq!(config.vip[0].stat.out.as_ref().unwrap().interval, 1);
    }

    #[test]
    fn test_enum_parsing() {
        let formats = vec![
            ("json", StatFormat::Json),
            ("prometheus", StatFormat::Prometheus),
            ("text", StatFormat::Text),
        ];

        for (str_val, enum_val) in formats {
            let toml = format!("fmt = \"{}\"\npath = \"a\"\ninterval = 1", str_val);
            let parsed: StatOutputConfig = toml::from_str(&toml).unwrap();
            assert_eq!(
                std::mem::discriminant(&parsed.fmt),
                std::mem::discriminant(&enum_val)
            );
        }
    }

    #[test]
    #[should_panic]
    fn test_invalid_ip_format() {
        let toml_content = r#"
            [[vip]]
            name = "bad-ip"
            addr = "999.999.999.999"
            port = 80
            proto = "tcp"
            [vip.lb]
            mode = "roundrobin"
            [[vip.rip]]
            addr = "1.1.1.1"
            port = 80
            [vip.stat]
            enable = false
            [vip.stat.out]
            fmt = "json"
            path = "p"
        "#;
        let _: Config = toml::from_str(toml_content).unwrap();
    }

    #[test]
    fn test_duplicate_vip_conflict() {
        let config = Config {
            vip: vec![
                create_mock_vip("10.0.0.1", 80),
                create_mock_vip("10.0.0.1", 80),
            ],
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_invalid_weight() {
        let mut vip = create_mock_vip("10.0.0.1", 80);
        vip.rip[0].weight = 0; // invallid weigh
        let config = Config { vip: vec![vip] };
        assert!(config.validate().is_err());
    }

    fn create_mock_vip(addr: &str, port: u16) -> Vip {
        Vip {
            name: "test".to_string(),
            addr: addr.parse().unwrap(),
            port,
            proto: Protocol::Tcp,
            lb: LbConfig {
                mode: LbMode::RoundRobin,
                hash: None,
            },
            rip: vec![RealIp {
                addr: "192.168.1.1".parse().unwrap(),
                port: 8080,
                weight: 1,
            }],
            stat: StatConfig {
                enable: false,
                out: None,
            },
        }
    }
}
