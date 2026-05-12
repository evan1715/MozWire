use crate::{
    constants::EXPLOITATION_ATTEMPT_MESSAGE,
    relay::{PublicKey, exploitation_attempt},
};
use serde::de;
use std::fmt;

fn is_ip_addr(c: char) -> bool {
    c.is_ascii_hexdigit() || c == '/' || c == '.' || c == ':'
}

pub struct IpAddrCidrVisitor;

impl de::Visitor<'_> for IpAddrCidrVisitor {
    type Value = IpAddrCIDR;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str(EXPLOITATION_ATTEMPT_MESSAGE)
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        if !v.chars().all(is_ip_addr) {
            exploitation_attempt();
        }
        Ok(IpAddrCIDR(v.to_string()))
    }
}

#[derive(Clone)]
pub struct IpAddrCIDR(pub String);

impl<'de> serde::Deserialize<'de> for IpAddrCIDR {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(IpAddrCidrVisitor)
    }
}

impl std::ops::Deref for IpAddrCIDR {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(serde::Deserialize)]
pub struct Device {
    pub name: String,
    pub pubkey: PublicKey,
    pub ipv4_address: IpAddrCIDR,
    pub ipv6_address: IpAddrCIDR,
}

impl fmt::Display for Device {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "- {}: {}, {}, {}",
            self.name, self.pubkey, self.ipv4_address.0, self.ipv6_address.0
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_addr_cidr_valid() {
        let json = r#""10.68.52.100/32""#;
        let addr: IpAddrCIDR = serde_json::from_str(json).unwrap();
        assert_eq!(*addr, "10.68.52.100/32");
    }

    #[test]
    fn test_ip_addr_cidr_ipv6() {
        let json = r#""fc00:bbbb:bbbb:bb01::4:6400/128""#;
        let addr: IpAddrCIDR = serde_json::from_str(json).unwrap();
        assert_eq!(*addr, "fc00:bbbb:bbbb:bb01::4:6400/128");
    }

    #[test]
    fn test_device_deserialization() {
        let json = r#"{
            "name": "my-laptop",
            "pubkey": "GC7dBMKmrQ3EBOrUHr3QYJR2gW3jDIuVEo/0p//WTEE=",
            "ipv4_address": "10.68.52.100/32",
            "ipv6_address": "fc00:bbbb:bbbb:bb01::4:6400/128"
        }"#;
        let device: Device = serde_json::from_str(json).unwrap();
        assert_eq!(device.name, "my-laptop");
        assert_eq!(
            device.pubkey.to_string(),
            "GC7dBMKmrQ3EBOrUHr3QYJR2gW3jDIuVEo/0p//WTEE="
        );
        assert_eq!(*device.ipv4_address, "10.68.52.100/32");
        assert_eq!(*device.ipv6_address, "fc00:bbbb:bbbb:bb01::4:6400/128");
    }

    #[test]
    fn test_device_display() {
        let json = r#"{
            "name": "my-laptop",
            "pubkey": "GC7dBMKmrQ3EBOrUHr3QYJR2gW3jDIuVEo/0p//WTEE=",
            "ipv4_address": "10.68.52.100/32",
            "ipv6_address": "fc00:bbbb:bbbb:bb01::4:6400/128"
        }"#;
        let device: Device = serde_json::from_str(json).unwrap();
        let display = device.to_string();
        assert!(display.contains("my-laptop"));
        assert!(display.contains("GC7dBMKmrQ3EBOrUHr3QYJR2gW3jDIuVEo/0p//WTEE="));
        assert!(display.contains("10.68.52.100/32"));
    }

    #[test]
    fn test_pubkey_equality_with_string() {
        let json = r#"{
            "name": "test",
            "pubkey": "GC7dBMKmrQ3EBOrUHr3QYJR2gW3jDIuVEo/0p//WTEE=",
            "ipv4_address": "10.0.0.1/32",
            "ipv6_address": "::1/128"
        }"#;
        let device: Device = serde_json::from_str(json).unwrap();
        let key_str = "GC7dBMKmrQ3EBOrUHr3QYJR2gW3jDIuVEo/0p//WTEE=".to_string();
        assert!(device.pubkey == key_str);
        assert!(key_str == device.pubkey);
        assert!(device.pubkey != "wrong_key".to_string());
    }
}
