use crate::constants::{EXPLOITATION_ATTEMPT_MESSAGE, RELAYLIST_URL};
use base64::Engine;
use serde::de;
use std::{
    collections::BTreeMap,
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

struct PublicKeyVisitor;

pub fn exploitation_attempt() -> ! {
    println!("{}", EXPLOITATION_ATTEMPT_MESSAGE);
    std::process::exit(1);
}

impl de::Visitor<'_> for PublicKeyVisitor {
    type Value = PublicKey;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str(EXPLOITATION_ATTEMPT_MESSAGE)
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        self.visit_bytes(v.as_bytes())
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        let mut pubkey = [0; 32];
        // 44 is the number of characters for a 256-bit base64 key
        if v.len() != 44 {
            exploitation_attempt();
        }
        match base64::prelude::BASE64_STANDARD.decode_slice(v, &mut pubkey) {
            Ok(32) => (),
            _ => exploitation_attempt(),
        };
        Ok(PublicKey(x25519_dalek::PublicKey::from(pubkey)))
    }
}

impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(PublicKeyVisitor)
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&base64::prelude::BASE64_STANDARD.encode(self.0.as_bytes()))
    }
}

pub struct PublicKey(x25519_dalek::PublicKey);

impl PartialEq<String> for PublicKey {
    fn eq(&self, other: &String) -> bool {
        base64::prelude::BASE64_STANDARD.encode(self.as_bytes()) == *other
    }
}

impl PartialEq<PublicKey> for String {
    fn eq(&self, other: &PublicKey) -> bool {
        other == self
    }
}

impl std::ops::Deref for PublicKey {
    type Target = x25519_dalek::PublicKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// Location metadata from the /app/v1/relays locations map
#[derive(serde::Deserialize)]
struct Location {
    country: String,
    city: String,
    latitude: f64,
    longitude: f64,
}

// active, owned, provider, weight, socks_name, extra_addrs_in omitted
#[derive(serde::Deserialize)]
pub struct Relay {
    pub hostname: String,
    /// Location key matching an entry in the RelayList locations map (e.g. "se-got")
    pub location: String,
    pub ipv4_addr_in: Ipv4Addr,
    ipv6_addr_in: Ipv6Addr,
    pub public_key: PublicKey,
    pub multihop_port: u16,
    #[serde(default = "default_active")]
    active: bool,
}

fn default_active() -> bool {
    true
}

impl Relay {
    fn validate_hostname(&self) -> bool {
        self.hostname
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
    }
}

// Wireguard section within the /app/v1/relays response
#[derive(serde::Deserialize)]
struct WireguardSection {
    relays: Vec<Relay>,
}

// Top-level structure of https://api.mullvad.net/app/v1/relays
// openvpn, bridge, shadowsocks sections omitted
#[derive(serde::Deserialize)]
pub struct RelayList {
    locations: BTreeMap<String, Location>,
    wireguard: WireguardSection,
}

impl RelayList {
    pub fn new(client: reqwest::blocking::Client) -> Self {
        let server_list = client
            .get(RELAYLIST_URL)
            .send()
            .unwrap()
            .json::<RelayList>()
            .unwrap();
        if let Some(server) = server_list
            .wireguard
            .relays
            .iter()
            .find(|s| !s.validate_hostname())
        {
            eprintln!(
                "A server contains invalid characters in its hostname: {}",
                server.hostname
            );
            std::process::exit(3);
        }
        server_list
    }

    /// Iterate over active WireGuard relays.
    pub fn servers(&self) -> impl Iterator<Item = &Relay> {
        self.wireguard.relays.iter().filter(|r| r.active)
    }
}

impl fmt::Display for RelayList {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Group active relays by country -> city using the locations map.
        // BTreeMap gives stable alphabetical ordering.
        type CityEntry<'a> = (&'a str, &'a Location, Vec<&'a Relay>);
        let mut by_country: BTreeMap<&str, BTreeMap<&str, CityEntry>> = BTreeMap::new();

        for relay in self.wireguard.relays.iter().filter(|r| r.active) {
            if let Some(loc) = self.locations.get(&relay.location) {
                by_country
                    .entry(&loc.country)
                    .or_default()
                    .entry(&loc.city)
                    .or_insert_with(|| (&relay.location, loc, Vec::new()))
                    .2
                    .push(relay);
            }
        }

        for (_country_name, cities) in &by_country {
            // Print country header from the first city's location data
            if let Some((_, (_, loc, _))) = cities.iter().next() {
                writeln!(f, "{}", loc.country)?;
            }
            for (_city_name, (loc_code, loc, relays)) in cities {
                writeln!(
                    f,
                    "\t{} ({}) @ {}°N, {}°E",
                    loc.city, loc_code, loc.latitude, loc.longitude
                )?;
                for relay in relays {
                    writeln!(
                        f,
                        "\t\t{} ({}, {})",
                        relay.hostname, relay.ipv4_addr_in, relay.ipv6_addr_in
                    )?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOCK_RELAY_LIST: &str = r#"{
        "locations": {
            "se-got": {
                "country": "Sweden",
                "city": "Gothenburg",
                "latitude": 57.70716,
                "longitude": 11.96679
            },
            "us-nyc": {
                "country": "United States",
                "city": "New York",
                "latitude": 40.71427,
                "longitude": -74.00597
            }
        },
        "wireguard": {
            "ipv4_gateway": "10.64.0.1",
            "ipv6_gateway": "fc00:bbbb:bbbb:bb01::1",
            "port_ranges": [[53,53],[4000,33433],[33565,51820],[52001,60000]],
            "relays": [
                {
                    "hostname": "se-got-wg-001",
                    "location": "se-got",
                    "active": true,
                    "owned": true,
                    "provider": "31173 Services AB",
                    "weight": 100,
                    "ipv4_addr_in": "185.213.154.68",
                    "ipv6_addr_in": "2a03:1b20:5::1",
                    "public_key": "GC7dBMKmrQ3EBOrUHr3QYJR2gW3jDIuVEo/0p//WTEE=",
                    "multihop_port": 30001,
                    "socks_name": "se-got-wg-001.socks5.mullvad.net",
                    "extra_addrs_in": []
                },
                {
                    "hostname": "us-nyc-wg-301",
                    "location": "us-nyc",
                    "active": false,
                    "owned": false,
                    "provider": "M247",
                    "weight": 100,
                    "ipv4_addr_in": "185.220.101.1",
                    "ipv6_addr_in": "2604:180::1",
                    "public_key": "GC7dBMKmrQ3EBOrUHr3QYJR2gW3jDIuVEo/0p//WTEE=",
                    "multihop_port": 30002,
                    "socks_name": "us-nyc-wg-301.socks5.mullvad.net",
                    "extra_addrs_in": []
                }
            ]
        }
    }"#;

    #[test]
    fn test_relay_list_deserialization() {
        let list: RelayList = serde_json::from_str(MOCK_RELAY_LIST).unwrap();
        assert_eq!(list.wireguard.relays.len(), 2);
        assert_eq!(list.locations.len(), 2);

        let se = &list.wireguard.relays[0];
        assert_eq!(se.hostname, "se-got-wg-001");
        assert_eq!(se.location, "se-got");
        assert!(se.active);
        assert_eq!(se.multihop_port, 30001);
        assert_eq!(se.ipv4_addr_in, "185.213.154.68".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn test_servers_filters_inactive() {
        let list: RelayList = serde_json::from_str(MOCK_RELAY_LIST).unwrap();
        let servers: Vec<&Relay> = list.servers().collect();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].hostname, "se-got-wg-001");
    }

    #[test]
    fn test_public_key_deserialization_from_string() {
        let json = r#""GC7dBMKmrQ3EBOrUHr3QYJR2gW3jDIuVEo/0p//WTEE=""#;
        let key: PublicKey = serde_json::from_str(json).unwrap();
        assert_eq!(
            key.to_string(),
            "GC7dBMKmrQ3EBOrUHr3QYJR2gW3jDIuVEo/0p//WTEE="
        );
    }

    #[test]
    fn test_public_key_display_roundtrip() {
        let original = "JyMv6TlARDnBfQmXFzlywOLveNV3mBMaWosFjTcYE0g=";
        let json = format!(r#""{}""#, original);
        let key: PublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key.to_string(), original);
    }

    #[test]
    fn test_hostname_validation() {
        let relay = |hostname: &str| Relay {
            hostname: hostname.to_string(),
            location: "se-got".to_string(),
            ipv4_addr_in: "1.2.3.4".parse().unwrap(),
            ipv6_addr_in: "::1".parse().unwrap(),
            public_key: serde_json::from_str(
                r#""GC7dBMKmrQ3EBOrUHr3QYJR2gW3jDIuVEo/0p//WTEE=""#,
            )
            .unwrap(),
            multihop_port: 1234,
            active: true,
        };
        assert!(relay("se-got-wg-001").validate_hostname());
        assert!(relay("us-nyc-001").validate_hostname());
        assert!(!relay("bad hostname!").validate_hostname());
        assert!(!relay("bad.hostname").validate_hostname());
    }

    #[test]
    fn test_relay_list_display() {
        let list: RelayList = serde_json::from_str(MOCK_RELAY_LIST).unwrap();
        let output = list.to_string();
        // Only active relay (se-got-wg-001) should appear
        assert!(output.contains("Sweden"));
        assert!(output.contains("Gothenburg"));
        assert!(output.contains("se-got-wg-001"));
        // Inactive relay should not appear
        assert!(!output.contains("us-nyc-wg-301"));
    }

    #[test]
    fn test_public_key_equality() {
        let key_b64 = "GC7dBMKmrQ3EBOrUHr3QYJR2gW3jDIuVEo/0p//WTEE=".to_string();
        let json = format!(r#""{}""#, key_b64);
        let key: PublicKey = serde_json::from_str(&json).unwrap();
        assert!(key == key_b64);
        assert!(key_b64 == key);
    }
}
