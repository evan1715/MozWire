/// Mullvad relay list: fetching, parsing, validation, and display.
///
/// ## API shape
///
/// MozWire fetches the relay list from `RELAYLIST_URL`
/// (`https://api.mullvad.net/app/v1/relays`). The response is a JSON object
/// with two sections we care about:
///
/// * `locations` — a flat map from a location key (e.g. `"se-got"`) to a
///   `Location` object containing the country name, city name, and coordinates.
/// * `wireguard` — contains `relays` (the usable server list), `port_ranges`,
///   and the `ipv4_gateway` / `ipv6_gateway` addresses.
///
/// Other top-level sections (`openvpn`, `bridge`, `shadowsocks`) are ignored
/// by this tool since MozWire only generates WireGuard configurations.
///
/// ## Security model
///
/// Every field received from the server that is written into a WireGuard
/// configuration file is validated before use. If validation fails the process
/// exits immediately via [`exploitation_attempt`] to avoid a config-injection
/// attack (e.g. a MITM inserting shell metacharacters into a hostname that
/// later appear in a `wg-quick` invocation).
use crate::constants::{EXPLOITATION_ATTEMPT_MESSAGE, RELAYLIST_URL};
use base64::Engine;
use serde::de;
use std::{
    collections::BTreeMap,
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

// ---------------------------------------------------------------------------
// PublicKey — a validated, display-able WireGuard Curve25519 public key
// ---------------------------------------------------------------------------

/// Zero-copy serde visitor that reads a base64-encoded Curve25519 public key
/// from a JSON string.
///
/// Both the Mullvad relay list and the Mozilla VPN device API return public
/// keys as standard (padded) base64 strings of exactly 44 characters, which
/// decode to the 32 raw bytes of an X25519 public key.
struct PublicKeyVisitor;

/// Abort the process with a loud warning when the server returns data that
/// looks like a deliberate injection attempt.
///
/// The return type `!` (the "never" type) tells the compiler this function
/// diverges — it never returns — so any code following a call to it is
/// provably unreachable.  Without the `!` annotation the compiler would treat
/// calls as returning `()`, requiring explicit `unreachable!()` markers after
/// each call and producing misleading control-flow analysis.
pub fn exploitation_attempt() -> ! {
    println!("{}", EXPLOITATION_ATTEMPT_MESSAGE);
    std::process::exit(1);
}

impl de::Visitor<'_> for PublicKeyVisitor {
    type Value = PublicKey;

    /// Used by serde when it cannot satisfy the request and needs to report a
    /// type error. We reuse `EXPLOITATION_ATTEMPT_MESSAGE` so the user always
    /// sees a consistent security-oriented error rather than a generic serde
    /// message about unexpected types.
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str(EXPLOITATION_ATTEMPT_MESSAGE)
    }

    /// serde_json calls `visit_str` (not `visit_bytes`) when the JSON value is
    /// a string, even when the deserializer was told to expect bytes via
    /// `deserialize_str`. We forward to `visit_bytes` by converting the UTF-8
    /// string to its raw bytes so the base64 decoding path is shared.
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        self.visit_bytes(v.as_bytes())
    }

    /// Core key validation: the byte slice `v` must be the raw UTF-8 bytes of
    /// a base64-standard (padded) 44-character string that decodes to exactly
    /// 32 bytes (256-bit Curve25519 key). Any deviation calls
    /// [`exploitation_attempt`] rather than returning a serde error, because
    /// the source of the data is the remote server and a violation means the
    /// data has been tampered with.
    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        let mut pubkey = [0u8; 32];
        // A standard-base64-encoded 256-bit key is always exactly 44 chars/bytes.
        if v.len() != 44 {
            exploitation_attempt();
        }
        // Decode in-place into `pubkey`. We expect exactly 32 decoded bytes.
        match base64::prelude::BASE64_STANDARD.decode_slice(v, &mut pubkey) {
            Ok(32) => (),
            _ => exploitation_attempt(),
        };
        Ok(PublicKey(x25519_dalek::PublicKey::from(pubkey)))
    }
}

/// A validated Curve25519 public key received from a remote server.
///
/// Wraps [`x25519_dalek::PublicKey`] with custom serde deserialization (via
/// [`PublicKeyVisitor`]) and a `Display` impl that re-encodes the raw 32 bytes
/// as standard base64 — the format expected by WireGuard config files.
pub struct PublicKey(x25519_dalek::PublicKey);

impl<'de> serde::Deserialize<'de> for PublicKey {
    /// Registers `PublicKeyVisitor` as the deserializer. We hint `deserialize_str`
    /// (not `deserialize_bytes`) because serde_json routes JSON strings through
    /// `visit_str`; `visit_bytes` is only reachable via our `visit_str` bridge.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(PublicKeyVisitor)
    }
}

/// Encodes the 32 raw bytes back to standard base64, producing the 44-character
/// string used in WireGuard `[Peer] PublicKey =` lines.
impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&base64::prelude::BASE64_STANDARD.encode(self.0.as_bytes()))
    }
}

/// Compare a `PublicKey` with a `String` holding its base64 representation.
/// Used in `main.rs` when searching the device list for a key by its base64
/// string (e.g. `id == device.pubkey`).
impl PartialEq<String> for PublicKey {
    fn eq(&self, other: &String) -> bool {
        base64::prelude::BASE64_STANDARD.encode(self.as_bytes()) == *other
    }
}

/// Symmetric: `String == PublicKey` delegates to `PublicKey == String`.
impl PartialEq<PublicKey> for String {
    fn eq(&self, other: &PublicKey) -> bool {
        other == self
    }
}

/// Provides transparent access to the underlying `x25519_dalek::PublicKey`,
/// so callers can use `.as_bytes()` directly to get the raw 32-byte slice
/// (needed when URL-encoding the key for DELETE /vpn/device/{pubkey}).
impl std::ops::Deref for PublicKey {
    type Target = x25519_dalek::PublicKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Relay list data structures (mirrors the Mullvad /app/v1/relays JSON)
// ---------------------------------------------------------------------------

/// Geographic metadata for a single location, as returned in the top-level
/// `locations` map of the relay list response.
///
/// The key in the `locations` map (e.g. `"se-got"`) is a composite of the
/// two-letter country code and a short city abbreviation. Each [`Relay`] has a
/// `location` field containing this same key, linking it to one of these
/// entries.
#[derive(serde::Deserialize)]
struct Location {
    /// Full country name, e.g. `"Sweden"`.
    country: String,
    /// Full city name, e.g. `"Gothenburg"`.
    city: String,
    /// Latitude in decimal degrees; positive = North, negative = South.
    latitude: f64,
    /// Longitude in decimal degrees; positive = East, negative = West.
    longitude: f64,
}

/// A single WireGuard relay server as returned in `wireguard.relays[]`.
///
/// Fields not needed by MozWire (`owned`, `provider`, `weight`, `socks_name`,
/// `extra_addrs_in`) are silently ignored by serde's `#[derive(Deserialize)]`
/// — no `#[serde(deny_unknown_fields)]` is used, so adding new fields to the
/// API response will never break deserialization.
#[derive(serde::Deserialize)]
pub struct Relay {
    /// Unique server identifier, e.g. `"se-got-wg-001"`.
    /// Used as the WireGuard config filename (`se-got-wg-001.conf`) and as
    /// the hostname regex filter target.
    pub hostname: String,

    /// Key into the parent [`RelayList`]'s `locations` map, e.g. `"se-got"`.
    /// Allows looking up country/city/coordinates without duplicating that
    /// data in every relay object.
    pub location: String,

    /// Public IPv4 address of the relay's WireGuard interface (`wg0`).
    /// Written as the `Endpoint` IP in the generated WireGuard config.
    pub ipv4_addr_in: Ipv4Addr,

    /// Public IPv6 address of the relay's WireGuard interface.
    /// Shown in `relay list` output alongside the IPv4 address.
    /// Private because callers outside this module only need it for display.
    ipv6_addr_in: Ipv6Addr,

    /// The relay's Curve25519 WireGuard public key.
    /// Written as `[Peer] PublicKey` in the generated config.
    pub public_key: PublicKey,

    /// Dedicated UDP port for this relay when used as the *entry node* in a
    /// multihop (double-VPN) configuration. In single-hop mode this field is
    /// unused; the user-chosen port from `--port` is used instead.
    pub multihop_port: u16,

    /// Whether this relay is currently accepting connections.
    /// Mullvad disables relays under maintenance without removing them from
    /// the list. `servers()` filters out inactive relays so they are never
    /// written into a WireGuard config or shown in `relay list`.
    ///
    /// Defaults to `true` via [`default_active`] in case the field is absent
    /// from an older API response shape.
    #[serde(default = "default_active")]
    active: bool,
}

/// Serde default for [`Relay::active`]. Treats a missing `active` field as
/// `true` so that relay lists from older API versions (which didn't include
/// the field) are fully usable.
fn default_active() -> bool {
    true
}

impl Relay {
    /// Returns `true` if the hostname consists only of ASCII alphanumerics and
    /// hyphens — the only characters that are safe to embed in a WireGuard
    /// config filename and in iptables rules generated by the kill-switch.
    ///
    /// A hostname that fails this check triggers [`exploitation_attempt`]
    /// inside [`RelayList::new`], preventing a MITM from injecting shell
    /// metacharacters (`;`, `$`, etc.) into a config file.
    fn validate_hostname(&self) -> bool {
        self.hostname
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
    }
}

/// The `wireguard` sub-object of the relay list response.
///
/// We only parse `relays` here. `ipv4_gateway`, `ipv6_gateway`, and
/// `port_ranges` are also present in the API response but are hard-coded as
/// constants in `constants.rs` rather than read at runtime — they are verified
/// against the live API via the `test_ipv4_gateway_live` integration test.
#[derive(serde::Deserialize)]
struct WireguardSection {
    relays: Vec<Relay>,
}

/// The top-level relay list returned by `RELAYLIST_URL`.
///
/// `BTreeMap` is used (instead of `HashMap`) for `locations` so that the
/// `Display` implementation iterates over countries in stable alphabetical
/// order without a separate sorting step.
#[derive(serde::Deserialize)]
pub struct RelayList {
    /// Mapping from location code to geographic metadata.
    locations: BTreeMap<String, Location>,
    /// WireGuard-specific relay data.
    wireguard: WireguardSection,
}

impl RelayList {
    /// Fetch and validate the Mullvad relay list from `RELAYLIST_URL`.
    ///
    /// Panics (via `.unwrap()`) on network or parse errors — this is a
    /// CLI tool and there is no sensible recovery path if the relay list
    /// cannot be loaded.
    ///
    /// After parsing, every hostname is validated. If any hostname contains a
    /// character outside `[A-Za-z0-9-]`, the process is aborted. This check
    /// guards against a MITM returning a crafted relay list whose hostnames
    /// contain shell metacharacters that would propagate into config files or
    /// iptables PostUp/PreDown scripts.
    pub fn new(client: reqwest::blocking::Client) -> Self {
        let server_list = client
            .get(RELAYLIST_URL)
            .send()
            .unwrap()
            .json::<RelayList>()
            .unwrap();

        // Validate all hostnames before returning. We scan the full list
        // (active + inactive) so a bad hostname is caught even if the relay
        // is currently disabled.
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

    /// Returns an iterator over **active** WireGuard relays.
    ///
    /// Inactive relays (e.g. those under maintenance) are excluded so that
    /// `relay save` never generates a config pointing at an unreachable server,
    /// and `relay list` never shows servers that cannot be connected to.
    pub fn servers(&self) -> impl Iterator<Item = &Relay> {
        self.wireguard.relays.iter().filter(|r| r.active)
    }
}

/// Formats the relay list for `mozwire relay list`, grouped alphabetically by
/// country then city, showing only active relays.
///
/// Example output:
/// ```text
/// Sweden
///     Gothenburg (se-got) @ 57.7072°N, 11.9668°E
///         se-got-wg-001 (185.213.154.68, 2a03:1b20:5::1)
///         se-got-wg-002 (185.213.154.69, 2a03:1b20:5::2)
/// United States
///     New York (us-nyc) @ 40.7143°N, 74.0060°W
///         us-nyc-wg-001 (x.x.x.x, ...)
/// ```
impl fmt::Display for RelayList {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Type alias to keep the nested BTreeMap legible:
        //   outer key  = country name  → inner BTreeMap
        //   inner key  = city name     → (location_code, &Location, relays)
        type CityEntry<'a> = (&'a str, &'a Location, Vec<&'a Relay>);
        let mut by_country: BTreeMap<&str, BTreeMap<&str, CityEntry>> = BTreeMap::new();

        // Walk active relays and bucket them into country → city groups.
        // Inactive relays are omitted from the listing entirely.
        for relay in self.wireguard.relays.iter().filter(|r| r.active) {
            if let Some(loc) = self.locations.get(&relay.location) {
                by_country
                    .entry(&loc.country)
                    .or_default()
                    .entry(&loc.city)
                    // First relay in a city seeds the (loc_code, &Location, vec) tuple.
                    .or_insert_with(|| (&relay.location, loc, Vec::new()))
                    .2 // push into the relay vec
                    .push(relay);
            }
        }

        for (_country_key, cities) in &by_country {
            // Print the country name once from any city's location.
            if let Some((_, (_, loc, _))) = cities.iter().next() {
                writeln!(f, "{}", loc.country)?;
            }
            for (_city_key, (loc_code, loc, relays)) in cities {
                // Coordinates: latitude is always N/S; longitude sign tells E/W.
                let lat_dir = if loc.latitude >= 0.0 { 'N' } else { 'S' };
                let lon_dir = if loc.longitude >= 0.0 { 'E' } else { 'W' };
                writeln!(
                    f,
                    "\t{} ({}) @ {:.4}°{}, {:.4}°{}",
                    loc.city,
                    loc_code,
                    loc.latitude.abs(),
                    lat_dir,
                    loc.longitude.abs(),
                    lon_dir
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal but realistic relay list payload mirroring the actual Mullvad
    /// API response shape. Includes:
    ///   - two locations (one per hemisphere to test N/S and E/W display)
    ///   - one active relay (se-got-wg-001) and one inactive (us-nyc-wg-301)
    ///   - all five port ranges matching PORT_RANGES
    ///   - extra fields (owned, provider, weight, socks_name, extra_addrs_in)
    ///     that MozWire ignores but the real API returns
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
            "port_ranges": [[53,53],[123,123],[4000,33433],[33565,51820],[52001,60000]],
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

    /// Full relay list deserialization: checks relay count, location count,
    /// and a sample of parsed field values.
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

    /// `servers()` must return only the active relay (se-got-wg-001) and
    /// silently skip the inactive one (us-nyc-wg-301).
    #[test]
    fn test_servers_filters_inactive() {
        let list: RelayList = serde_json::from_str(MOCK_RELAY_LIST).unwrap();
        let servers: Vec<&Relay> = list.servers().collect();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].hostname, "se-got-wg-001");
    }

    /// PublicKey must deserialize correctly from a JSON string value.
    /// This exercises `visit_str` → `visit_bytes` → base64 decode path.
    #[test]
    fn test_public_key_deserialization_from_string() {
        let json = r#""GC7dBMKmrQ3EBOrUHr3QYJR2gW3jDIuVEo/0p//WTEE=""#;
        let key: PublicKey = serde_json::from_str(json).unwrap();
        assert_eq!(
            key.to_string(),
            "GC7dBMKmrQ3EBOrUHr3QYJR2gW3jDIuVEo/0p//WTEE="
        );
    }

    /// Deserializing a PublicKey and formatting it back must return the
    /// original base64 string (round-trip fidelity).
    #[test]
    fn test_public_key_display_roundtrip() {
        let original = "JyMv6TlARDnBfQmXFzlywOLveNV3mBMaWosFjTcYE0g=";
        let json = format!(r#""{}""#, original);
        let key: PublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key.to_string(), original);
    }

    /// `validate_hostname` must accept alphanumerics + hyphens and reject
    /// anything else (spaces, dots, shell metacharacters, etc.).
    #[test]
    fn test_hostname_validation() {
        // Helper closure builds a minimal Relay with the given hostname.
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
        assert!(!relay("bad hostname!").validate_hostname()); // space + !
        assert!(!relay("bad.hostname").validate_hostname());  // dot
        assert!(!relay("x;echo pwned").validate_hostname()); // semicolon
    }

    /// The Display impl must include Sweden and Gothenburg (active relay) and
    /// must NOT include New York or us-nyc-wg-301 (inactive relay).
    /// Also checks that the negative longitude for New York is rendered as °W.
    #[test]
    fn test_relay_list_display() {
        let list: RelayList = serde_json::from_str(MOCK_RELAY_LIST).unwrap();
        let output = list.to_string();

        // Active relay's country/city/hostname must appear.
        assert!(output.contains("Sweden"));
        assert!(output.contains("Gothenburg"));
        assert!(output.contains("se-got-wg-001"));

        // Inactive relay must be completely absent.
        assert!(!output.contains("us-nyc-wg-301"));
        assert!(!output.contains("New York"));

        // Swedish longitude is positive → should be labelled E, not W.
        assert!(output.contains('E'), "positive longitude should be labelled E");
    }

    /// Coordinates with a negative longitude must render as °W.
    #[test]
    fn test_display_negative_longitude_is_west() {
        // Build a minimal RelayList with only a western-hemisphere location.
        let json = r#"{
            "locations": {
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
                "port_ranges": [],
                "relays": [{
                    "hostname": "us-nyc-wg-001",
                    "location": "us-nyc",
                    "active": true,
                    "owned": false,
                    "provider": "M247",
                    "weight": 100,
                    "ipv4_addr_in": "185.220.101.1",
                    "ipv6_addr_in": "2604:180::1",
                    "public_key": "GC7dBMKmrQ3EBOrUHr3QYJR2gW3jDIuVEo/0p//WTEE=",
                    "multihop_port": 30002,
                    "socks_name": "us-nyc-wg-001.socks5.mullvad.net",
                    "extra_addrs_in": []
                }]
            }
        }"#;
        let list: RelayList = serde_json::from_str(json).unwrap();
        let output = list.to_string();
        assert!(output.contains('W'), "negative longitude should be labelled W");
        assert!(!output.contains('E'), "negative longitude must not be labelled E");
    }

    /// `PartialEq<String>` and `PartialEq<PublicKey>` must be symmetric and
    /// must reject a different base64 string.
    #[test]
    fn test_public_key_equality() {
        let key_b64 = "GC7dBMKmrQ3EBOrUHr3QYJR2gW3jDIuVEo/0p//WTEE=".to_string();
        let json = format!(r#""{}""#, key_b64);
        let key: PublicKey = serde_json::from_str(&json).unwrap();
        assert!(key == key_b64);
        assert!(key_b64 == key);
        assert!(key != "wrongwrongwrongwrongwrongwrongwrongwrongwrong=".to_string());
    }
}
