/// Device management data structures for the Mozilla VPN API.
///
/// In Mozilla VPN's model every WireGuard key-pair is associated with a
/// "device" entry in the user's account. When a device is registered the
/// Mozilla backend allocates an IPv4 address (in the 10.64.0.0/10 range) and
/// an IPv6 address (in the fc00:bbbb:bbbb:bb01::/64 range) that become the
/// tunnel interface addresses for that key-pair.
///
/// This module contains:
/// * [`IpAddrCIDR`] — a validated IP-address-with-prefix-length string, used
///   for both the IPv4 and IPv6 interface addresses returned by the device API.
/// * [`Device`] — a single registered device as returned by the API.
use crate::{
    constants::EXPLOITATION_ATTEMPT_MESSAGE,
    relay::{PublicKey, exploitation_attempt},
};
use serde::de;
use std::fmt;

// ---------------------------------------------------------------------------
// IpAddrCIDR — a security-validated IP address + prefix length string
// ---------------------------------------------------------------------------

/// Returns `true` if `c` is a valid character in an IP address or CIDR
/// notation string.
///
/// Allowed characters:
/// * ASCII hex digits (`0–9`, `a–f`, `A–F`) — IPv4 decimal octets and IPv6 hex groups
/// * `/` — separates the address from the prefix length
/// * `.` — separates IPv4 octets
/// * `:` — separates IPv6 groups
///
/// Everything else (spaces, letters outside hex, shell metacharacters, etc.)
/// is rejected by [`IpAddrCidrVisitor::visit_str`].
fn is_ip_addr(c: char) -> bool {
    c.is_ascii_hexdigit() || c == '/' || c == '.' || c == ':'
}

/// serde visitor for [`IpAddrCIDR`].
///
/// We implement a custom visitor (rather than deriving `Deserialize` on a
/// `String` field) so that character validation happens at parse time, before
/// the string is stored anywhere. A server-returned string containing shell
/// metacharacters would otherwise be written verbatim into the WireGuard
/// config's `Address =` line and could be dangerous if the file is later
/// processed by a shell script or `wg-quick`.
pub struct IpAddrCidrVisitor;

impl de::Visitor<'_> for IpAddrCidrVisitor {
    type Value = IpAddrCIDR;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str(EXPLOITATION_ATTEMPT_MESSAGE)
    }

    /// Validates every character in the JSON string value. If any character
    /// is not in the allowed IP-address set the process is immediately aborted
    /// via [`exploitation_attempt`] — this is treated as a deliberate
    /// tampering attempt rather than a recoverable parse error.
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        if !v.chars().all(is_ip_addr) {
            exploitation_attempt();
        }
        Ok(IpAddrCIDR(v.to_string()))
    }
}

/// An IP address with CIDR prefix length (e.g. `"10.68.52.100/32"` or
/// `"fc00:bbbb:bbbb:bb01::4:6400/128"`), validated at parse time to contain
/// only characters that are safe to embed in a WireGuard config file.
///
/// Stored as a plain `String` rather than a parsed `IpAddr` + prefix length
/// because `wg-quick` reads the `Address =` field as a raw string anyway and
/// because parsing + re-formatting could change the canonical representation
/// (e.g. IPv6 zero-compression).
///
/// `Clone` is derived because the address must be moved into both the
/// `address` string (for the `[Interface] Address =` line) and the outer
/// scope; see `main.rs` where both `ipv4_address` and `ipv6_address` are
/// cloned from a `&Device`.
#[derive(Clone)]
pub struct IpAddrCIDR(pub String);

impl<'de> serde::Deserialize<'de> for IpAddrCIDR {
    /// Uses `deserialize_str` so serde_json routes JSON string values through
    /// `IpAddrCidrVisitor::visit_str` for character validation.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(IpAddrCidrVisitor)
    }
}

/// Transparent deref so `*addr` or `&*addr` gives the inner `&String`,
/// allowing callers to use the CIDR string with any `str`-accepting API
/// (e.g. `format!`, `writeln!`) without going through `.0`.
impl std::ops::Deref for IpAddrCIDR {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Device — a registered WireGuard device in the Mozilla VPN account
// ---------------------------------------------------------------------------

/// A WireGuard device registered with the Mozilla VPN API.
///
/// The API returns extra fields (e.g. `created_at`) that serde silently
/// ignores because `#[serde(deny_unknown_fields)]` is not applied.
///
/// Field meaning:
/// * `name` — human-readable label set by the user at registration time.
/// * `pubkey` — the Curve25519 public key; also used as the device's unique
///   identifier in the DELETE `/api/v1/vpn/device/{pubkey}` endpoint.
/// * `ipv4_address` — the VPN tunnel IPv4 address for this device, in CIDR
///   notation (e.g. `10.68.52.100/32`). Written to `[Interface] Address =`.
/// * `ipv6_address` — the VPN tunnel IPv6 address for this device, in CIDR
///   notation (e.g. `fc00:bbbb:bbbb:bb01::4:6400/128`).
#[derive(serde::Deserialize)]
pub struct Device {
    pub name: String,
    pub pubkey: PublicKey,
    pub ipv4_address: IpAddrCIDR,
    pub ipv6_address: IpAddrCIDR,
}

/// Human-readable one-line summary used by `mozwire device list`.
///
/// Format: `- <name>: <pubkey>, <ipv4_address>, <ipv6_address>`
impl fmt::Display for Device {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "- {}: {}, {}, {}",
            self.name, self.pubkey, self.ipv4_address.0, self.ipv6_address.0
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid IPv4 CIDR address parses without error.
    #[test]
    fn test_ip_addr_cidr_valid() {
        let json = r#""10.68.52.100/32""#;
        let addr: IpAddrCIDR = serde_json::from_str(json).unwrap();
        assert_eq!(*addr, "10.68.52.100/32");
    }

    /// A valid IPv6 CIDR address (including colons and slashes) parses without
    /// error — verifies that `:` and `/` are in the allowed character set.
    #[test]
    fn test_ip_addr_cidr_ipv6() {
        let json = r#""fc00:bbbb:bbbb:bb01::4:6400/128""#;
        let addr: IpAddrCIDR = serde_json::from_str(json).unwrap();
        assert_eq!(*addr, "fc00:bbbb:bbbb:bb01::4:6400/128");
    }

    /// A complete Device JSON blob (as returned by the Mozilla VPN API)
    /// deserializes correctly, with all fields accessible.
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

    /// Device Display produces a line that includes the name, public key,
    /// and IPv4 address.
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

    /// `PartialEq<String>` and `PartialEq<PublicKey>` must work symmetrically,
    /// and must reject a string that differs from the actual key.
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
        assert!(device.pubkey == key_str);    // PublicKey == String
        assert!(key_str == device.pubkey);    // String == PublicKey (symmetric)
        assert!(device.pubkey != "wrong_key".to_string());
    }
}
