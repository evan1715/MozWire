/// Global constants shared across every module in MozWire.
///
/// These values are derived from the Mullvad and Mozilla VPN APIs. The two
/// ignored integration tests below can be run against the live APIs to verify
/// that the hard-coded values still match what the servers advertise.
use std::net::Ipv4Addr;

/// Mullvad relay list endpoint used by the Mullvad desktop app (v1 is the
/// current and only documented app endpoint as of 2026; no v2 exists yet).
///
/// Response schema (abbreviated):
/// ```json
/// {
///   "locations": { "se-got": { "country": "Sweden", "city": "Gothenburg",
///                              "latitude": 57.7, "longitude": 11.97 } },
///   "wireguard": {
///     "ipv4_gateway": "10.64.0.1",
///     "ipv6_gateway": "fc00:bbbb:bbbb:bb01::1",
///     "port_ranges": [[53,53],[123,123],[4000,33433],[33565,51820],[52001,60000]],
///     "relays": [ { "hostname": "se-got-wg-001", "location": "se-got",
///                   "active": true, "ipv4_addr_in": "...", "ipv6_addr_in": "...",
///                   "public_key": "<base64>", "multihop_port": 30001, ... } ]
///   }
/// }
/// ```
pub const RELAYLIST_URL: &str = "https://api.mullvad.net/app/v1/relays";

/// Base URL for the Mozilla VPN guardian API.
///
/// Mozilla VPN is still an active subscription service as of 2026. It uses
/// Mullvad's WireGuard servers under the hood, which is why MozWire combines
/// device management from this API with the relay list from Mullvad's API.
pub const BASE_URL: &str = "https://vpn.mozilla.org";

/// Path prefix for Mozilla VPN API version 1.
/// Used for: account info (GET /vpn/account), device CRUD (/vpn/device[/{pubkey}]).
pub const V1_API: &str = "/api/v1";

/// Path prefix for Mozilla VPN API version 2.
/// Used for: the OAuth2 PKCE login redirect (/vpn/login/linux) and token
/// exchange (/vpn/login/verify). The v2 login endpoints are separate from v1
/// resource endpoints because the auth flow was redesigned for PKCE.
pub const V2_API: &str = "/api/v2";

/// The WireGuard DNS server advertised by Mullvad for all VPN sessions.
///
/// This is the IPv4 address of Mullvad's DNS resolver inside the VPN tunnel.
/// It is written into every generated WireGuard config as the `DNS =` line.
/// The value is confirmed by the live integration test below.
pub const IPV4_GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 64, 0, 1);

/// Allowed WireGuard endpoint port ranges, as advertised by Mullvad's API.
///
/// Mullvad deliberately supports these unusual ports so that traffic looks
/// like common protocols (53 = DNS, 123 = NTP) and can pass through
/// restrictive firewalls or hide VPN usage from DPI:
///
/// | Range          | Disguise / reason                              |
/// |----------------|------------------------------------------------|
/// | 53–53          | Looks like DNS (UDP port 53)                   |
/// | 123–123        | Looks like NTP (UDP port 123)                  |
/// | 4000–33433     | General ephemeral / unreserved ports           |
/// | 33565–51820    | Includes the standard WireGuard port (51820)   |
/// | 52001–60000    | Additional ephemeral / unreserved ports        |
///
/// The default port is 51820 (standard WireGuard). `--port random` picks any
/// port from the flattened union of all ranges.
///
/// Port 443 was removed by Mullvad in a prior API update (commit 518cb85).
pub const PORT_RANGES: [(u16, u16); 5] = [
    (53, 53),
    (123, 123),
    (4000, 33433),
    (33565, 51820),
    (52001, 60000),
];

/// Message printed to stdout if the server returns data containing characters
/// that should never appear in valid API responses (e.g. shell metacharacters
/// in a hostname). The tool exits immediately to prevent config injection.
pub const EXPLOITATION_ATTEMPT_MESSAGE: &str = "INVALID DATA RETURNED FROM SERVER, THE CONTENT \
                                                COULD HAVE BEEN TEMPERED IN AN ATTEMPT AT \
                                                EXPLOITING VULNERABILITIES";

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity-check that the gateway constant has the expected hard-coded value.
    #[test]
    fn test_ipv4_gateway_value() {
        assert_eq!(IPV4_GATEWAY, Ipv4Addr::new(10, 64, 0, 1));
    }

    /// Verify that PORT_RANGES is sorted and non-overlapping, which is required
    /// for the port validation logic in main.rs that iterates over ranges.
    #[test]
    fn test_port_ranges_are_sorted_non_overlapping() {
        let mut prev_end = 0u16;
        for &(start, end) in &PORT_RANGES {
            assert!(start <= end, "range start > end: {start}..={end}");
            assert!(
                start > prev_end,
                "ranges overlap or are not sorted: prev_end={prev_end}, start={start}"
            );
            prev_end = end;
        }
    }

    /// The CLI default port is 51820 (standard WireGuard). Verify it falls
    /// within one of the allowed PORT_RANGES so validation passes for it.
    #[test]
    fn test_port_51820_in_range() {
        let port: u16 = 51820;
        let in_range = PORT_RANGES.iter().any(|&(s, e)| port >= s && port <= e);
        assert!(in_range, "port 51820 is not in PORT_RANGES");
    }

    /// Verify PORT_RANGES covers the disguise ports (53=DNS, 123=NTP).
    #[test]
    fn test_disguise_ports_in_range() {
        for disguise_port in [53u16, 123u16] {
            assert!(
                PORT_RANGES.iter().any(|&(s, e)| disguise_port >= s && disguise_port <= e),
                "disguise port {disguise_port} not in PORT_RANGES"
            );
        }
    }

    /// Live integration test: fetch the relay list from Mullvad's API and
    /// assert that the gateway IP and port ranges match our hard-coded values.
    ///
    /// This test is `#[ignore]` because it requires network access and hits a
    /// real external server. Run it manually when updating constants:
    ///   cargo test -- --ignored test_ipv4_gateway_live
    #[test]
    #[ignore]
    fn test_ipv4_gateway_live() {
        // Only the wireguard sub-object is needed to check the constants.
        #[derive(serde::Deserialize)]
        struct Wireguard {
            port_ranges: Vec<(u16, u16)>,
            ipv4_gateway: Ipv4Addr,
        }
        #[derive(serde::Deserialize)]
        struct Relays {
            wireguard: Wireguard,
        }
        let relays: Relays = reqwest::blocking::get(RELAYLIST_URL)
            .unwrap()
            .json()
            .unwrap();
        assert_eq!(relays.wireguard.ipv4_gateway, IPV4_GATEWAY);
        let expected: Vec<(u16, u16)> = PORT_RANGES.to_vec();
        assert_eq!(relays.wireguard.port_ranges, expected);
    }
}
