use std::net::Ipv4Addr;

/// Mullvad relay list API - returns WireGuard servers, gateway IPs and port ranges.
pub const RELAYLIST_URL: &str = "https://api.mullvad.net/app/v1/relays";
pub const BASE_URL: &str = "https://vpn.mozilla.org";
pub const V1_API: &str = "/api/v1";
pub const V2_API: &str = "/api/v2";
pub const IPV4_GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 64, 0, 1);
pub const PORT_RANGES: [(u16, u16); 5] = [
    (53, 53),
    (123, 123),
    (4000, 33433),
    (33565, 51820),
    (52001, 60000),
];
pub const EXPLOITATION_ATTEMPT_MESSAGE: &str = "INVALID DATA RETURNED FROM SERVER, THE CONTENT \
                                                COULD HAVE BEEN TEMPERED IN AN ATTEMPT AT \
                                                EXPLOITING VULNERABILITIES";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_gateway_value() {
        assert_eq!(IPV4_GATEWAY, Ipv4Addr::new(10, 64, 0, 1));
    }

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

    #[test]
    fn test_port_51820_in_range() {
        // Default WireGuard port must be within one of the allowed ranges.
        let port: u16 = 51820;
        let in_range = PORT_RANGES.iter().any(|&(s, e)| port >= s && port <= e);
        assert!(in_range, "port 51820 is not in PORT_RANGES");
    }

    /// Verifies RELAYLIST_URL, gateway and port ranges against the live Mullvad API.
    /// Requires network access - run with `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn test_ipv4_gateway_live() {
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
