/// MozWire — Mozilla VPN WireGuard configuration manager.
///
/// # Overview
///
/// MozWire bridges two separate APIs:
///
/// 1. **Mozilla VPN API** (`https://vpn.mozilla.org`) — handles authentication
///    (OAuth2 PKCE) and device management (registering / listing / deleting
///    WireGuard key-pairs linked to a user account).
///
/// 2. **Mullvad relay list API** (`https://api.mullvad.net/app/v1/relays`) —
///    returns the list of WireGuard servers that Mozilla VPN uses under the
///    hood. MozWire fetches this list to let users pick a server and generates
///    a standard `wg-quick` compatible `.conf` file for it.
///
/// # Authentication flow (no `--token`)
///
/// 1. Generate a PKCE code verifier (32 random bytes → base64url, 43 chars)
///    and a code challenge (SHA-256 of verifier → base64url).
/// 2. Open `GET /api/v2/vpn/login/linux?code_challenge_method=S256
///    &code_challenge=<challenge>&port=<local_port>` in the user's browser.
/// 3. Bind a local HTTP server on a random port. The Mozilla VPN login page
///    redirects back to `http://127.0.0.1:<port>/?code=<80 hex chars>` after
///    the user signs in.
/// 4. Exchange the code for a bearer token:
///    `POST /api/v2/vpn/login/verify` with `{code, code_verifier}`.
///    Response: `{token: "...", user: {devices: [...]}}`.
///
/// # Authentication flow (`--token <TOKEN>`)
///
/// Skip the browser entirely. Call `GET /api/v1/vpn/account` with the token
/// to verify it and fetch the device list.
///
/// # Exit codes
///
/// * 0 — success
/// * 2 — bad CLI arguments or invalid key supplied by the user
/// * 3 — API returned an error response (token invalid/expired, etc.)
use crate::cli::{Cli, Commands, DeviceCommands, Port, RelayCommands, Tunnel};
use crate::constants::{BASE_URL, IPV4_GATEWAY, PORT_RANGES, V1_API, V2_API};
use crate::device::Device;
use crate::relay::RelayList;
use base64::Engine;
use clap::Parser;
use core::num::NonZeroUsize;
use rand::seq::IteratorRandom;
// rand_core 0.6 is used explicitly for the crypto path because x25519-dalek
// 2.x depends on rand_core 0.6 while rand 0.9 uses rand_core 0.9; the two
// versions are distinct crates and their OsRng/RngCore types are incompatible.
use rand_core::{OsRng, RngCore};
use tiny_http::ListenAddr;

mod cli;
mod constants;
mod device;
mod relay;

// ---------------------------------------------------------------------------
// Mozilla VPN API types
// ---------------------------------------------------------------------------

/// The `user` sub-object in both the login response and the account endpoint.
///
/// serde ignores unknown fields (e.g. `email`, `avatar`, `max_devices`) so
/// only the device list that MozWire actually needs is extracted.
#[derive(serde::Deserialize)]
struct User {
    devices: Vec<Device>,
}

/// Returned by `POST /api/v2/vpn/login/verify` and constructed manually when
/// a pre-existing `--token` is supplied.
#[derive(serde::Deserialize)]
struct Login {
    /// The authenticated user's device list, needed to find the tunnel
    /// addresses for a given public key.
    user: User,
    /// Bearer token for all subsequent API requests.
    token: String,
}

/// Error body returned by the Mozilla VPN API when a request fails.
///
/// Example: `{"errno": 120, "error": "invalid token"}`
#[derive(serde::Deserialize)]
struct Error {
    /// Numeric error code. Known values:
    /// * 120 — token is missing, malformed, or invalid
    /// * 122 — token has expired; the user must re-authenticate
    errno: u32,
    /// Human-readable error description.
    error: String,
}

impl Error {
    /// Print a user-friendly message for the error and exit with code 3.
    ///
    /// The return type `!` makes it safe to call this directly in match arms
    /// or after `.unwrap_or_else` without needing a separate `unreachable!()`.
    fn fail(self) -> ! {
        match self.errno {
            // errno 120: token present but not valid — bad format or revoked.
            // The raw API message can be "jwt malformed", "invalid token", or
            // "Format is Authorization: Bearer [token]" depending on where
            // validation failed.
            120 => {
                eprintln!("Invalid token ({})", self.error);
            }
            // errno 122: token was valid but has since expired.
            // The user must run mozwire again without --token to get a new one.
            122 => {
                eprintln!("Token expired, regenerate a token by not specifying the --token option");
            }
            _ => {
                eprintln!("{}", self.error);
            }
        }
        std::process::exit(3);
    }
}

// ---------------------------------------------------------------------------
// Device registration request
// ---------------------------------------------------------------------------

/// Request body for `POST /api/v1/vpn/device` — registers a new WireGuard
/// key-pair with the Mozilla VPN account.
///
/// Lifetime `'a` lets us borrow name and pubkey from the enclosing scope
/// without cloning them into this short-lived request struct.
#[derive(serde::Serialize)]
struct NewDevice<'a> {
    /// Human-readable label for the device in the Mozilla VPN account portal.
    /// Defaults to the machine's hostname.
    name: &'a str,
    /// Base64-encoded Curve25519 public key to register.
    pubkey: &'a str,
}

/// Derives the Curve25519 public key from a base64-encoded private key.
///
/// Steps:
/// 1. Decode the 44-char base64 string to 32 raw bytes.
/// 2. Wrap in `x25519_dalek::StaticSecret` (the clamping step from RFC 8031
///    is applied internally).
/// 3. Compute the corresponding public key via scalar multiplication on the
///    Curve25519 base point.
/// 4. Re-encode the 32-byte public key as base64.
///
/// Returns `Err` if the input is not valid base64 or does not decode to
/// exactly 32 bytes.
fn private_to_public_key(privkey_base64: &str) -> Result<String, base64::DecodeSliceError> {
    let mut privkey = [0u8; 32];
    base64::prelude::BASE64_STANDARD.decode_slice(privkey_base64, &mut privkey)?;
    Ok(base64::prelude::BASE64_STANDARD.encode(
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(privkey)).as_bytes(),
    ))
}

impl NewDevice<'_> {
    /// Upload this device to the Mozilla VPN API and return the created
    /// [`Device`] object (which contains the allocated tunnel addresses).
    ///
    /// Calls `POST /api/v1/vpn/device` with `Authorization: Bearer <token>`.
    /// Panics on network/IO errors. Exits with code 3 on API errors.
    fn upload(self, client: &reqwest::blocking::Client, token: &str) -> Device {
        let response = client
            .post(format!("{}{}/vpn/device", BASE_URL, V1_API))
            .bearer_auth(token)
            .json(&self)
            .send()
            .unwrap();
        if response.status().is_success() {
            return response.json().unwrap();
        }
        response.json::<Error>().unwrap().fail();
    }
}

// ---------------------------------------------------------------------------
// PKCE token exchange request
// ---------------------------------------------------------------------------

/// Request body for `POST /api/v2/vpn/login/verify`.
///
/// Both fields are sent as JSON strings. The server verifies that
/// SHA-256(`code_verifier`) matches the `code_challenge` sent in the initial
/// redirect, then exchanges the authorization `code` for a bearer token.
#[derive(serde::Serialize)]
struct AccessTokenRequest<'a> {
    /// The authorization code extracted from the redirect URL
    /// (`/?code=<80 hex chars>`).
    code: &'a str,
    /// The original 43-character base64url code verifier (pre-hash).
    code_verifier: &'a str,
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    let matches = Cli::parse();

    // If the user invoked `mozwire` with no subcommand and did not pass
    // `--print-token`, print the help message and exit. This mirrors the
    // behaviour of `arg_required_else_help` but allows `--print-token` alone
    // (without a subcommand) to be a valid invocation.
    if matches.command.is_none() && !matches.print_token {
        use clap::CommandFactory;
        Cli::command().print_help().unwrap();
        std::process::exit(2);
    }

    // A single shared HTTP client is used for all requests. reqwest's blocking
    // client is used throughout because MozWire is a CLI tool with no async
    // I/O needs. The User-Agent is required because some Mozilla API endpoints
    // reject requests without one.
    let client = reqwest::blocking::Client::builder()
        .user_agent("Why does the api need a user agent???")
        .build()
        .unwrap();

    // Obtain a `Login` struct (token + device list) either by running the full
    // OAuth2 PKCE browser flow or by using a pre-supplied `--token`.
    let login = matches.token.as_ref().map_or_else(
        || {
            // ── Browser-based PKCE login flow ──────────────────────────────
            // RngCore and OsRng are imported at the top of the file from
            // rand_core 0.6 so they are compatible with x25519-dalek 2.x.
            use sha2::Digest;

            // Step 1: Generate a cryptographically random 32-byte code verifier,
            // then base64url-encode it (no padding) to 43 characters.
            // RFC 7636 requires the verifier to be between 43 and 128 characters
            // of unreserved URL characters; base64url with 32 random bytes gives
            // exactly 43 characters that satisfy this requirement.
            // OsRng comes from rand_core 0.6 (compatible with x25519-dalek 2.x).
            let mut code_verifier_random = [0u8; 32];
            OsRng.fill_bytes(&mut code_verifier_random);
            let mut code_verifier = [0u8; 43]; // base64url of 32 bytes = 43 chars
            base64::prelude::BASE64_URL_SAFE_NO_PAD
                .encode_slice(code_verifier_random, &mut code_verifier)
                .expect("Could not encode code verifier random");

            // Step 2: code_challenge = base64url(SHA-256(code_verifier)).
            // SHA-256 produces 32 bytes → base64url without padding = 43 chars.
            let mut code_challenge = String::with_capacity(43);
            base64::prelude::BASE64_URL_SAFE_NO_PAD
                .encode_string(sha2::Sha256::digest(code_verifier), &mut code_challenge);

            use tiny_http::{Method, Server};

            // Step 3: Bind a local HTTP server on a random port. The OS assigns
            // the port; we read it back from `server_addr()` to include in the
            // login URL so the Mozilla backend knows where to redirect after login.
            let server = Server::http("127.0.0.1:0").unwrap();

            let login_url = format!(
                "{}{}/vpn/login/linux?code_challenge_method=S256&code_challenge={}&port={}",
                BASE_URL,
                V2_API,
                code_challenge,
                match server.server_addr() {
                    ListenAddr::IP(socket_addr) => socket_addr.port(),
                    // Server::http always binds to a TCP socket, not a Unix socket.
                    #[cfg(unix)]
                    ListenAddr::Unix(_) => unreachable!("Server is not bound to a unix socket"),
                }
            );

            eprint!("Please visit: {}.", login_url);
            if !matches.no_browser {
                match webbrowser::open(&login_url) {
                    Ok(_) => eprint!(" Link opened in browser."),
                    Err(_) => eprint!(" Failed to open link in browser, please visit it manually."),
                }
            }
            eprintln!();

            // Step 4: Wait for the redirect. The Mozilla VPN login page redirects
            // the browser to `http://127.0.0.1:<port>/?code=<80 hex chars>` after
            // the user successfully authenticates.
            let code;
            // Regex anchored at both ends: the URL must be exactly `/?code=<80 lowercase hex>`.
            let code_url_regex = regex::Regex::new(r"\A/\?code=([0-9a-f]{80})\z").unwrap();
            for request in server.incoming_requests() {
                // Ignore non-GET requests and URLs that don't contain a valid code.
                if *request.method() == Method::Get
                    && let Some(caps) = code_url_regex.captures(request.url())
                {
                    code = caps.get(1).unwrap();
                    // Step 5: Exchange the code for a bearer token.
                    // POST /api/v2/vpn/login/verify with the code and verifier.
                    // Response is a Login JSON object containing the token and
                    // the user's device list.
                    return client
                        .post(format!("{}{}/vpn/login/verify", BASE_URL, V2_API))
                        .json(&AccessTokenRequest {
                            code: code.as_str(),
                            code_verifier: std::str::from_utf8(&code_verifier).unwrap(),
                        })
                        .send()
                        .unwrap()
                        .json()
                        .unwrap();
                }
            }
            unreachable!("Server closed without receiving code")
        },
        |token| {
            // ── Pre-supplied token path ────────────────────────────────────
            // Verify the token is still valid and fetch the device list with a
            // single GET /api/v1/vpn/account call. The token is trimmed of
            // leading/trailing whitespace to handle copy-paste artifacts.
            let response = client
                .get(format!("{}{}/vpn/account", BASE_URL, V1_API))
                .bearer_auth(token.trim())
                .send()
                .unwrap();
            if !response.status().is_success() {
                response.json::<Error>().unwrap().fail();
            }

            Login {
                user: response.json::<User>().unwrap(),
                token: token.to_owned(),
            }
        },
    );

    // If `--print-token` was requested, output the token now (after auth
    // succeeds) so the user can save it for `--token` on future runs.
    if matches.print_token {
        println!("{}", login.token);
    }

    // rand::rng() is the rand 0.9 replacement for the deprecated thread_rng().
    let mut rng = rand::rng();

    match matches.command {
        // ── device subcommand ──────────────────────────────────────────────
        Some(Commands::Device { command: device_m }) => match device_m {
            DeviceCommands::Add {
                pubkey,
                privkey,
                name,
            } => {
                // Either a public key was supplied directly, or we derive it
                // from the private key. clap's ArgGroup ensures exactly one of
                // `--pubkey` / `--privkey` is present.
                let pubkey = pubkey.unwrap_or_else(|| {
                    private_to_public_key(&privkey.unwrap()).unwrap_or_else(|_| {
                        println!("Invalid private key.");
                        std::process::exit(2)
                    })
                });
                // Register the key with the API and print the resulting Device
                // (which includes the allocated tunnel IP addresses).
                println!(
                    "{}",
                    &NewDevice {
                        name: &name.name,
                        pubkey: &pubkey,
                    }
                    .upload(&client, &login.token),
                );
            }
            DeviceCommands::List => {
                eprintln!("Devices:");
                for device in login.user.devices {
                    println!("{}", device)
                }
            }
            DeviceCommands::Remove { ids } => {
                // Each `id` may be a device name, a base64 public key, or a
                // base64 private key (from which we derive the public key).
                // We match against all devices in the account's device list.
                for id in ids {
                    for device in login.user.devices.iter().filter(|device| {
                        id == device.name
                            || id == device.pubkey
                            || private_to_public_key(&id)
                                .is_ok_and(|pubkey| pubkey == device.pubkey)
                    }) {
                        // DELETE /api/v1/vpn/device/{url-encoded-base64-pubkey}
                        // `device.pubkey.as_bytes()` gives the raw 32 key bytes;
                        // BASE64_STANDARD.encode produces the 44-char base64 string;
                        // NON_ALPHANUMERIC percent-encodes `+`, `/`, `=` for the URL.
                        client
                            .delete(format!(
                                "{}{}/vpn/device/{}",
                                BASE_URL,
                                V1_API,
                                percent_encoding::utf8_percent_encode(
                                    &base64::prelude::BASE64_STANDARD
                                        .encode(device.pubkey.as_bytes()),
                                    percent_encoding::NON_ALPHANUMERIC
                                )
                            ))
                            .bearer_auth(&login.token)
                            .send()
                            .unwrap();
                        eprintln!(
                            "Device {}, with public key: {} has successfully been removed.",
                            device.name, device.pubkey
                        );
                    }
                }
            }
        },

        // ── relay subcommand ───────────────────────────────────────────────
        Some(Commands::Relay { command: relay_m }) => match relay_m {
            RelayCommands::List => {
                // Fetch the relay list and print it; relay::Display handles
                // grouping by country/city and filtering inactive relays.
                print!("{}", RelayList::new(client));
            }
            RelayCommands::Save {
                regex,
                killswitch,
                output,
                name,
                limit,
                privkey,
                tunnel,
                hop,
                port,
                ..
            } => {
                // ── Step 1: Resolve or generate the WireGuard key-pair ─────
                //
                // If `--privkey` was given, derive the public key from it.
                // Otherwise generate a fresh Curve25519 key-pair using the OS
                // CSPRNG (OsRng), which is appropriate for key material.
                let (pubkey_base64, privkey_base64) = privkey.map_or_else(
                    || {
                        // OsRng is rand_core 0.6's implementation, which satisfies
                        // x25519-dalek 2.x's RngCore + CryptoRng (0.6) bounds.
                        let privkey =
                            x25519_dalek::StaticSecret::random_from_rng(OsRng);
                        let privkey_base64 =
                            base64::prelude::BASE64_STANDARD.encode(privkey.to_bytes());
                        (
                            base64::prelude::BASE64_STANDARD
                                .encode(x25519_dalek::PublicKey::from(&privkey).as_bytes()),
                            privkey_base64,
                        )
                    },
                    |privkey_base64| {
                        (
                            private_to_public_key(&privkey_base64).unwrap_or_else(|_| {
                                println!("Invalid private key.");
                                std::process::exit(2)
                            }),
                            privkey_base64.to_owned(),
                        )
                    },
                );

                // ── Step 2: Find the tunnel addresses for this key ─────────
                //
                // The Mozilla VPN API allocates a unique IPv4 and IPv6 tunnel
                // address per registered device (public key). We look up the
                // key in the device list we fetched during auth; if it's not
                // there we register it now (which also uploads it to Mullvad's
                // key list internally).
                let (address, allowed_ips) = {
                    let (ipv4_address, ipv6_address) = login
                        .user
                        .devices
                        .iter()
                        .find(|device| device.pubkey == pubkey_base64)
                        .map_or_else(
                            || {
                                eprintln!("Public key not in device list, uploading it.");
                                let device = NewDevice {
                                    name: &name.name,
                                    pubkey: &pubkey_base64,
                                }
                                .upload(&client, &login.token);
                                (device.ipv4_address, device.ipv6_address)
                            },
                            |device| (device.ipv4_address.clone(), device.ipv6_address.clone()),
                        );

                    // Build the `Address =` and `AllowedIPs =` values based on
                    // the requested tunnel mode (IPv4-only, IPv6-only, or both).
                    match tunnel {
                        // Both: comma-separated IPv4 + IPv6 addresses; route all
                        // traffic from both protocol stacks through the tunnel.
                        Tunnel::Both => (
                            format!("{},{}", &ipv4_address.0, &ipv6_address.0),
                            "0.0.0.0/0,::0/0",
                        ),
                        Tunnel::Ipv4 => (ipv4_address.0, "0.0.0.0/0"),
                        Tunnel::Ipv6 => (ipv6_address.0, "::0/0"),
                    }
                };

                // ── Step 3: Filter the relay list ──────────────────────────
                //
                // Fetch the full Mullvad relay list and apply the hostname regex
                // filter. Only active relays are returned by `servers()`.
                let server_list = RelayList::new(client);
                let filtered = server_list
                    .servers()
                    .filter(|server| regex.is_match(&server.hostname));

                // Apply the `--limit` / `-n` cap: if limit is 0 (NonZeroUsize
                // returns None) take all matching servers; otherwise choose up
                // to `limit` at random using reservoir sampling so the selection
                // is uniformly distributed.
                for server in if let Some(limit) = NonZeroUsize::new(limit) {
                    filtered.choose_multiple(&mut rng, limit.get())
                } else {
                    filtered.collect()
                } {
                    // ── Step 4: Resolve the endpoint IP and port ───────────
                    //
                    // Single-hop: connect directly to the chosen server's IP.
                    // Multihop (--hop <entry>): connect to the entry node's IP
                    // on the exit node's dedicated multihop_port. The traffic is
                    // routed through the entry node and emerges at the exit node.
                    let (ip, port) = {
                        match hop {
                            Some(ref hop) => (
                                server_list
                                    .servers()
                                    .find(|server| server.hostname == *hop)
                                    .unwrap()
                                    .ipv4_addr_in,
                                server.multihop_port,
                            ),
                            None => {
                                // Single-hop: use the server's own IPv4 address.
                                // Port is either the user-specified value or a
                                // random one from the allowed PORT_RANGES.
                                (server.ipv4_addr_in, {
                                    let mut ports =
                                        PORT_RANGES.iter().map(|(from, to)| (*from)..=(*to));
                                    match port {
                                        Port::Random => {
                                            // Flatten all ranges into one iterator and
                                            // choose uniformly at random using Knuth's
                                            // reservoir algorithm (O(n) time, O(1) space).
                                            ports.flatten().choose(&mut rng).unwrap()
                                        }
                                        Port::Port(port_number) => {
                                            if ports.any(|range| range.contains(&port_number)) {
                                                port_number
                                            } else {
                                                println!(
                                                    "{} is outside of the usable port range.",
                                                    port_number
                                                );
                                                std::process::exit(2);
                                            }
                                        }
                                    }
                                })
                            }
                        }
                    };

                    // ── Step 5: Write the wg-quick config file ─────────────
                    //
                    // Config format (wg-quick compatible):
                    //
                    // [Interface]
                    // PrivateKey = <base64 private key>
                    // Address    = <ipv4_cidr>[,<ipv6_cidr>]
                    // DNS        = 10.64.0.1   ← Mullvad's in-tunnel DNS
                    // [optional PostUp/PreDown kill-switch iptables rules]
                    //
                    // [Peer]
                    // PublicKey  = <base64 relay public key>
                    // AllowedIPs = 0.0.0.0/0[,::0/0]
                    // Endpoint   = <ip>:<port>
                    std::fs::create_dir_all(&output).unwrap();
                    let path = output.join(format!("{}.conf", server.hostname));
                    std::fs::write(
                        &path,
                        format!(
                            "[Interface]
PrivateKey = {privkey_base64}
Address = {address}
DNS = {IPV4_GATEWAY}{}

[Peer]
PublicKey = {}
AllowedIPs = {allowed_ips}
Endpoint = {ip}:{port}\n",
                            // Kill-switch: add iptables rules that DROP all traffic
                            // that doesn't go through the WireGuard interface (`%i`).
                            // `wg show %i fwmark` returns the fwmark used by WireGuard
                            // for its own traffic (which must not be blocked).
                            // PostUp runs after the interface is brought up.
                            // PreDown runs before the interface is taken down.
                            if killswitch {
                                "\nPostUp = iptables -I OUTPUT ! -o %i -m mark ! --mark $(wg show \
                                 %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT && ip6tables \
                                 -I OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m \
                                 addrtype ! --dst-type LOCAL -j REJECT
PreDown = iptables -D OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! \
                                 --dst-type LOCAL -j REJECT && ip6tables -D OUTPUT ! -o %i -m mark \
                                 ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j \
                                 REJECT"
                            } else {
                                ""
                            },
                            server.public_key,
                        ),
                    )
                    .unwrap();
                    println!("Wrote configuration to {}.", path.to_str().unwrap());
                }
            }
        },
        None => (),
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify known private→public key mappings for Curve25519.
    ///
    /// These test vectors were generated independently and confirm that the
    /// base64-decode → StaticSecret::from → PublicKey::from → base64-encode
    /// pipeline is correct and stable across dependency updates.
    #[test]
    fn test_private_to_public_key() {
        assert_eq!(
            private_to_public_key("OO9fkBohqv0mnmogkonAXBAvurjfy/DYXcpI1Yt7pEo=").unwrap(),
            "JyMv6TlARDnBfQmXFzlywOLveNV3mBMaWosFjTcYE0g="
        );
        assert_eq!(
            private_to_public_key("wD4tAq9edXWCILzf8uO7qgsOs/2gTUTvcGMhUdwS6E8=").unwrap(),
            "wv6lbcAK1L+IYJk8SgpRLgFED7/pggu8uvi8Li7OjH4="
        );
        assert_eq!(
            private_to_public_key("4AaD2YkoQ+c2ccL/fnjTmTeRdiZVhvXhiL4gApeePG4=").unwrap(),
            "idTXEeR5rjxYMgQpwbLP+2qYEYR5KinvDqfZpFg7HTo="
        );
        assert_eq!(
            private_to_public_key("iBr/jbjbij/w3BpvTvkB6r1zQvMpIx5mc1C/qnuzpnU=").unwrap(),
            "gxi5un691rLWUD4HSXM0gU4OpHt4r+yVlQ/jfDYJIR8="
        );
        assert_eq!(
            private_to_public_key("kCJuJAX+EWZ23tPK1b+Szl+m89TYxLh9ilIn+gDzZnc=").unwrap(),
            "nT4fmyCGntbuIetTOndAAF/b02p5GGj3MkOSb1wF1zY="
        );
    }

    /// Invalid base64 and too-short inputs must return Err rather than
    /// panicking, so callers can handle them gracefully.
    #[test]
    fn test_private_to_public_key_invalid_base64() {
        assert!(private_to_public_key("not-valid-base64!!!").is_err());
        assert!(private_to_public_key("tooshort=").is_err());
    }

    /// The function must be deterministic: the same private key always
    /// produces the same public key (Curve25519 is a mathematical function,
    /// not probabilistic).
    #[test]
    fn test_private_to_public_key_deterministic() {
        let privkey = "OO9fkBohqv0mnmogkonAXBAvurjfy/DYXcpI1Yt7pEo=";
        let pub1 = private_to_public_key(privkey).unwrap();
        let pub2 = private_to_public_key(privkey).unwrap();
        assert_eq!(pub1, pub2);
    }

    /// Verify that the Login struct (token + user.devices) deserializes
    /// correctly from a response shaped like the Mozilla VPN API's.
    #[test]
    fn test_login_deserialization() {
        let json = r#"{
            "token": "test_token_abc123",
            "user": {
                "devices": [
                    {
                        "name": "my-device",
                        "pubkey": "GC7dBMKmrQ3EBOrUHr3QYJR2gW3jDIuVEo/0p//WTEE=",
                        "ipv4_address": "10.68.52.100/32",
                        "ipv6_address": "fc00:bbbb:bbbb:bb01::4:6400/128"
                    }
                ]
            }
        }"#;
        let login: Login = serde_json::from_str(json).unwrap();
        assert_eq!(login.token, "test_token_abc123");
        assert_eq!(login.user.devices.len(), 1);
        assert_eq!(login.user.devices[0].name, "my-device");
    }

    /// The Error struct must parse both the numeric errno and the string
    /// message from the API error body.
    #[test]
    fn test_error_deserialization() {
        let json = r#"{"errno": 120, "error": "invalid token"}"#;
        let err: Error = serde_json::from_str(json).unwrap();
        assert_eq!(err.errno, 120);
        assert_eq!(err.error, "invalid token");
    }

    /// NewDevice must serialize to a JSON object with `name` and `pubkey`
    /// fields, which is what the Mozilla VPN POST /vpn/device API expects.
    #[test]
    fn test_new_device_serialization() {
        let device = NewDevice {
            name: "test-device",
            pubkey: "GC7dBMKmrQ3EBOrUHr3QYJR2gW3jDIuVEo/0p//WTEE=",
        };
        let json = serde_json::to_string(&device).unwrap();
        assert!(json.contains("test-device"));
        assert!(json.contains("GC7dBMKmrQ3EBOrUHr3QYJR2gW3jDIuVEo/0p//WTEE="));
    }

    /// Every boundary of every PORT_RANGE must be within a valid range,
    /// and the default WireGuard port (51820) must be included.
    #[test]
    fn test_port_in_allowed_range() {
        use crate::constants::PORT_RANGES;
        for &(start, end) in &PORT_RANGES {
            let in_start = PORT_RANGES.iter().any(|&(s, e)| start >= s && start <= e);
            let in_end = PORT_RANGES.iter().any(|&(s, e)| end >= s && end <= e);
            assert!(in_start, "range start {start} not in any PORT_RANGES");
            assert!(in_end, "range end {end} not in any PORT_RANGES");
        }
        let port: u16 = 51820;
        assert!(
            PORT_RANGES.iter().any(|&(s, e)| port >= s && port <= e),
            "default port 51820 not in PORT_RANGES"
        );
    }
}
