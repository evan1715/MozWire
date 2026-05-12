/// Command-line interface definition for MozWire.
///
/// Uses `clap` v4 with the derive API. The full argument tree is:
///
/// ```text
/// mozwire [--token TOKEN] [--no-browser] [--print-token]
///   device
///     add  (--pubkey KEY | --privkey KEY) [--name NAME]
///     list
///     remove ID...
///   relay
///     list
///     save [REGEX] [-o DIR] [--privkey KEY] [-p PORT] [--tunnel MODE]
///          [-n N] [--killswitch] [--hop HOSTNAME] [--name NAME]
/// ```
///
/// Every user-facing string appears in the doc-comment above the field/variant
/// and is picked up by clap's derive macros for `--help` output.
use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};
use regex::Regex;
use std::path::PathBuf;
use std::{num::ParseIntError, str::FromStr};

// ---------------------------------------------------------------------------
// Top-level CLI struct
// ---------------------------------------------------------------------------

/// Root of the argument tree. Parsed by `Cli::parse()` in `main`.
///
/// clap's `arg_required_else_help = true` would normally require a subcommand,
/// but we handle the "no subcommand, no --print-token" case manually in main
/// so that `--print-token` alone is a valid invocation.
#[derive(Parser)]
#[clap(
    author,
    about,
    version,
    after_help = "To query MozillaVPN, mozwire requires a token, specified with --token. If it is \
                  left unspecified, mozwire will generate a token by opening a login page, the \
                  token generated can be printed using --print-token, so that it can be reused. \
                  To generate a WireGuard configuration use `mozwire relay save`.",
    arg_required_else_help = true
)]
pub struct Cli {
    /// The subcommand to run (`device` or `relay`).
    /// `Option` because `--print-token` alone, without any subcommand, is valid.
    #[command(subcommand)]
    pub(crate) command: Option<Commands>,

    /// Suppress automatic browser opening during the PKCE login flow.
    ///
    /// By default, MozWire opens the login URL in the system browser. Pass
    /// `--no-browser` in headless or CI environments where no browser is
    /// available; the URL is printed to stderr so it can be opened manually.
    #[arg(long, global = true)]
    pub(crate) no_browser: bool,

    /// Pre-existing Mozilla VPN bearer token.
    ///
    /// If supplied, the browser-based login flow is skipped and this token is
    /// used directly for all API calls. The token can also be provided via the
    /// `MOZ_TOKEN` environment variable, which is convenient for scripts.
    ///
    /// Obtain a token on first run with `--print-token` and store it for
    /// subsequent runs.
    #[arg(long, global = true, env = "MOZ_TOKEN")]
    pub(crate) token: Option<String>,

    /// Print the bearer token to stdout after authentication.
    ///
    /// Useful for capturing the token from the first run so it can be passed
    /// as `--token` or `MOZ_TOKEN` on subsequent runs, avoiding the browser
    /// login each time.
    #[arg(long, global = true)]
    pub(crate) print_token: bool,
}

// ---------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------

/// The two top-level subcommands: `device` and `relay`.
#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Add, remove and list devices. To connect to MozillaVPN, a device needs to be on the list.
    Device {
        #[command(subcommand)]
        command: DeviceCommands,
    },
    /// List available relays (VPN servers) and save WireGuard configurations.
    Relay {
        #[command(subcommand)]
        command: RelayCommands,
    },
}

// ---------------------------------------------------------------------------
// Tunnel mode
// ---------------------------------------------------------------------------

/// Whether to route IPv4 traffic, IPv6 traffic, or both through the tunnel.
///
/// This controls two fields in the generated WireGuard config:
/// * `[Interface] Address =` — the tunnel interface address(es).
/// * `[Peer] AllowedIPs =` — the IP ranges routed through the tunnel.
///
/// | Variant | Address           | AllowedIPs          |
/// |---------|-------------------|---------------------|
/// | Both    | IPv4 CIDR, IPv6 CIDR | 0.0.0.0/0,::0/0 |
/// | Ipv4    | IPv4 CIDR only    | 0.0.0.0/0           |
/// | Ipv6    | IPv6 CIDR only    | ::0/0               |
#[derive(ValueEnum, Clone, Default)]
pub(crate) enum Tunnel {
    /// Tunnel both IPv4 and IPv6 (default). Full-stack VPN.
    #[default]
    Both,
    /// Tunnel only IPv4 traffic. IPv6 traffic bypasses the VPN.
    Ipv4,
    /// Tunnel only IPv6 traffic. IPv4 traffic bypasses the VPN.
    Ipv6,
}

// ---------------------------------------------------------------------------
// Port
// ---------------------------------------------------------------------------

/// WireGuard endpoint port selection: either a specific port number or a
/// randomly chosen port from the allowed [`PORT_RANGES`].
///
/// Choosing a non-standard port (e.g. 53 or 123) can help bypass firewalls
/// that block the default WireGuard port 51820, or disguise VPN traffic as
/// DNS/NTP to evade DPI.
#[derive(Clone)]
pub(crate) enum Port {
    /// Choose a random port from the union of all `PORT_RANGES` on each save.
    /// This is the behaviour of the official Windows Mozilla VPN client.
    Random,
    /// Use this specific port number. Must be within one of the `PORT_RANGES`
    /// or the tool exits with code 2.
    Port(u16),
}

impl FromStr for Port {
    type Err = ParseIntError;

    /// Parse `"random"` → `Port::Random`, any decimal integer → `Port::Port`.
    /// A non-numeric string other than `"random"` returns a `ParseIntError`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "random" => Ok(Self::Random),
            port => Ok(Self::Port(port.parse()?)),
        }
    }
}

// ---------------------------------------------------------------------------
// Shared --name argument
// ---------------------------------------------------------------------------

/// Shared `--name` argument used by `device add` and `relay save`.
///
/// The name is the human-readable label shown in the Mozilla VPN account
/// portal. It has no effect on routing or the VPN configuration itself.
/// Defaults to the system hostname so each machine gets a recognizable label
/// without any user input.
#[derive(Args)]
pub(crate) struct NameArgs {
    /// Name linked with a public key. Defaults to the hostname of the system.
    /// This value has no effect on the functioning of the VPN.
    #[arg(long, default_value_t = sys_info::hostname().unwrap())]
    pub(crate) name: String,
}

// ---------------------------------------------------------------------------
// relay subcommands
// ---------------------------------------------------------------------------

/// Subcommands for the `relay` group.
#[derive(Subcommand)]
pub(crate) enum RelayCommands {
    /// Print a list of all active Mullvad WireGuard relay servers, grouped by
    /// country and city.
    #[command(alias = "ls")]
    List,

    /// Generate a `wg-quick`-compatible WireGuard config file for one or more
    /// relay servers and write it to the output directory.
    ///
    /// If the WireGuard key used (`--privkey` or auto-generated) is not yet
    /// registered as a device, MozWire registers it first via the Mozilla VPN
    /// API (which allocates tunnel IP addresses for it).
    ///
    /// `--hop` and `--port` are mutually exclusive: multihop configurations
    /// use the exit node's `multihop_port`, not a user-specified port.
    #[command(group(ArgGroup::new("port-or-hop").args(&["hop", "port"])))]
    Save {
        /// Regex to filter relay servers by hostname.
        /// Only servers whose hostname matches this pattern are saved.
        /// Default `""` matches every server.
        #[clap(default_value = "")]
        regex: Regex,

        /// Directory in which to write the `.conf` files.
        /// One file is written per matching server (e.g. `se-got-wg-001.conf`).
        #[clap(default_value = ".", short)]
        output: PathBuf,

        /// Private key to use in the WireGuard config. Must be a base64-encoded
        /// 32-byte Curve25519 scalar. If omitted, a fresh key-pair is generated
        /// using the OS CSPRNG, registered with Mozilla VPN, and used.
        #[clap(long)]
        privkey: Option<String>,

        /// UDP port for the WireGuard `Endpoint`. Accepts a decimal number or
        /// `"random"`. Must be within the `PORT_RANGES` defined in `constants.rs`.
        /// Default 51820 is the standard WireGuard port.
        /// Mutually exclusive with `--hop`.
        #[arg(value_enum, default_value = "51820", short)]
        port: Port,

        /// Whether to route IPv4-only, IPv6-only, or both through the tunnel.
        #[clap(long, value_enum, default_value_t)]
        tunnel: Tunnel,

        /// Maximum number of server configs to save. `0` means no limit (save all
        /// matching servers). When a limit is set, servers are chosen at random
        /// using reservoir sampling for a uniform distribution.
        #[clap(short = 'n', default_value_t = 1)]
        limit: usize,

        /// Add iptables/ip6tables kill-switch rules to the config.
        ///
        /// When enabled, `PostUp` rules block all non-VPN traffic while the
        /// interface is up, and `PreDown` rules remove those blocks when the
        /// interface is taken down. This prevents traffic leaks if the VPN
        /// connection drops.
        #[clap(long)]
        killswitch: bool,

        /// Hostname of the entry node for a Mullvad multihop (double-VPN) setup.
        ///
        /// In multihop mode, you connect to the entry node (`--hop`), which
        /// forwards your traffic to the exit node (the server matched by the
        /// regex). The `Endpoint` in the config is the entry node's IPv4 address
        /// and the exit node's `multihop_port`. Mutually exclusive with `--port`.
        #[clap(long)]
        hop: Option<String>,

        /// Device name to use when registering a new key with Mozilla VPN.
        #[clap(flatten)]
        name: NameArgs,
    },
}

// ---------------------------------------------------------------------------
// device subcommands
// ---------------------------------------------------------------------------

/// Subcommands for the `device` group.
#[derive(Subcommand)]
pub(crate) enum DeviceCommands {
    /// Register a WireGuard public key with the Mozilla VPN account.
    ///
    /// On success, the API allocates a unique IPv4 and IPv6 tunnel address for
    /// this key and returns the full Device record (shown on stdout).
    ///
    /// Exactly one of `--pubkey` or `--privkey` must be provided.
    #[command(group(ArgGroup::new("key").required(true).args(&["pubkey", "privkey"])))]
    Add {
        /// Base64-encoded Curve25519 public key to register directly.
        #[arg(long)]
        pubkey: Option<String>,
        /// Base64-encoded Curve25519 private key; the public key is derived
        /// from it and registered. The private key itself is never sent to the API.
        #[arg(long)]
        privkey: Option<String>,
        #[command(flatten)]
        name: NameArgs,
    },

    /// Print all devices registered to this Mozilla VPN account.
    #[command(alias = "ls")]
    List,

    /// Remove one or more devices from the Mozilla VPN account.
    ///
    /// Each ID can be:
    /// * the device's name (as shown by `device list`)
    /// * a base64 public key
    /// * a base64 private key (the public key is derived and matched)
    #[command(alias = "rm")]
    Remove {
        /// Public key, private key, or device name of the device(s) to remove.
        #[arg(required = true)]
        ids: Vec<String>,
    },
}
