# desyncd

Adaptive DPI desynchronization tool. Automatically discovers and applies the best bypass strategies for your ISP and target domains.

Combines the power of [zapret](https://github.com/bol-van/zapret) with the simplicity of [byedpi](https://github.com/hufrea/byedpi), in a single Rust binary with auto-adaptation.

## Features

- **7 bypass techniques**: TCP split, TLS record fragmentation, fake packet injection, disorder, SNI manipulation, HTTP Host tricks, and technique chaining
- **Auto-adaptation**: automatically probes and discovers the best strategy per domain
- **Multi-mode**: SOCKS5 + HTTP CONNECT proxy (all platforms), transparent proxy (Linux), NFQ packet interception (Linux)
- **Stealth**: split jitter, timing jitter, randomized fake packets, TLS padding extension (anti-ML)
- **Per-domain rules**: different strategies for different sites, with wildcard support
- **QUIC awareness**: detects QUIC Initial packets for future UDP desync support

## Quick Start

```bash
# Build
cargo build --release

# Run with default config (SOCKS5 on 127.0.0.1:1080)
./target/release/desyncd run

# Test which techniques work for a domain
./target/release/desyncd test --domain youtube.com --all-techniques

# Auto-discover the best strategy and save to database
./target/release/desyncd adapt --domain youtube.com --save

# Show effective config
./target/release/desyncd show-config
```

Configure your browser or system to use SOCKS5 proxy at `127.0.0.1:1080`.

## Modes

| Mode | Platform | Privileges | Description |
|------|----------|------------|-------------|
| `socks` | All | None | SOCKS5 + HTTP CONNECT proxy (default) |
| `transparent` | Linux | root | Intercepts via `iptables REDIRECT` + `SO_ORIGINAL_DST` |
| `nfq` | Linux | root/CAP_NET_ADMIN | Kernel packet interception via NFQUEUE |

```bash
# SOCKS5 mode (default)
desyncd run --mode socks --listen 127.0.0.1:1080

# Transparent mode (Linux, requires iptables rules)
sudo desyncd run --mode transparent --listen 0.0.0.0:1080
# Then: sudo iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports 1080
```

## Configuration

Place your config at `~/.config/desyncd/config.toml` or pass `--config path/to/config.toml`.

```toml
[general]
mode = "socks"
log_level = "info"

[proxy]
listen = "127.0.0.1:1080"

# Auto-adaptation settings
[adaptation]
enabled = true
test_interval_secs = 21600  # 6 hours
test_domains = ["youtube.com", "rutracker.org"]

# Stealth settings (anti-DPI fingerprinting)
[stealth]
split_jitter = 4              # +/- N bytes randomization of split position
timing_jitter_us = 500        # random delay between segments (microseconds)
randomize_tls_padding = true  # add random TLS padding extension (anti-ML)
fake_size_range = [48, 200]   # randomize fake packet size

# --- Strategies ---
[strategies.default_tls]
techniques = [
    { name = "tcp_split", split_position = "Sni" },
]

[strategies.tls_frag]
techniques = [
    { name = "tls_record_frag", split_position = "Sni" },
]

[strategies.aggressive]
techniques = [
    { name = "tls_record_frag", split_position = "Sni" },
    { name = "tcp_split", split_position = { SniOffset = -2 } },
]

# --- Rules ---
[[rules]]
domains = ["*.youtube.com", "*.googlevideo.com"]
strategy = "aggressive"
priority = 10

[[rules]]
domains = ["*"]
strategy = "default_tls"
priority = 0
```

## Techniques

| Technique | Level | Description |
|-----------|-------|-------------|
| `tcp_split` | TCP | Splits TCP segment at SNI position into 2+ sends. Works against DPI that reassembles only the first segment. |
| `tls_record_frag` | TLS | Fragments ClientHello into multiple TLS records. More reliable than TCP split — works at application layer. |
| `fake_packet` | TCP | Injects a fake TLS record before the real ClientHello. Confuses DPI that processes only the first record. |
| `disorder` | TCP | Sends split segments in reverse order. Effective against DPI with limited reassembly buffers. |
| `sni_manip` | TLS | Modifies SNI field: mixed case, removal, or padding. Works against case-sensitive DPI. |
| `http_host` | HTTP | Modifies HTTP Host header: mixed case, extra spaces, tab separation, line wrapping, duplicate headers. |
| combo | Chain | Applies multiple techniques in sequence for maximum effectiveness. |

### Split positions

- `Sni` — split at the start of the SNI value
- `{ SniOffset = N }` — offset N bytes from SNI start (negative values shift left)
- `{ Absolute = N }` — split at byte position N
- `{ Random = [min, max] }` — random position in range

## Auto-Adaptation

desyncd can automatically find the best bypass strategy for your ISP:

```bash
# Test all techniques against a domain
desyncd test --domain youtube.com --all-techniques

# Find and save the best strategy
desyncd adapt --domain youtube.com --save
```

The adaptation engine:
1. Tests baseline connectivity (no desync)
2. Sweeps all single techniques with default parameters
3. Varies split position for winning techniques
4. Combines top techniques into chains
5. Scores by: `success_rate * 100 - latency * 0.01 - complexity * 2`

With `adaptation.enabled = true` in config, a background scheduler periodically re-tests and updates strategies.

## Stealth Features

| Parameter | Effect |
|-----------|--------|
| `split_jitter` | Randomizes split position by +/- N bytes per connection. Prevents fingerprinting by exact split offset. |
| `timing_jitter_us` | Adds random delay (0 to N microseconds) between segments. Breaks timing correlation. |
| `fake_size_range` | Randomizes fake TLS record size (default fixed at 64 bytes). Defeats size-based ML classifiers. |
| `randomize_tls_padding` | Adds random TLS padding extension (16-256 bytes) to ClientHello. Changes packet size per connection. |

## Building from Source

```bash
# Requirements: Rust 1.70+
cargo build --release

# Run tests
cargo test

# Cross-compile for Linux (from macOS)
cargo build --release --target x86_64-unknown-linux-gnu
```

## CLI Reference

```
desyncd [OPTIONS] <COMMAND>

Commands:
  run          Start the proxy/interceptor (default)
  test         Run block detection tests against domains
  adapt        Auto-discover best strategy for domains
  show-config  Print effective configuration

Options:
  -m, --mode <MODE>          Operating mode: socks, transparent, nfq
  -l, --listen <ADDR>        Listen address (e.g. 127.0.0.1:1080)
  -c, --config <PATH>        Path to configuration file
  -s, --strategy <NAME>      Override strategy for all connections
  -v, --verbose              Increase log verbosity (-v, -vv, -vvv)
```

## Architecture

```
desyncd-cli          Main binary, CLI interface
desyncd-config       TOML config + clap CLI parsing
desyncd-proxy        SOCKS5/HTTP CONNECT/transparent proxy
desyncd-desync       Bypass technique implementations
desyncd-packet       Protocol parsing (TLS/HTTP/QUIC)
desyncd-strategy     Strategy selection and domain matching
desyncd-adapt        Auto-adaptation engine
desyncd-store        SQLite persistence
desyncd-platform     Platform abstraction (firewall, NFQ)
desyncd-nfq          Linux NFQUEUE packet handler
desyncd-types        Shared types and enums
```

## License

MIT OR Apache-2.0
