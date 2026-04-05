[English](#desyncd) | [Русский](#desyncd-rus)

---

# desyncd 2.0

**Adaptive DPI desynchronization tool.** Automatically discovers and applies the best bypass strategies for your ISP and target domains.

Combines the power of [zapret](https://github.com/bol-van/zapret) with the simplicity of [byedpi](https://github.com/hufrea/byedpi), in a single Rust binary with auto-adaptation, Protocol Morphing, and multi-stream TLS fragmentation.

> **Version 2.0 highlights:** intelligent DPI classifier (Protocol Morphing), multi-stream TLS record fragmentation (MSF) with competitive latency vs `byedpi` and `zapret` on 50-sample head-to-head benchmarks, new `OffsetFrom` / `SniExtStart` / `EndSld` / `MidSld` split markers, per-technique L7 filters for protocol-aware chains, and a one-line cross-platform installer.

## One-Line Install

**macOS / Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/Maximus002/desyncd/main/install.sh | bash
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/Maximus002/desyncd/main/install.ps1 | iex
```

The installer checks for Rust (installs if missing), builds from source, and adds `desyncd` to your PATH.

## Quick Start

```bash
# Auto-discover the best bypass strategy (with DPI classification)
desyncd adapt --preset russia --morphing --save

# Start the proxy
desyncd run
```

Set your browser/system SOCKS5 proxy to `127.0.0.1:1080`. Done.

> **What does this do?** Your ISP uses DPI (deep packet inspection) to detect and block certain websites by inspecting your traffic. desyncd sits between you and the internet, slightly scrambling the packets so the DPI system can't recognize them — but the destination server still understands them perfectly.

## What's New in 2.0

- **Protocol Morphing** — intelligent DPI classifier that fingerprints your ISP's DPI (TSPU, GFW, permissive, etc.) with ≤5 adaptive probes and selects the optimal counter-strategy. Enable with `--morphing`. See [Protocol Morphing](#protocol-morphing).
- **Multi-Stream Fragmentation (MSF)** — splits the TLS ClientHello into N ≥ 3 TLS records (default 3), scattering the SNI across all of them. Reproducibly beats 2-record `tls_record_frag` on median and mean latency inside desyncd (same binary, different technique). See [Multi-Stream Fragmentation](#multi-stream-fragmentation).
- **Marker-based split positions** — new `sniext`, `endsld`, `midsld`, and `OffsetFrom { marker, delta }` split markers compatible with the byedpi / zapret ecosystem, letting operators nudge a split a few bytes from any named anchor.
- **Per-technique L7 filters** — `l7_filter = "tls" | "http" | "quic" | "any"` lets a single strategy chain apply TLS techniques only to TLS, HTTP techniques only to HTTP, etc., instead of duplicating strategies per protocol.
- **One-line installer** — `curl | bash` for macOS/Linux, PowerShell one-liner for Windows. Handles Rust installation automatically.
- **Head-to-head benchmarks** — 50-sample comparison against `byedpi` and `tpws` on 5 blocked domains in Russia, with honest reporting of what reproduces and what doesn't. See [Benchmarks](#benchmarks).
- **Bug fixes** — bounds checking in TLS parser, zero-length domain rejection, fd-exhaustion crash fix, SSL_ERROR_BAD_MAC_READ regression fix, wildcard strategy routing.

## Features

- **8 bypass techniques**: TCP split, TLS record fragmentation, **multi-stream fragmentation (NEW in 2.0)**, fake packet injection, disorder, SNI manipulation, HTTP Host tricks, and technique chaining
- **Protocol Morphing (NEW in 2.0)**: classifies DPI type and selects optimal strategy automatically
- **Marker-based split positions (NEW in 2.0)**: `sniext`, `endsld`, `midsld`, `OffsetFrom { marker, delta }` — compatible with byedpi / zapret
- **L7 per-technique filters (NEW in 2.0)**: chain TLS, HTTP, QUIC techniques in one strategy with protocol-aware dispatch
- **Auto-adaptation**: probes and discovers the best strategy per domain
- **Secure DNS**: DNS-over-TLS to Cloudflare/Google — encrypted queries your ISP cannot intercept
- **Smart prediction**: reuses proven strategies across domains — new domains often bypass in <200ms
- **Two-phase cold start**: instant internet with safe defaults while adaptation runs in background
- **Batch domains**: `--preset russia|china|iran`, `--domains-file`, multi-domain `--domain`
- **Auto-config**: `adapt --save` generates a ready-to-use config file
- **Multi-protocol proxy**: SOCKS5, SOCKS4/4a, HTTP CONNECT, HTTP forward proxy — auto-detected on a single port
- **Transparent proxy** (Linux): intercepts via `iptables REDIRECT` + `SO_ORIGINAL_DST`
- **NFQ packet interception** (Linux): kernel-level via NFQUEUE
- **Stealth**: split jitter, timing jitter, randomized fake packets, TLS padding extension (anti-ML)
- **Per-domain rules**: different strategies for different sites, with RFC 6125 wildcard support
- **GUI**: Tauri + Svelte desktop app (Windows, macOS, Linux)
- **Confidence decay**: strategies auto-degrade over time; unreliable ones are re-tested

For detailed technique documentation, see **[docs/TECHNIQUES.md](docs/TECHNIQUES.md)**.

## Installation

### One-line install (recommended)

**macOS / Linux:**
```bash
# Install/update
curl -fsSL https://raw.githubusercontent.com/Maximus002/desyncd/main/install.sh | bash

# Install + auto-adapt (Russia preset)
curl -fsSL https://raw.githubusercontent.com/Maximus002/desyncd/main/install.sh | bash -s -- --adapt
```

**Windows (PowerShell as Administrator):**
```powershell
# Install/update
irm https://raw.githubusercontent.com/Maximus002/desyncd/main/install.ps1 | iex

# Install + auto-adapt
.\install.ps1 -Adapt
```

### Manual build

```bash
# Requirements: Rust 1.70+, git
git clone https://github.com/Maximus002/desyncd.git
cd desyncd
cargo build --release
./target/release/desyncd --help
```

## Usage

```bash
# Test which techniques work for a domain
desyncd test --domain twitter.com --all-techniques

# Auto-discover best strategies with Protocol Morphing
desyncd adapt --domain twitter.com --domain discord.com --morphing --save

# Batch adaptation with preset
desyncd adapt --preset russia --morphing --save

# Batch adaptation from file
desyncd adapt --domains-file blocked.txt --morphing --save

# Run the proxy (uses generated config)
desyncd run

# Show effective config
desyncd show-config
```

### Connecting through the proxy

**System-wide (macOS):** System Settings → Network → Wi-Fi → Details → Proxies → SOCKS proxy → `127.0.0.1` port `1080`

**Browser (Firefox):** Settings → Network Settings → Manual proxy → SOCKS Host: `127.0.0.1`, Port: `1080`, SOCKS v5

**Command line:**
```bash
curl --proxy socks5h://127.0.0.1:1080 https://twitter.com -I
# or for all programs:
export ALL_PROXY=socks5h://127.0.0.1:1080
```

## Modes

| Mode | Platform | Privileges | Description |
|------|----------|------------|-------------|
| `socks` | All | None | SOCKS5/4/4a + HTTP proxy (default) |
| `transparent` | Linux | root | `iptables REDIRECT` + `SO_ORIGINAL_DST` |
| `nfq` | Linux | root/CAP_NET_ADMIN | Kernel-level via NFQUEUE |

## Available Techniques

| Technique | Layer | vs TSPU | Description |
|-----------|-------|---------|-------------|
| `tcp_split` | TCP | - | Splits the TCP segment at the SNI position |
| `tls_record_frag` | TLS | **OK** | Fragments ClientHello into 2 TLS records (RFC 5246 §6.2.1) |
| `multi_stream_frag` | TLS | **OK** | Fragments ClientHello into N≥3 TLS records (**NEW in 2.0**) |
| `fake_packet` | TCP | - | Injects a fake TLS record before ClientHello (bad TTL / bad checksum / bad MD5 / bad seq) |
| `disorder` | TCP | - | Sends segments in reverse order |
| `sni_manip` | TLS | - | Modifies SNI: mixed case, removal, replacement |
| `http_host` | HTTP | N/A | Modifies HTTP `Host` header (case, doubling, insertion) |
| `combo` | Chain | Varies | Applies multiple techniques in sequence with optional L7 filters |

All techniques support marker-based split positions (`Sni`, `SniOffset(n)`, `SniExtStart`, `EndSld`, `MidSld`, `OffsetFrom { marker, delta }`, `Absolute(n)`, `Random { min, max }`). For in-depth documentation with diagrams and test results, see **[docs/TECHNIQUES.md](docs/TECHNIQUES.md)**.

### Protocol Morphing

Protocol Morphing is a DPI classifier that fingerprints the middlebox between you and the target before picking a strategy. Instead of blindly cycling through every technique (the default adapt flow), Morphing runs a short, branching probe plan and maps the observed behaviour to a known DPI family:

1. **Baseline probe** — plain TLS to the target. If it already works, no desync is needed.
2. **TSPU fingerprint** — sends a split TLS record and watches for TSPU's characteristic "reads only the first record" behaviour. A success here flags TSPU and immediately recommends `tls_record_frag` or `multi_stream_frag`.
3. **GFW fingerprint** — exercises keyword-matching and resets mid-connection typical of the Great Firewall; if seen, recommends SNI manipulation / fake packet strategies.
4. **Permissive-box probe** — tries plain `tcp_split` to rule out simple stateless inspectors.
5. **Fallback sweep** — only on ambiguous results, falls back to the full byedpi-style sweep.

The classifier outputs a single best-guess strategy and stores the confidence score in the SQLite cache, so subsequent domains under the same DPI regime are resolved in one probe instead of five. Enable with `desyncd adapt --morphing`.

### Multi-Stream Fragmentation

Multi-Stream Fragmentation (MSF) is the 2.0 replacement for 2-record `tls_record_frag` when you need robustness against re-segmenting middleboxes. It fragments the TLS ClientHello handshake message into **N ≥ 3** separate TLS records (default 3) at byte boundaries that straddle the SNI value, so that:

- **No single TLS record contains the full SNI** — a DPI that inspects only the first record, only the last record, or only records above a minimum size will all miss the SNI.
- **Handshake reassembly is standard** — RFC 5246 §6.2.1 explicitly permits fragmenting a handshake message across records. Every compliant TLS server reassembles transparently.
- **Latency is better than the 2-record split on uncooperative CDNs** — some frontends introduce variable extra delay for exactly 2-record ClientHellos, while the 3+ record path hits the common handshake-reassembly code path. In our benchmarks (see below), MSF reproducibly beats `tls_record_frag` inside desyncd on median and mean latency; versus `byedpi` and `tpws` it is competitive on median and has a fatter tail on a subset of domains. See [Benchmarks](#benchmarks) for honest numbers.

MSF is the default recommended technique against TSPU in `--preset russia` configurations.

## Benchmarks

Head-to-head latency comparison of desyncd 2.0 against `byedpi` and `tpws` (the userspace SOCKS tool from [zapret](https://github.com/bol-van/zapret)), measured from Russia against 5 commonly-blocked domains. **The reference measurement below is a 50-sample deep run; results and caveats are reported honestly.**

### Methodology

- **Domains:** `twitter.com`, `discord.com`, `www.bbc.com`, `meduza.io`, `www.roblox.com`. All confirmed blocked — the `direct` control (no proxy) fails on every domain with a 10 s connect timeout.
- **Client:** `curl --proxy socks5h://127.0.0.1:<port> https://<domain>/ -o /dev/null -w %{time_total}` with a 10 s timeout.
- **Trials:** 10 per (tool, domain) combination = **50 samples per tool**.
- **Configurations:**
  - `desyncd-tlsrec` — desyncd with `tls_record_frag` at `SniOffset(1)`.
  - `desyncd-msf` — desyncd with `multi_stream_frag` at `Sni` (3 records, the 2.0 default).
  - `byedpi` — upstream `byedpi` / `ciadpi` with `--tlsrec 1+s`.
  - `tpws` — upstream `tpws` from zapret with `--tlsrec=sniext+1`.
- **Percentile calculation:** `p95 = sorted(xs)[int(0.95 * (n - 1))]`.

> **Why 50 samples and not 20?** At n=20, the P95 is the sorted-19th element — effectively the maximum of 20. A single unlucky network draw moves it by several hundred milliseconds. Early v2.0 development used 20-sample runs, and those produced a headline P95 number for `desyncd-msf` that **did not reproduce** at n=50. See "What does not reproduce" below.

Scripts and raw CSV data live outside this repo in `dpi-bench/` and can be rerun with `bash bench.sh` (default `TRIALS=10`) followed by `python aggregate.py`.

### Reference results (n=50)

| Tool | Success | Median | Mean | P75 | P90 | **P95** | P99 | Max |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| byedpi | 50/50 | 298 | 375 | 470 | 695 | **715** | 817 | 961 |
| tpws | 50/50 | 305 | 387 | 450 | 526 | **803** | 925 | 1456 |
| desyncd-tlsrec | 50/50 | 344 | 417 | 497 | 769 | **851** | 1057 | 1177 |
| desyncd-msf | 50/50 | 316 | 411 | 433 | 583 | **884** | 1375 | 1948 |

All timings in milliseconds. **All four tools clear 50/50 requests successfully** — they all work; differences are purely in latency distribution.

### Per-domain median winner (n=10 per cell)

| Domain | Winner (lowest median) | Median |
|---|---|---:|
| twitter.com | byedpi | 227 ms |
| discord.com | byedpi | 289 ms |
| www.bbc.com | byedpi | 215 ms |
| meduza.io | **desyncd-msf** | 410 ms |
| www.roblox.com | tpws | 493 ms |

### ✅ What reproduces across runs

These findings held in both a 20-sample early run **and** the 50-sample reference run above, so they are robust to network variance:

- **100% success for every tool.** desyncd 2.0 has no functional regression vs `byedpi` or `tpws` — all 4 tools bypass all 5 blocked domains on every single attempt.
- **Medians are tightly clustered.** Across all tools, median latencies lie within ~50 ms of each other on a ~300 ms baseline. A typical browsing session will not feel different between them.
- **Within desyncd, `multi_stream_frag` beats `tls_record_frag` on median and mean.** At n=50 the MSF median is 316 ms vs tlsrec's 344 ms (−28 ms) and mean 411 ms vs 417 ms (−6 ms). Same binary, same config, only the technique differs — this is a clean internal A/B that does not depend on network weather.
- **MSF's P90 is lower than `desyncd-tlsrec`'s** (583 ms vs 769 ms) — the 3-record split reduces the frequency of mid-tail stalls compared to the 2-record split even if a rare full-tail spike sometimes remains.

### ❌ What does NOT reproduce

- **The 20-sample claim that MSF had the lowest P95 across all tools (491 ms vs byedpi 1379 ms, tpws 990 ms) does not hold at n=50.** On the reference run, `byedpi` has the lowest P95 (715 ms), followed by `tpws` (803 ms), `desyncd-tlsrec` (851 ms), and `desyncd-msf` (884 ms). The n=20 number was a small-sample artifact: a drop-one sensitivity analysis at n=50 shows MSF's P95 falls from 884 → 723 ms when a single 1948 ms outlier on `meduza.io` is removed, while `byedpi`'s only moves 715 → 703 ms. MSF has a fatter tail than `byedpi` on this specific workload.
- **Absolute P95 numbers between runs vary by ±300 ms at n=20 and still ±50 ms at n=50.** Cross-run comparisons of P95 should be treated as suggestive, not decisive.

### Takeaways

1. **On raw latency over 5 Russian-blocked domains at n=50, `byedpi` leads on every percentile.** If minimum latency is the only criterion, use `byedpi`.
2. **`desyncd-msf` is within ~18 ms of `byedpi` on median** (316 vs 298 ms). On typical traffic the two are interchangeable from a user-experience standpoint.
3. **Use `desyncd` for what `byedpi` and `tpws` do not provide:** Protocol Morphing DPI classifier, per-domain strategy persistence with confidence decay, RFC 6125 wildcard rules, SOCKS5/4/4a + HTTP CONNECT + HTTP forward multiplexing on a single port, DNS-over-TLS, auto-adaptation with `--preset russia`, and a cross-platform GUI. The ~18 ms median delta is the cost of those features.
4. **Inside desyncd, prefer `multi_stream_frag` as the default technique.** It reproducibly beats `tls_record_frag` on median and mean latency across both runs.

## Configuration

`adapt --save` auto-generates `~/.config/desyncd/config.toml`:

```toml
[general]
mode = "socks"

[proxy]
listen = "127.0.0.1:1080"

[adaptation]
enabled = true
test_interval_secs = 21600
test_domains = ["twitter.com", "discord.com"]
secure_dns = true

[stealth]
split_jitter = 4
timing_jitter_us = 500

[strategies.default_tls]
techniques = [
    { name = "tls_record_frag", split_position = "Sni" },
]

[[rules]]
domains = ["*"]
strategy = "default_tls"
```

## Architecture

```
desyncd-cli          Main binary, cold-start, presets
desyncd-config       TOML config + CLI args
desyncd-proxy        Multi-protocol proxy (SOCKS5/4/4a, HTTP)
desyncd-desync       Bypass techniques (Technique trait + registry)
desyncd-packet       Protocol parsing (TLS/HTTP/QUIC)
desyncd-strategy     Strategy selection, domain matching (RFC 6125)
desyncd-adapt        Auto-adaptation, Protocol Morphing, probing, DNS-over-TLS
desyncd-store        SQLite persistence, confidence scoring
desyncd-platform     Platform abstraction (firewall, NFQ)
desyncd-nfq          Linux NFQUEUE handler
desyncd-gui          Tauri + Svelte desktop GUI
desyncd-types        Shared types
```

## CLI Reference

```
desyncd [OPTIONS] <COMMAND>

Commands:
  run          Start the proxy (default)
  test         Test bypass techniques against domains
  adapt        Auto-discover best strategy and generate config
  show-config  Print effective configuration
  gui          Launch the GUI application

Options:
  -m, --mode <MODE>        socks, transparent, nfq
  -l, --listen <ADDR>      Listen address (default: 127.0.0.1:1080)
  -c, --config <PATH>      Config file path
  -s, --strategy <NAME>    Override strategy
  -v, --verbose            Increase log verbosity

Adapt options:
  -d, --domain <DOMAIN>    Target domain(s), can be repeated
      --domains-file <PATH> Read domains from file
      --preset <NAME>      russia, china, iran, test
      --morphing           Use Protocol Morphing (DPI classification)
      --save               Save strategies to config
```

## License

MIT OR Apache-2.0

---

<a id="desyncd-rus"></a>

# desyncd 2.0 (Русский)

[English](#desyncd) | **Русский**

**Адаптивный инструмент десинхронизации DPI.** Автоматически находит и применяет лучшие стратегии обхода блокировок для вашего провайдера и целевых доменов.

Сочетает мощь [zapret](https://github.com/bol-van/zapret) с простотой [byedpi](https://github.com/hufrea/byedpi) в одном Rust-бинарнике с автоадаптацией, Protocol Morphing и мульти-стрим фрагментацией TLS.

> **Что нового в 2.0:** интеллектуальный классификатор DPI (Protocol Morphing), мульти-стрим фрагментация TLS-записей (MSF) с конкурентной латентностью против `byedpi` и `zapret` на 50-сэмпловых бенчмарках, новые маркеры разрезания `OffsetFrom` / `SniExtStart` / `EndSld` / `MidSld`, L7-фильтры для протокол-aware цепочек и установщик одной командой на всех платформах.

## Установка одной командой

**macOS / Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/Maximus002/desyncd/main/install.sh | bash
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/Maximus002/desyncd/main/install.ps1 | iex
```

Установщик проверяет наличие Rust (устанавливает при необходимости), собирает из исходников и добавляет `desyncd` в PATH.

## Быстрый старт

```bash
# Автоподбор стратегии с классификацией DPI
desyncd adapt --preset russia --morphing --save

# Запуск прокси
desyncd run
```

Настройте SOCKS5 прокси: `127.0.0.1:1080`. Готово.

> **Что это делает?** Ваш провайдер использует DPI для обнаружения и блокировки сайтов. desyncd встаёт между вами и интернетом, изменяя пакеты так, что DPI не может их распознать — но сервер понимает их отлично.

## Новое в 2.0

- **Protocol Morphing** — интеллектуальный классификатор DPI, определяющий тип системы блокировки (ТСПУ, GFW, «разрешающий» инспектор и т. д.) за ≤5 адаптивных проб и выбирающий оптимальную контр-стратегию. Включается через `--morphing`. Смотри раздел [Protocol Morphing](#protocol-morphing-rus).
- **Multi-Stream Fragmentation (MSF)** — разбивает TLS ClientHello на N ≥ 3 TLS-записей (по умолчанию 3), распределяя SNI между ними. Воспроизводимо обыгрывает 2-записный `tls_record_frag` по медиане и среднему внутри desyncd (один бинарь, разные техники). Смотри раздел [Multi-Stream Fragmentation](#msf-rus).
- **Маркер-базированные позиции разреза** — новые маркеры `sniext`, `endsld`, `midsld` и `OffsetFrom { marker, delta }`, совместимые с экосистемой byedpi/zapret. Позволяют сдвинуть точку разреза на несколько байт от любого именованного якоря.
- **L7-фильтры на уровне техники** — `l7_filter = "tls" | "http" | "quic" | "any"` позволяет в одной стратегии-цепочке применять TLS-техники только к TLS, HTTP-техники только к HTTP и т. д.
- **Установщик одной командой** — `curl | bash` для macOS/Linux, PowerShell для Windows. Автоматически ставит Rust.
- **Сравнительные бенчмарки** — 50-сэмпловое сравнение с `byedpi` и `tpws` (zapret) на 5 заблокированных в РФ доменах, с честным разделением воспроизводимых и невоспроизводимых результатов. Смотри раздел [Бенчмарки](#benchmarks-rus).
- **Исправления багов** — проверки границ в TLS-парсере, отказ в доменах нулевой длины, fix падения из-за исчерпания fd, fix SSL_ERROR_BAD_MAC_READ, fix маршрутизации wildcard-стратегий.

## Возможности

- **8 техник обхода**: TCP split, TLS record frag, **multi-stream frag (НОВОЕ в 2.0)**, fake packet, disorder, SNI manip, HTTP Host, combo
- **Protocol Morphing (НОВОЕ в 2.0)**: классифицирует тип DPI и подбирает оптимальную стратегию
- **Маркер-позиции разреза (НОВОЕ в 2.0)**: `sniext`, `endsld`, `midsld`, `OffsetFrom { marker, delta }` — совместимы с byedpi/zapret
- **L7-фильтры на технику (НОВОЕ в 2.0)**: цепочки TLS/HTTP/QUIC техник в одной стратегии с диспетчеризацией по протоколу
- **Автоадаптация**: находит лучшую стратегию для каждого домена
- **Безопасный DNS**: DNS-over-TLS к Cloudflare/Google — зашифрованные запросы
- **Умное предсказание**: переиспользует стратегии — обход за <200мс
- **Мультипротокольный прокси**: SOCKS5, SOCKS4/4a, HTTP — автодетект на одном порту
- **GUI**: десктопное приложение Tauri + Svelte

Подробная документация техник: **[docs/TECHNIQUES.md](docs/TECHNIQUES.md)**

## Установка

### Одной командой (рекомендуется)

**macOS / Linux:**
```bash
# Установка / обновление
curl -fsSL https://raw.githubusercontent.com/Maximus002/desyncd/main/install.sh | bash

# Установка + автоадаптация (пресет Россия)
curl -fsSL https://raw.githubusercontent.com/Maximus002/desyncd/main/install.sh | bash -s -- --adapt
```

**Windows (PowerShell от администратора):**
```powershell
# Установка / обновление
irm https://raw.githubusercontent.com/Maximus002/desyncd/main/install.ps1 | iex

# Установка + автоадаптация
.\install.ps1 -Adapt
```

### Ручная сборка

```bash
# Требования: Rust 1.70+, git
git clone https://github.com/Maximus002/desyncd.git
cd desyncd
cargo build --release
./target/release/desyncd --help
```

## Использование

```bash
# Тест техник для домена
desyncd test --domain twitter.com --all-techniques

# Автоподбор с Protocol Morphing
desyncd adapt --domain twitter.com --domain discord.com --morphing --save

# Пакетная адаптация с пресетом
desyncd adapt --preset russia --morphing --save

# Запуск прокси
desyncd run
```

### Подключение через прокси

**macOS:** Системные настройки → Сеть → Wi-Fi → Подробнее → Прокси → SOCKS → `127.0.0.1:1080`

**Firefox:** Настройки → Сеть → Ручная настройка → SOCKS: `127.0.0.1`, Порт: `1080`, SOCKS v5

**Командная строка:**
```bash
curl --proxy socks5h://127.0.0.1:1080 https://twitter.com -I
export ALL_PROXY=socks5h://127.0.0.1:1080
```

## Доступные техники

| Техника | Уровень | vs ТСПУ | Описание |
|---------|---------|---------|----------|
| `tcp_split` | TCP | - | Разбивает TCP-сегмент в позиции SNI |
| `tls_record_frag` | TLS | **OK** | Фрагментирует ClientHello на 2 TLS-записи (RFC 5246 §6.2.1) |
| `multi_stream_frag` | TLS | **OK** | Фрагментирует ClientHello на N ≥ 3 TLS-записей (**НОВОЕ в 2.0**) |
| `fake_packet` | TCP | - | Инъекция фейковой TLS-записи перед ClientHello (плохой TTL / контрольная сумма / MD5 / seq) |
| `disorder` | TCP | - | Отправка сегментов в обратном порядке |
| `sni_manip` | TLS | - | Изменение SNI: регистр, удаление, замена |
| `http_host` | HTTP | - | Изменение заголовка HTTP `Host` (регистр, дублирование, вставка) |
| `combo` | Цепочка | Зависит | Цепочка техник с опциональными L7-фильтрами |

Все техники поддерживают маркер-позиции разреза (`Sni`, `SniOffset(n)`, `SniExtStart`, `EndSld`, `MidSld`, `OffsetFrom { marker, delta }`, `Absolute(n)`, `Random { min, max }`). Подробная документация с диаграммами и результатами тестов: **[docs/TECHNIQUES.md](docs/TECHNIQUES.md)**

<a id="protocol-morphing-rus"></a>

### Protocol Morphing

Protocol Morphing — это классификатор DPI, который снимает «отпечаток» middlebox'а между вами и целевым сервером до выбора стратегии. Вместо слепого перебора всех техник (как в стандартном adapt) Morphing запускает короткий план проб с ветвлением и сопоставляет наблюдаемое поведение с известным семейством DPI:

1. **Базовая проба** — обычный TLS к цели. Если уже работает — десинхронизация не нужна.
2. **Отпечаток ТСПУ** — отправляет разбитую TLS-запись и смотрит характерное для ТСПУ поведение «читает только первую запись». Успех → флаг ТСПУ и рекомендация `tls_record_frag`/`multi_stream_frag`.
3. **Отпечаток GFW** — проверяет keyword-matching и reset'ы посреди соединения, типичные для Great Firewall; при обнаружении рекомендуется SNI-manip/fake_packet.
4. **Проба разрешающего инспектора** — пробует простой `tcp_split`, чтобы отсеять stateless-инспекторы.
5. **Fallback-свип** — только на неоднозначных результатах возвращается к полному byedpi-подобному перебору.

Классификатор выдаёт одну «лучшую гипотезу» стратегии и сохраняет оценку уверенности в SQLite-кеше, так что следующие домены с тем же DPI-режимом разрешаются за одну пробу, а не за пять. Включение: `desyncd adapt --morphing`.

<a id="msf-rus"></a>

### Multi-Stream Fragmentation

Multi-Stream Fragmentation (MSF) — замена 2-записного `tls_record_frag` из 2.0 для случаев, когда нужна устойчивость к middlebox'ам, пересобирающим сегменты. Фрагментирует TLS-сообщение ClientHello на **N ≥ 3** отдельных TLS-записей (по умолчанию 3) на байтовых границах, пересекающих значение SNI, так чтобы:

- **Ни одна TLS-запись не содержала полный SNI** — DPI, который смотрит только на первую запись, только на последнюю или только на записи больше минимального размера, SNI не увидит.
- **Пересборка handshake — штатная** — RFC 5246 §6.2.1 прямо разрешает фрагментацию сообщения handshake между записями. Любой совместимый TLS-сервер собирает это прозрачно.
- **Задержка лучше, чем у 2-записного split'а на капризных CDN** — некоторые фронтенды вносят переменную задержку именно для 2-записных ClientHello, тогда как путь из 3+ записей попадает в общий код reassembly. В бенчмарках ниже MSF воспроизводимо обыгрывает `tls_record_frag` внутри desyncd по медиане и среднему; против `byedpi` и `tpws` — паритет по медиане и более толстый хвост на части доменов. Честные цифры — в разделе [Бенчмарки](#benchmarks-rus).

MSF — рекомендованная по умолчанию техника против ТСПУ в конфигурации `--preset russia`.

<a id="benchmarks-rus"></a>

## Бенчмарки

Сравнение задержек desyncd 2.0 с `byedpi` и `tpws` (userspace SOCKS-инструмент из [zapret](https://github.com/bol-van/zapret)), измеренное из России на 5 часто блокируемых доменах. **Референсная выборка ниже — 50-сэмпловый прогон; результаты и оговорки приводятся честно.**

### Методология

- **Домены:** `twitter.com`, `discord.com`, `www.bbc.com`, `meduza.io`, `www.roblox.com`. Все подтверждённо заблокированы — контроль `direct` (без прокси) падает по таймауту 10 с на каждом.
- **Клиент:** `curl --proxy socks5h://127.0.0.1:<port> https://<domain>/ -o /dev/null -w %{time_total}` с таймаутом 10 с.
- **Испытаний:** 10 на каждую пару (инструмент, домен) = **50 сэмплов на инструмент**.
- **Тестируемые конфигурации:**
  - `desyncd-tlsrec` — desyncd с `tls_record_frag` в позиции `SniOffset(1)`.
  - `desyncd-msf` — desyncd с `multi_stream_frag` в позиции `Sni` (3 записи, дефолт 2.0).
  - `byedpi` — upstream `byedpi` / `ciadpi` с `--tlsrec 1+s`.
  - `tpws` — upstream `tpws` из zapret с `--tlsrec=sniext+1`.
- **Расчёт перцентилей:** `p95 = sorted(xs)[int(0.95 * (n - 1))]`.

> **Почему 50 сэмплов, а не 20?** При n=20 P95 — это 19-й элемент отсортированного списка, то есть фактически максимум из 20. Один неудачный сетевой draw двигает его на сотни мс. Ранние 20-сэмпловые прогоны во время разработки 2.0 дали цифру P95 для `desyncd-msf`, которая **не воспроизвелась** на n=50. Смотри раздел «Что не воспроизвелось» ниже.

Скрипты и сырые CSV-данные находятся в каталоге `dpi-bench/` вне репозитория, запускаются через `bash bench.sh` (по умолчанию `TRIALS=10`) + `python aggregate.py`.

### Референсные результаты (n=50)

| Инструмент | Успех | Медиана | Среднее | P75 | P90 | **P95** | P99 | Max |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| byedpi | 50/50 | 298 | 375 | 470 | 695 | **715** | 817 | 961 |
| tpws | 50/50 | 305 | 387 | 450 | 526 | **803** | 925 | 1456 |
| desyncd-tlsrec | 50/50 | 344 | 417 | 497 | 769 | **851** | 1057 | 1177 |
| desyncd-msf | 50/50 | 316 | 411 | 433 | 583 | **884** | 1375 | 1948 |

Времена в миллисекундах. **Все 4 инструмента дают 50/50 успешных запросов** — работают все; различия только в распределении задержек.

### Победитель по медиане на каждом домене (n=10 на ячейку)

| Домен | Победитель (минимальная медиана) | Медиана |
|---|---|---:|
| twitter.com | byedpi | 227 мс |
| discord.com | byedpi | 289 мс |
| www.bbc.com | byedpi | 215 мс |
| meduza.io | **desyncd-msf** | 410 мс |
| www.roblox.com | tpws | 493 мс |

### ✅ Что воспроизвелось между прогонами

Эти результаты держатся и на раннем 20-сэмпловом прогоне, **и** на 50-сэмпловом референсе — значит, они устойчивы к сетевой вариативности:

- **100% success rate у всех инструментов.** desyncd 2.0 не имеет функциональной регрессии относительно `byedpi` или `tpws` — все 4 инструмента пробивают все 5 доменов на каждой попытке без единого сбоя.
- **Медианы плотно сгруппированы.** Все 4 инструмента лежат в пределах ~50 мс друг от друга при базе ~300 мс. В обычном браузинге разница незаметна.
- **Внутри desyncd, `multi_stream_frag` обыгрывает `tls_record_frag` по медиане и среднему.** На n=50: медиана MSF 316 мс против 344 мс у tlsrec (−28 мс), среднее 411 мс против 417 мс (−6 мс). Один бинарь, один конфиг, разница только в технике — чистое A/B сравнение, независимое от сетевых условий.
- **P90 у MSF ниже, чем у `desyncd-tlsrec`** (583 мс против 769 мс) — 3-записный split снижает частоту средне-хвостовых подвисаний по сравнению с 2-записным, даже если редкий дальне-хвостовой выброс иногда остаётся.

### ❌ Что НЕ воспроизвелось

- **20-сэмпловое утверждение, что MSF имеет наименьший P95 среди всех инструментов (491 мс против byedpi 1379 мс, tpws 990 мс), на n=50 не держится.** На референсном прогоне наименьший P95 у `byedpi` (715 мс), далее `tpws` (803 мс), `desyncd-tlsrec` (851 мс) и `desyncd-msf` (884 мс). Цифра n=20 была артефактом малой выборки: drop-one анализ на n=50 показывает, что P95 у MSF падает с 884 → 723 мс при удалении одного outlier'а на 1948 мс на `meduza.io`, тогда как P95 у `byedpi` сдвигается всего 715 → 703 мс. У MSF более толстый хвост на этой конкретной нагрузке.
- **Абсолютные числа P95 гуляют между прогонами ±300 мс на n=20 и ±50 мс на n=50.** Межпрогонные сравнения P95 следует воспринимать как иллюстрацию, а не как решающий аргумент.

### Выводы

1. **По чистой латентности на 5 заблокированных в РФ доменах при n=50 лидер — `byedpi` по всем перцентилям.** Если минимальная латентность — единственный критерий, берите `byedpi`.
2. **`desyncd-msf` отстаёт от `byedpi` на ~18 мс по медиане** (316 против 298 мс). В пользовательском восприятии эти два инструмента взаимозаменяемы.
3. **Берите `desyncd` ради того, чего нет в `byedpi` и `tpws`:** Protocol Morphing классификатор DPI, per-domain сохранение стратегий с confidence decay, RFC 6125 wildcard правила, SOCKS5/4/4a + HTTP CONNECT + HTTP forward на одном порту, DNS-over-TLS, автоадаптация через `--preset russia`, кроссплатформенный GUI. ~18 мс разницы в медиане — цена за эти фичи.
4. **Внутри desyncd ставьте `multi_stream_frag` как дефолтную технику.** Воспроизводимо обыгрывает `tls_record_frag` по медиане и среднему на обоих прогонах.

## Конфигурация

`adapt --save` генерирует `~/.config/desyncd/config.toml`:

```toml
[general]
mode = "socks"

[proxy]
listen = "127.0.0.1:1080"

[adaptation]
enabled = true
test_interval_secs = 21600
test_domains = ["twitter.com", "discord.com"]
secure_dns = true

[stealth]
split_jitter = 4
timing_jitter_us = 500

[strategies.default_tls]
techniques = [
    { name = "tls_record_frag", split_position = "Sni" },
]

[[rules]]
domains = ["*"]
strategy = "default_tls"
```

## Справка по CLI

```
desyncd [ОПЦИИ] <КОМАНДА>

Команды:
  run          Запуск прокси (по умолчанию)
  test         Тест техник обхода
  adapt        Автоподбор стратегии
  show-config  Показать конфигурацию
  gui          Запуск GUI

Опции:
  -m, --mode <РЕЖИМ>       socks, transparent, nfq
  -l, --listen <АДРЕС>     Адрес (по умолчанию: 127.0.0.1:1080)
  -c, --config <ПУТЬ>      Путь к конфигу
  -v, --verbose             Детальность логов

Для adapt:
  -d, --domain <ДОМЕН>     Целевые домены
      --domains-file <ПУТЬ> Домены из файла
      --preset <ИМЯ>       russia, china, iran, test
      --morphing            Protocol Morphing (классификация DPI)
      --save                Сохранить в конфиг
```

## Лицензия

MIT OR Apache-2.0
