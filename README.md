[English](#desyncd) | [Русский](#desyncd-rus)

---

# desyncd 2.0

**Adaptive DPI desynchronization tool.** Automatically discovers and applies the best bypass strategies for your ISP and target domains.

Combines the power of [zapret](https://github.com/bol-van/zapret) with the simplicity of [byedpi](https://github.com/hufrea/byedpi), in a single Rust binary with auto-adaptation, Protocol Morphing, and multi-stream TLS fragmentation.

> **Version 2.0 highlights:** intelligent DPI classifier (Protocol Morphing), multi-stream TLS record fragmentation (MSF) with the best P95 latency in head-to-head benchmarks vs `byedpi`/`tpws`, new `OffsetFrom`/`SniExtStart`/`EndSld`/`MidSld` split markers, per-technique L7 filters for protocol-aware chains, and a one-line cross-platform installer.

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
- **Multi-Stream Fragmentation (MSF)** — splits the TLS ClientHello into N≥3 TLS records (default 3), scattering the SNI across all of them. Faster P95 and more robust against re-segmenting middleboxes than a 2-record split. See [Multi-Stream Fragmentation](#multi-stream-fragmentation).
- **Marker-based split positions** — new `sniext`, `endsld`, `midsld`, and `OffsetFrom { marker, delta }` split markers compatible with the byedpi / zapret ecosystem, letting operators nudge a split a few bytes from any named anchor.
- **Per-technique L7 filters** — `l7_filter = "tls" | "http" | "quic" | "any"` lets a single strategy chain apply TLS techniques only to TLS, HTTP techniques only to HTTP, etc., instead of duplicating strategies per protocol.
- **One-line installer** — `curl | bash` for macOS/Linux, PowerShell one-liner for Windows. Handles Rust installation automatically.
- **Head-to-head benchmarks** — desyncd-msf has the lowest P95 latency against `byedpi` and `tpws` on 5 blocked domains in Russia. See [Benchmarks](#benchmarks).
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
- **Latency is better than the 2-record split on uncooperative CDNs** — some frontends introduce variable extra delay for exactly 2-record ClientHellos, while the 3+ record path hits the common handshake-reassembly code path. In our benchmarks (see below), MSF has the lowest P95 latency of any tool tested.

MSF is the default recommended technique against TSPU in `--preset russia` configurations.

## Benchmarks

Head-to-head latency comparison of desyncd 2.0 against the two most popular open-source DPI bypass tools (`byedpi` and `tpws`), measured from Russia against 5 of the most commonly-blocked domains.

### Methodology

- **Domains:** `twitter.com`, `discord.com`, `www.bbc.com`, `meduza.io`, `www.roblox.com` (all confirmed blocked — `direct` control fails on all of them).
- **Trials:** 4 per (tool, domain) combination = **20 runs per tool**.
- **Client:** `curl --proxy socks5h://127.0.0.1:<port> https://<domain> -o /dev/null -w %{time_total}` with a 10 s timeout.
- **Configurations tested:**
  - `desyncd-tlsrec` — desyncd with `tls_record_frag` at `SniOffset(1)`.
  - `desyncd-msf` — desyncd with `multi_stream_frag` at `Sni` (3 records, the 2.0 default).
  - `byedpi` — upstream `byedpi` with `--tlsrec 1+s` (its TSPU-recommended preset).
  - `tpws` — upstream `tpws` with `--tlsrec=sniext+1` (its TSPU-recommended preset).
- **Metric of interest:** P95 — the 95th-percentile wall-clock time a user would actually experience on a cold TLS handshake. Median hides tail spikes caused by middlebox timeouts; P95 surfaces them.

Scripts and raw per-run CSV data live in the `dpi-bench/` directory outside this repo; they can be rerun with `bash bench.sh` + `python aggregate.py`.

### Per-domain results

| Domain | Tool | Success | Median | Min | Max | P95 |
|---|---|---|---:|---:|---:|---:|
| discord.com | desyncd-tlsrec | 4/4 | 292 | 252 | 679 | 679 |
| discord.com | **desyncd-msf** | 4/4 | 319 | 235 | **447** | **447** |
| discord.com | byedpi | 4/4 | 255 | 227 | 352 | 352 |
| discord.com | tpws | 4/4 | 314 | 231 | 425 | 425 |
| meduza.io | desyncd-tlsrec | 4/4 | 423 | 377 | 868 | 868 |
| meduza.io | **desyncd-msf** | 4/4 | 405 | 284 | **491** | **491** |
| meduza.io | byedpi | 4/4 | 423 | 298 | 1379 | 1379 |
| meduza.io | tpws | 4/4 | 391 | 296 | 990 | 990 |
| twitter.com | desyncd-tlsrec | 4/4 | 232 | 221 | 306 | 306 |
| twitter.com | **desyncd-msf** | 4/4 | 237 | 222 | **239** | **239** |
| twitter.com | byedpi | 4/4 | 226 | 221 | 250 | 250 |
| twitter.com | tpws | 4/4 | 242 | 222 | 275 | 275 |
| www.bbc.com | desyncd-tlsrec | 4/4 | 367 | 276 | 622 | 622 |
| www.bbc.com | **desyncd-msf** | 4/4 | 424 | 338 | **473** | **473** |
| www.bbc.com | byedpi | 4/4 | 360 | 274 | 1336 | 1336 |
| www.bbc.com | tpws | 4/4 | 373 | 264 | 432 | 432 |
| www.roblox.com | desyncd-tlsrec | 4/4 | 580 | 468 | 856 | 856 |
| www.roblox.com | **desyncd-msf** | 4/4 | 462 | 434 | **481** | **481** |
| www.roblox.com | byedpi | 4/4 | 606 | 445 | 844 | 844 |
| www.roblox.com | tpws | 4/4 | 466 | 442 | 676 | 676 |

Timings are in milliseconds. All 4 tools achieve **20/20 success** — they all work. The differentiator is tail latency.

### Aggregate (20 runs per tool)

| Tool | Success | Median | Mean | **P95** |
|---|---|---:|---:|---:|
| desyncd-tlsrec | 20/20 | 386 ms | 435 ms | 868 ms |
| **desyncd-msf** | 20/20 | 380 ms | 367 ms | **491 ms** |
| byedpi | 20/20 | 346 ms | 468 ms | 1379 ms |
| tpws | 20/20 | 362 ms | 391 ms | 990 ms |

**desyncd-msf has the best P95 latency of all four tools** — 491 ms vs 990 ms for tpws (2.0× better) and 1379 ms for byedpi (2.8× better). Its mean is also the lowest (367 ms vs 391–468 ms). The median is within 40 ms of the fastest tool, and the *maximum* single observation across the entire 20-run dataset is 491 ms — meaning MSF never exhibited the 800–1400 ms tail spikes that every other tool produces on at least one domain.

For most users the median is not the interesting number: the median TLS handshake already feels fast. What makes a browser feel responsive is the absence of stalls on the 1-in-10 or 1-in-20 page load where a middlebox has a bad day. That is P95, and MSF is the only tested technique that keeps it under 500 ms.

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

> **Что нового в 2.0:** интеллектуальный классификатор DPI (Protocol Morphing), мульти-стрим фрагментация TLS-записей (MSF) с лучшим P95 в сравнении с `byedpi`/`tpws`, новые маркеры разрезания `OffsetFrom`/`SniExtStart`/`EndSld`/`MidSld`, L7-фильтры для протокол-aware цепочек и установщик одной командой на всех платформах.

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
- **Multi-Stream Fragmentation (MSF)** — разбивает TLS ClientHello на N ≥ 3 TLS-записей (по умолчанию 3), распределяя SNI между ними. Ниже P95-задержка и выше устойчивость к middlebox'ам, пересобирающим сегменты, чем у 2-х-рекордного split'а. Смотри раздел [Multi-Stream Fragmentation](#msf-rus).
- **Маркер-базированные позиции разреза** — новые маркеры `sniext`, `endsld`, `midsld` и `OffsetFrom { marker, delta }`, совместимые с экосистемой byedpi/zapret. Позволяют сдвинуть точку разреза на несколько байт от любого именованного якоря.
- **L7-фильтры на уровне техники** — `l7_filter = "tls" | "http" | "quic" | "any"` позволяет в одной стратегии-цепочке применять TLS-техники только к TLS, HTTP-техники только к HTTP и т. д.
- **Установщик одной командой** — `curl | bash` для macOS/Linux, PowerShell для Windows. Автоматически ставит Rust.
- **Сравнительные бенчмарки** — desyncd-msf имеет наименьший P95 среди `byedpi` и `tpws` на 5 заблокированных в РФ доменах. Смотри раздел [Бенчмарки](#benchmarks-rus).
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
- **Задержка лучше, чем у 2-записного split'а на капризных CDN** — некоторые фронтенды вносят переменную задержку именно для 2-записных ClientHello, тогда как путь из 3+ записей попадает в общий код reassembly. В бенчмарках ниже MSF имеет наименьший P95 среди всех протестированных инструментов.

MSF — рекомендованная по умолчанию техника против ТСПУ в конфигурации `--preset russia`.

<a id="benchmarks-rus"></a>

## Бенчмарки

Сравнение задержек desyncd 2.0 с двумя самыми популярными открытыми инструментами обхода DPI (`byedpi` и `tpws`), измеренное из России на 5 из наиболее часто блокируемых доменов.

### Методология

- **Домены:** `twitter.com`, `discord.com`, `www.bbc.com`, `meduza.io`, `www.roblox.com` (все подтверждённо заблокированы — контроль `direct` падает на всех).
- **Испытаний:** 4 на каждую пару (инструмент, домен) = **20 запусков на инструмент**.
- **Клиент:** `curl --proxy socks5h://127.0.0.1:<port> https://<domain> -o /dev/null -w %{time_total}` с таймаутом 10 с.
- **Тестируемые конфигурации:**
  - `desyncd-tlsrec` — desyncd с `tls_record_frag` в позиции `SniOffset(1)`.
  - `desyncd-msf` — desyncd с `multi_stream_frag` в позиции `Sni` (3 записи, дефолт 2.0).
  - `byedpi` — upstream `byedpi` с `--tlsrec 1+s` (его ТСПУ-пресет).
  - `tpws` — upstream `tpws` с `--tlsrec=sniext+1` (его ТСПУ-пресет).
- **Метрика интереса:** P95 — 95-й перцентиль фактического времени ожидания пользователя на холодном TLS-handshake. Медиана прячет хвосты из-за таймаутов middlebox'ов; P95 их вытаскивает.

Скрипты и сырые CSV-данные находятся в каталоге `dpi-bench/` вне репозитория, запускаются через `bash bench.sh` + `python aggregate.py`.

### Результаты по доменам

| Домен | Инструмент | Успех | Медиана | Мин | Макс | P95 |
|---|---|---|---:|---:|---:|---:|
| discord.com | desyncd-tlsrec | 4/4 | 292 | 252 | 679 | 679 |
| discord.com | **desyncd-msf** | 4/4 | 319 | 235 | **447** | **447** |
| discord.com | byedpi | 4/4 | 255 | 227 | 352 | 352 |
| discord.com | tpws | 4/4 | 314 | 231 | 425 | 425 |
| meduza.io | desyncd-tlsrec | 4/4 | 423 | 377 | 868 | 868 |
| meduza.io | **desyncd-msf** | 4/4 | 405 | 284 | **491** | **491** |
| meduza.io | byedpi | 4/4 | 423 | 298 | 1379 | 1379 |
| meduza.io | tpws | 4/4 | 391 | 296 | 990 | 990 |
| twitter.com | desyncd-tlsrec | 4/4 | 232 | 221 | 306 | 306 |
| twitter.com | **desyncd-msf** | 4/4 | 237 | 222 | **239** | **239** |
| twitter.com | byedpi | 4/4 | 226 | 221 | 250 | 250 |
| twitter.com | tpws | 4/4 | 242 | 222 | 275 | 275 |
| www.bbc.com | desyncd-tlsrec | 4/4 | 367 | 276 | 622 | 622 |
| www.bbc.com | **desyncd-msf** | 4/4 | 424 | 338 | **473** | **473** |
| www.bbc.com | byedpi | 4/4 | 360 | 274 | 1336 | 1336 |
| www.bbc.com | tpws | 4/4 | 373 | 264 | 432 | 432 |
| www.roblox.com | desyncd-tlsrec | 4/4 | 580 | 468 | 856 | 856 |
| www.roblox.com | **desyncd-msf** | 4/4 | 462 | 434 | **481** | **481** |
| www.roblox.com | byedpi | 4/4 | 606 | 445 | 844 | 844 |
| www.roblox.com | tpws | 4/4 | 466 | 442 | 676 | 676 |

Времена в миллисекундах. Все 4 инструмента дают **20/20 успешных** запусков — работают все. Отличаются задержки на хвосте распределения.

### Агрегат (20 запусков на инструмент)

| Инструмент | Успех | Медиана | Среднее | **P95** |
|---|---|---:|---:|---:|
| desyncd-tlsrec | 20/20 | 386 мс | 435 мс | 868 мс |
| **desyncd-msf** | 20/20 | 380 мс | 367 мс | **491 мс** |
| byedpi | 20/20 | 346 мс | 468 мс | 1379 мс |
| tpws | 20/20 | 362 мс | 391 мс | 990 мс |

**У desyncd-msf самый низкий P95 из всех четырёх инструментов** — 491 мс против 990 мс у tpws (в 2.0 раза лучше) и 1379 мс у byedpi (в 2.8 раза лучше). Среднее тоже самое низкое (367 мс против 391–468 мс). Медиана в пределах 40 мс от самого быстрого инструмента, а *максимальное* наблюдение за все 20 запусков — 491 мс. То есть MSF никогда не показывал хвостовых всплесков на 800–1400 мс, которые есть у каждого другого инструмента хотя бы на одном домене.

Большинству пользователей интересна не медиана: медианный handshake уже кажется быстрым. Субъективную «отзывчивость» браузера определяет отсутствие залипаний на каждой 10-й или 20-й загрузке страницы, где middlebox «тупит». Это и есть P95, и MSF — единственная из протестированных техник, удерживающая его ниже 500 мс.

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
