[English](#desyncd) | [Русский](#desyncd-rus)

---

# desyncd

Adaptive DPI desynchronization tool. Automatically discovers and applies the best bypass strategies for your ISP and target domains.

Combines the power of [zapret](https://github.com/bol-van/zapret) with the simplicity of [byedpi](https://github.com/hufrea/byedpi), in a single Rust binary with auto-adaptation.

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

- **Protocol Morphing** — intelligent DPI classifier that identifies your ISP's DPI type (TSPU, GFW, etc.) in 5 probes and selects the optimal counter-strategy. Use with `--morphing`.
- **Multi-Stream Fragmentation** — splits TLS ClientHello into N records (default 3), distributing SNI across all of them. Faster and more robust than single-split fragmentation.
- **One-line installer** — `curl | bash` for macOS/Linux, PowerShell one-liner for Windows. Handles Rust installation automatically.
- **Bug fixes** — bounds checking in TLS parser, zero-length domain rejection, error logging in proxy relay.

## Features

- **8 bypass techniques**: TCP split, TLS record fragmentation, **multi-stream fragmentation (NEW)**, fake packet injection, disorder, SNI manipulation, HTTP Host tricks, and technique chaining
- **Protocol Morphing**: classifies DPI type and selects optimal strategy automatically
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

## Techniques

| Technique | Layer | vs TSPU | Description |
|-----------|-------|---------|-------------|
| `tcp_split` | TCP | - | Splits TCP segment at SNI position |
| `tls_record_frag` | TLS | **OK** | Fragments ClientHello into 2 TLS records |
| `multi_stream_frag` | TLS | **OK** | Fragments ClientHello into N TLS records (NEW) |
| `fake_packet` | TCP | - | Injects fake TLS record before ClientHello |
| `disorder` | TCP | - | Sends segments in reverse order |
| `sni_manip` | TLS | - | Modifies SNI: mixed case, removal |
| `http_host` | HTTP | N/A | Modifies HTTP Host header |
| `combo` | Chain | Varies | Applies multiple techniques in sequence |

For in-depth documentation with diagrams and test results, see **[docs/TECHNIQUES.md](docs/TECHNIQUES.md)**.

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

# desyncd (Русский)

[English](#desyncd) | **Русский**

Адаптивный инструмент десинхронизации DPI. Автоматически находит и применяет лучшие стратегии обхода блокировок для вашего провайдера.

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

- **Protocol Morphing** — интеллектуальный классификатор DPI, определяющий тип системы блокировки (ТСПУ и др.) за 5 проб. Используйте с `--morphing`.
- **Multi-Stream Fragmentation** — разбивает TLS ClientHello на N записей (по умолчанию 3), распределяя SNI между ними. Быстрее и надёжнее однократной фрагментации.
- **Установщик одной командой** — `curl | bash` для macOS/Linux, PowerShell для Windows. Автоматически ставит Rust.
- **Исправления багов** — проверки границ в TLS-парсере, валидация длин, логирование ошибок прокси.

## Возможности

- **8 техник обхода**: TCP split, TLS record frag, **multi-stream frag (НОВОЕ)**, fake packet, disorder, SNI manip, HTTP Host, combo
- **Protocol Morphing**: классифицирует DPI и подбирает оптимальную стратегию
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

## Техники обхода

| Техника | Уровень | vs ТСПУ | Описание |
|---------|---------|---------|----------|
| `tcp_split` | TCP | - | Разбивает TCP-сегмент в позиции SNI |
| `tls_record_frag` | TLS | **OK** | Фрагментирует ClientHello на 2 TLS-записи |
| `multi_stream_frag` | TLS | **OK** | Фрагментирует на N записей (НОВОЕ) |
| `fake_packet` | TCP | - | Инъекция фейковой TLS-записи |
| `disorder` | TCP | - | Отправка сегментов в обратном порядке |
| `sni_manip` | TLS | - | Изменение SNI: регистр, удаление |
| `http_host` | HTTP | - | Изменение HTTP Host |
| `combo` | Цепочка | Зависит | Цепочка техник |

Подробная документация с диаграммами и результатами тестов: **[docs/TECHNIQUES.md](docs/TECHNIQUES.md)**

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
