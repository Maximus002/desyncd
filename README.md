[English](#desyncd) | [Русский](#desyncd-rus)

---

# desyncd

Adaptive DPI desynchronization tool. Automatically discovers and applies the best bypass strategies for your ISP and target domains.

Combines the power of [zapret](https://github.com/bol-van/zapret) with the simplicity of [byedpi](https://github.com/hufrea/byedpi), in a single Rust binary with auto-adaptation.

## TL;DR (3 commands to get started)

```bash
# 1. Build
cargo build --release

# 2. Find what works for your ISP (takes ~1 min per domain)
./target/release/desyncd adapt --domain youtube.com --domain rutracker.org --save

# 3. Run — config is generated automatically
./target/release/desyncd run
```

Set your browser/system SOCKS5 proxy to `127.0.0.1:1080`. Done.

> **What does this do?** Your ISP uses DPI (deep packet inspection) to detect and block certain websites by looking at your traffic. desyncd sits between you and the internet, slightly scrambling the packets so the DPI system can't recognize them — but the destination server still understands them perfectly.

## Features

- **7 bypass techniques**: TCP split, TLS record fragmentation, fake packet injection, disorder, SNI manipulation, HTTP Host tricks, and technique chaining
- **Auto-adaptation**: automatically probes and discovers the best strategy per domain
- **Auto-config**: `adapt --save` generates a ready-to-use config file
- **Multi-mode**: SOCKS5 + HTTP CONNECT proxy (all platforms), transparent proxy (Linux), NFQ packet interception (Linux)
- **Stealth**: split jitter, timing jitter, randomized fake packets, TLS padding extension (anti-ML)
- **Per-domain rules**: different strategies for different sites, with wildcard support
- **GUI**: Tauri + Svelte desktop app (Windows, macOS, Linux)
- **QUIC awareness**: detects QUIC Initial packets for future UDP desync support

## Quick Start

```bash
# Build
cargo build --release

# Run with default config (SOCKS5 on 127.0.0.1:1080)
./target/release/desyncd run

# Test which techniques work for a domain
./target/release/desyncd test --domain youtube.com --all-techniques

# Auto-discover best strategies and generate config
./target/release/desyncd adapt --domain youtube.com --domain rutracker.org --save

# Show effective config
./target/release/desyncd show-config
```

### Connecting through the proxy

**System-wide (macOS):** System Settings → Network → Wi-Fi → Details → Proxies → SOCKS proxy → `127.0.0.1` port `1080`

**Browser (Firefox):** Settings → Network Settings → Manual proxy → SOCKS Host: `127.0.0.1`, Port: `1080`, SOCKS v5

**Command line:**
```bash
curl --proxy socks5h://127.0.0.1:1080 https://youtube.com -I
# or for all programs:
export ALL_PROXY=socks5h://127.0.0.1:1080
```

## Modes

| Mode | Platform | Privileges | Description |
|------|----------|------------|-------------|
| `socks` | All | None | SOCKS5 + HTTP CONNECT proxy (default) |
| `transparent` | Linux | root | Intercepts via `iptables REDIRECT` + `SO_ORIGINAL_DST` |
| `nfq` | Linux | root/CAP_NET_ADMIN | Kernel packet interception via NFQUEUE |

## Configuration

`adapt --save` auto-generates the config at `~/.config/desyncd/config.toml`. You can also create it manually:

```toml
[general]
mode = "socks"
log_level = "info"

[proxy]
listen = "127.0.0.1:1080"

[adaptation]
enabled = true
test_interval_secs = 21600  # 6 hours
test_domains = ["youtube.com", "rutracker.org"]

[stealth]
split_jitter = 4
timing_jitter_us = 500
randomize_tls_padding = true
fake_size_range = [48, 200]

# --- Strategies ---
[strategies.default_tls]
techniques = [
    { name = "tcp_split", split_position = "Sni" },
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
| `tcp_split` | TCP | Splits TCP segment at SNI position into 2+ sends |
| `tls_record_frag` | TLS | Fragments ClientHello into multiple TLS records |
| `fake_packet` | TCP | Injects a fake TLS record before the real ClientHello |
| `disorder` | TCP | Sends split segments in reverse order |
| `sni_manip` | TLS | Modifies SNI field: mixed case, removal, or padding |
| `http_host` | HTTP | Modifies HTTP Host header: mixed case, extra spaces, tabs |
| combo | Chain | Applies multiple techniques in sequence |

## Auto-Adaptation

```bash
# Find best strategy for one or more domains, generate config
desyncd adapt --domain youtube.com --domain discord.com --save
# Then just run:
desyncd run
```

The engine: baseline test → sweep all techniques → vary split positions → combine winners → score and save.

## Stealth Features

| Parameter | Effect |
|-----------|--------|
| `split_jitter` | Randomizes split position by +/- N bytes per connection |
| `timing_jitter_us` | Random delay between segments (microseconds) |
| `fake_size_range` | Randomizes fake TLS record size |
| `randomize_tls_padding` | Adds random TLS padding extension (anti-ML) |

## Building from Source

```bash
# Requirements: Rust 1.70+
cargo build --release

# Run tests
cargo test

# GUI (requires Node.js)
cd crates/desyncd-gui && cargo tauri dev
```

## CLI Reference

```
desyncd [OPTIONS] <COMMAND>

Commands:
  run          Start the proxy (default)
  test         Test bypass techniques against domains
  adapt        Auto-discover best strategy and generate config
  show-config  Print effective configuration

Options:
  -m, --mode <MODE>       socks, transparent, nfq
  -l, --listen <ADDR>     Listen address (default: 127.0.0.1:1080)
  -c, --config <PATH>     Config file path
  -s, --strategy <NAME>   Override strategy for all connections
  -v, --verbose           Increase log verbosity (-v, -vv, -vvv)
```

## Architecture

```
desyncd-cli          Main binary
desyncd-config       TOML config + CLI
desyncd-proxy        SOCKS5/HTTP CONNECT/transparent proxy
desyncd-desync       Bypass technique implementations
desyncd-packet       Protocol parsing (TLS/HTTP/QUIC)
desyncd-strategy     Strategy selection and domain matching
desyncd-adapt        Auto-adaptation engine
desyncd-store        SQLite persistence
desyncd-platform     Platform abstraction (firewall, NFQ)
desyncd-nfq          Linux NFQUEUE handler
desyncd-gui          Tauri + Svelte desktop GUI
desyncd-types        Shared types
```

## License

MIT OR Apache-2.0

---

<a id="desyncd-rus"></a>

# desyncd (Русский)

[English](#desyncd) | **Русский**

Адаптивный инструмент десинхронизации DPI. Автоматически находит и применяет лучшие стратегии обхода блокировок для вашего провайдера.

Объединяет мощь [zapret](https://github.com/bol-van/zapret) с простотой [byedpi](https://github.com/hufrea/byedpi) в одном Rust-бинарнике с автоадаптацией.

## TL;DR (3 команды и готово)

```bash
# 1. Собрать
cargo build --release

# 2. Найти что работает у вашего провайдера (~1 мин на домен)
./target/release/desyncd adapt --domain youtube.com --domain rutracker.org --save

# 3. Запустить — конфиг генерируется автоматически
./target/release/desyncd run
```

Настройте SOCKS5 прокси в браузере/системе: `127.0.0.1:1080`. Готово.

> **Что это делает?** Ваш провайдер использует DPI (глубокий анализ пакетов) для обнаружения и блокировки сайтов, анализируя ваш трафик. desyncd встаёт между вами и интернетом, слегка изменяя пакеты так, что DPI-система не может их распознать — но сервер назначения понимает их отлично.

## Возможности

- **7 техник обхода**: TCP split, фрагментация TLS record, инъекция фейковых пакетов, disorder, манипуляция SNI, трюки с HTTP Host, цепочки техник
- **Автоадаптация**: автоматически тестирует и находит лучшую стратегию для каждого домена
- **Автоконфиг**: `adapt --save` генерирует готовый к использованию конфиг
- **Мультирежим**: SOCKS5 + HTTP CONNECT прокси (все платформы), прозрачный прокси (Linux), перехват пакетов NFQ (Linux)
- **Стелс**: рандомизация позиции разбиения, задержки между сегментами, рандомизация фейковых пакетов, TLS padding (анти-ML)
- **Правила по доменам**: разные стратегии для разных сайтов с поддержкой wildcard
- **GUI**: десктопное приложение Tauri + Svelte (Windows, macOS, Linux)

## Быстрый старт

```bash
# Собрать
cargo build --release

# Запустить с дефолтным конфигом (SOCKS5 на 127.0.0.1:1080)
./target/release/desyncd run

# Протестировать какие техники работают
./target/release/desyncd test --domain youtube.com --all-techniques

# Автоподбор стратегий + генерация конфига
./target/release/desyncd adapt --domain youtube.com --domain rutracker.org --save

# Посмотреть текущий конфиг
./target/release/desyncd show-config
```

### Подключение через прокси

**Системный прокси (macOS):** Системные настройки → Сеть → Wi-Fi → Подробнее → Прокси → SOCKS прокси → `127.0.0.1` порт `1080`

**Браузер (Firefox):** Настройки → Настройки сети → Ручная настройка → SOCKS: `127.0.0.1`, Порт: `1080`, SOCKS v5

**Командная строка:**
```bash
curl --proxy socks5h://127.0.0.1:1080 https://youtube.com -I
# или для всех программ:
export ALL_PROXY=socks5h://127.0.0.1:1080
```

## Режимы работы

| Режим | Платформа | Привилегии | Описание |
|-------|-----------|------------|----------|
| `socks` | Все | Нет | SOCKS5 + HTTP CONNECT прокси (по умолчанию) |
| `transparent` | Linux | root | Перехват через `iptables REDIRECT` + `SO_ORIGINAL_DST` |
| `nfq` | Linux | root/CAP_NET_ADMIN | Перехват пакетов через NFQUEUE |

## Конфигурация

`adapt --save` автоматически генерирует конфиг в `~/.config/desyncd/config.toml`. Можно создать и вручную:

```toml
[general]
mode = "socks"
log_level = "info"

[proxy]
listen = "127.0.0.1:1080"

[adaptation]
enabled = true
test_interval_secs = 21600  # 6 часов
test_domains = ["youtube.com", "rutracker.org"]

[stealth]
split_jitter = 4              # рандомизация позиции разбиения +/- N байт
timing_jitter_us = 500        # задержка между сегментами (микросекунды)
randomize_tls_padding = true  # случайный TLS padding (анти-ML)
fake_size_range = [48, 200]   # рандомизация размера фейковых пакетов

# --- Стратегии ---
[strategies.default_tls]
techniques = [
    { name = "tcp_split", split_position = "Sni" },
]

[strategies.aggressive]
techniques = [
    { name = "tls_record_frag", split_position = "Sni" },
    { name = "tcp_split", split_position = { SniOffset = -2 } },
]

# --- Правила ---
[[rules]]
domains = ["*.youtube.com", "*.googlevideo.com"]
strategy = "aggressive"
priority = 10

[[rules]]
domains = ["*"]
strategy = "default_tls"
priority = 0
```

## Техники обхода

| Техника | Уровень | Описание |
|---------|---------|----------|
| `tcp_split` | TCP | Разбивает TCP-сегмент в позиции SNI на 2+ части |
| `tls_record_frag` | TLS | Фрагментирует ClientHello на несколько TLS-записей |
| `fake_packet` | TCP | Инъектирует фейковую TLS-запись перед настоящим ClientHello |
| `disorder` | TCP | Отправляет сегменты в обратном порядке |
| `sni_manip` | TLS | Изменяет SNI: смешанный регистр, удаление, дополнение |
| `http_host` | HTTP | Изменяет HTTP Host: смешанный регистр, лишние пробелы, табы |
| combo | Цепочка | Применяет несколько техник последовательно |

## Автоадаптация

```bash
# Найти лучшую стратегию для доменов, сгенерировать конфиг
desyncd adapt --domain youtube.com --domain discord.com --save
# Затем просто запустить:
desyncd run
```

Алгоритм: тест базовой связи → перебор всех техник → вариации позиции разбиения → комбинирование победителей → оценка и сохранение.

## Стелс-функции

| Параметр | Эффект |
|----------|--------|
| `split_jitter` | Рандомизирует позицию разбиения на +/- N байт для каждого соединения |
| `timing_jitter_us` | Случайная задержка между сегментами (микросекунды) |
| `fake_size_range` | Рандомизирует размер фейковых TLS-записей |
| `randomize_tls_padding` | Добавляет случайный TLS padding (анти-ML) |

## Сборка из исходников

```bash
# Требования: Rust 1.70+
cargo build --release

# Запуск тестов
cargo test

# GUI (требует Node.js)
cd crates/desyncd-gui && cargo tauri dev
```

## Справка по CLI

```
desyncd [ОПЦИИ] <КОМАНДА>

Команды:
  run          Запуск прокси (по умолчанию)
  test         Тест техник обхода для доменов
  adapt        Автоподбор стратегии и генерация конфига
  show-config  Показать текущую конфигурацию

Опции:
  -m, --mode <РЕЖИМ>     socks, transparent, nfq
  -l, --listen <АДРЕС>   Адрес прослушивания (по умолчанию: 127.0.0.1:1080)
  -c, --config <ПУТЬ>    Путь к конфигу
  -s, --strategy <ИМЯ>   Принудительная стратегия для всех соединений
  -v, --verbose           Увеличить детальность логов (-v, -vv, -vvv)
```

## Лицензия

MIT OR Apache-2.0
