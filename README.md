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
- **Smart prediction**: reuses proven strategies across domains — new domains often bypass in <200ms
- **Two-phase cold start**: instant internet access with safe defaults while adaptation runs in background
- **Batch domains**: `--preset russia|china|iran`, `--domains-file`, multi-domain `--domain`
- **Auto-config**: `adapt --save` generates a ready-to-use config file
- **Multi-protocol proxy**: SOCKS5, SOCKS4/4a, HTTP CONNECT, HTTP forward proxy — auto-detected on a single port
- **Transparent proxy** (Linux): intercepts via `iptables REDIRECT` + `SO_ORIGINAL_DST`
- **NFQ packet interception** (Linux): kernel-level via NFQUEUE
- **Stealth**: split jitter, timing jitter, randomized fake packets, TLS padding extension (anti-ML)
- **Per-domain rules**: different strategies for different sites, with RFC 6125 wildcard support
- **Pluggable architecture**: add a new bypass technique by implementing a single trait — the engine, CLI, and probe pick it up automatically
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

# Batch adaptation with preset
./target/release/desyncd adapt --preset russia --save

# Batch adaptation with file
./target/release/desyncd adapt --domains-file my_domains.txt --save

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
| `socks` | All | None | SOCKS5/4/4a + HTTP CONNECT + HTTP forward proxy (default) |
| `transparent` | Linux | root | Intercepts via `iptables REDIRECT` + `SO_ORIGINAL_DST` |
| `nfq` | Linux | root/CAP_NET_ADMIN | Kernel packet interception via NFQUEUE |

> **Note:** In `socks` mode, the proxy auto-detects the client protocol (SOCKS5, SOCKS4/4a, HTTP CONNECT, plain HTTP) on a single port — no configuration needed.

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

# Use a preset for your region
desyncd adapt --preset russia --save    # youtube, rutracker, discord, ...
desyncd adapt --preset china --save     # google, wikipedia, twitter, ...

# Load domains from a file (one per line)
desyncd adapt --domains-file blocked.txt --save

# Then just run:
desyncd run
```

The engine: baseline test → smart prediction (reuse known strategies) → sweep all techniques → vary split positions → combine winners → score and save.

**Smart prediction:** When a working strategy is found for one domain, it's automatically tried for new domains first. Since ISPs typically use the same DPI rules, this often works — reducing discovery time from ~60s to <200ms.

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
  -m, --mode <MODE>          socks, transparent, nfq
  -l, --listen <ADDR>        Listen address (default: 127.0.0.1:1080)
  -c, --config <PATH>        Config file path
  -s, --strategy <NAME>      Override strategy for all connections
  -v, --verbose              Increase log verbosity (-v, -vv, -vvv)

Adapt-specific:
  -d, --domain <DOMAIN>      Target domain(s), can be repeated
      --domains-file <PATH>  Read domains from file (one per line)
      --preset <NAME>        Built-in domain list: russia, china, iran, test
      --save                 Save discovered strategies to config
```

## Architecture

```
desyncd-cli          Main binary, cold-start logic, preset domains
desyncd-config       TOML config + CLI argument parsing
desyncd-proxy        Multi-protocol proxy (SOCKS5/4/4a, HTTP), action executor
desyncd-desync       Bypass techniques (Technique trait + registry)
desyncd-packet       Protocol parsing (TLS/HTTP/QUIC)
desyncd-strategy     Strategy selection, domain matching (RFC 6125)
desyncd-adapt        Auto-adaptation engine, smart prediction, probing
desyncd-store        SQLite persistence, cross-domain strategy queries
desyncd-platform     Platform abstraction (firewall, NFQ)
desyncd-nfq          Linux NFQUEUE handler
desyncd-gui          Tauri + Svelte desktop GUI
desyncd-types        Shared types (DesyncAction, SplitPosition, etc.)
```

### Adding a new technique

1. Create `crates/desyncd-desync/src/my_technique.rs` implementing the `Technique` trait
2. Add `pub mod my_technique;` to `lib.rs`
3. Register it in `TechniqueRegistry::default()`

That's it — the strategy engine, probe, and CLI pick it up automatically.

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
- **Умное предсказание**: переиспользует найденные стратегии для новых доменов — часто обход за <200мс
- **Двухфазный холодный старт**: мгновенный доступ в интернет с безопасными дефолтами, пока идёт адаптация
- **Пакетная обработка**: `--preset russia|china|iran`, `--domains-file`, множественные `--domain`
- **Автоконфиг**: `adapt --save` генерирует готовый к использованию конфиг
- **Мультипротокольный прокси**: SOCKS5, SOCKS4/4a, HTTP CONNECT, HTTP forward прокси — автодетект на одном порту
- **Прозрачный прокси** (Linux): перехват через `iptables REDIRECT` + `SO_ORIGINAL_DST`
- **Перехват пакетов NFQ** (Linux): на уровне ядра через NFQUEUE
- **Стелс**: рандомизация позиции разбиения, задержки между сегментами, рандомизация фейковых пакетов, TLS padding (анти-ML)
- **Правила по доменам**: разные стратегии для разных сайтов с поддержкой wildcard (RFC 6125)
- **Расширяемая архитектура**: новая техника обхода = один трейт — движок, CLI и probe подхватят автоматически
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

# Пакетная адаптация с пресетом
./target/release/desyncd adapt --preset russia --save

# Пакетная адаптация из файла
./target/release/desyncd adapt --domains-file my_domains.txt --save

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
| `socks` | Все | Нет | SOCKS5/4/4a + HTTP CONNECT + HTTP forward прокси (по умолчанию) |
| `transparent` | Linux | root | Перехват через `iptables REDIRECT` + `SO_ORIGINAL_DST` |
| `nfq` | Linux | root/CAP_NET_ADMIN | Перехват пакетов через NFQUEUE |

> **Примечание:** В режиме `socks` прокси автоматически определяет протокол клиента (SOCKS5, SOCKS4/4a, HTTP CONNECT, plain HTTP) на одном порту — настройка не нужна.

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

# Использовать пресет для региона
desyncd adapt --preset russia --save    # youtube, rutracker, discord, ...
desyncd adapt --preset china --save     # google, wikipedia, twitter, ...

# Загрузить домены из файла (один на строку)
desyncd adapt --domains-file blocked.txt --save

# Затем просто запустить:
desyncd run
```

Алгоритм: тест базовой связи → умное предсказание (переиспользование известных стратегий) → перебор всех техник → вариации позиции разбиения → комбинирование победителей → оценка и сохранение.

**Умное предсказание:** Когда рабочая стратегия найдена для одного домена, она автоматически пробуется для новых. Поскольку провайдеры обычно используют одинаковые правила DPI, это часто работает — время обнаружения сокращается с ~60с до <200мс.

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
  -m, --mode <РЕЖИМ>        socks, transparent, nfq
  -l, --listen <АДРЕС>      Адрес прослушивания (по умолчанию: 127.0.0.1:1080)
  -c, --config <ПУТЬ>       Путь к конфигу
  -s, --strategy <ИМЯ>      Принудительная стратегия для всех соединений
  -v, --verbose              Увеличить детальность логов (-v, -vv, -vvv)

Для adapt:
  -d, --domain <ДОМЕН>      Целевые домены, можно повторять
      --domains-file <ПУТЬ>  Читать домены из файла (один на строку)
      --preset <ИМЯ>         Встроенный список доменов: russia, china, iran, test
      --save                 Сохранить найденные стратегии в конфиг
```

## Лицензия

MIT OR Apache-2.0
