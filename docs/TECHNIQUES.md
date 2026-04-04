[English](#techniques) | [Русский](#техники-обхода)

---

# Techniques

Detailed documentation of all DPI bypass techniques implemented in desyncd 2.0.

## How DPI Works

Deep Packet Inspection (DPI) systems analyze network traffic to identify and block specific websites. The primary method is **SNI inspection** — examining the Server Name Indication field in the TLS ClientHello message to determine which website the user is connecting to.

```
Client                DPI                 Server
  |                    |                    |
  |--- ClientHello --->|                    |
  |    (contains SNI   |                    |
  |     "twitter.com") |                    |
  |                    |--- DROP/RST ------>|
  |                    |                    |
  |<--- RST/Timeout ---|                    |
```

desyncd modifies the packets so that the DPI cannot extract the SNI, while the destination server reassembles them correctly.

## Technique Overview

| # | Technique | Layer | Effectiveness vs TSPU | Effectiveness vs GFW | Speed Impact |
|---|-----------|-------|----------------------|---------------------|--------------|
| 1 | `tcp_split` | TCP | None | Medium | Minimal |
| 2 | `tls_record_frag` | TLS | **High** | Medium | Minimal |
| 3 | `multi_stream_frag` | TLS | **High** | High | Minimal |
| 4 | `fake_packet` | TCP | None (SOCKS) | Medium (NFQ) | Low |
| 5 | `disorder` | TCP | None | Medium | Minimal |
| 6 | `sni_manip` | TLS | None | Low | None |
| 7 | `http_host` | HTTP | N/A (HTTPS only) | N/A | None |
| 8 | `combo` | Chain | Varies | Varies | Varies |

---

## 1. TCP Split (`tcp_split`)

**Layer:** TCP transport
**File:** `crates/desyncd-desync/src/tcp_split.rs`

Splits the application payload at a specified byte offset into multiple TCP segments. In SOCKS proxy mode, each segment is sent as a separate `write()` call with `TCP_NODELAY` enabled, causing the OS to emit separate TCP packets.

```
Original:        [  ClientHello (SNI = "twitter.com")  ]
                                  |
After tcp_split:  [ ClientHe ] [ llo (SNI = "twitter.com") ]
                   Segment 1          Segment 2
```

**How it bypasses DPI:**
Simple DPI systems that only inspect the first TCP segment will see an incomplete ClientHello and cannot extract the SNI. The server's TCP stack reassembles both segments into the complete message.

**When it works:** Against DPI that does not perform TCP reassembly.
**When it fails:** Against DPI that reassembles TCP streams before inspection (e.g., Russian TSPU).

**Parameters:**
- `split_position`: Where to split — `Sni` (at SNI offset), `SniOffset(N)`, `Absolute(N)`, `Random{min, max}`

**Output:** `DesyncAction::Split([segment1, segment2])`

---

## 2. TLS Record Fragmentation (`tls_record_frag`)

**Layer:** TLS record
**File:** `crates/desyncd-desync/src/tls_record_frag.rs`

Fragments the TLS ClientHello into **2 TLS records**. Each record has its own 5-byte header (content_type, version, length). This is fully compliant with RFC 5246 Section 6.2.1, which explicitly allows handshake messages to span multiple records.

```
Original:
  [TLS Header | ClientHello data (with SNI "twitter.com")]

After tls_record_frag:
  [TLS Header | ClientHe...] [TLS Header | ...llo (SNI = "twitter.com")]
       Record 1                      Record 2
```

**How it bypasses DPI:**
DPI systems like the Russian TSPU parse **only the first TLS record** for SNI extraction. Since the first record contains only a fragment of the ClientHello (the SNI bytes are split across records), the DPI cannot find the domain name and lets the traffic through.

**When it works:** Against DPI that inspects only the first TLS record (TSPU, and many other commercial DPI systems).
**When it fails:** Against DPI that reassembles TLS records before inspection.

**Why it works against TSPU specifically:**
TSPU reassembles TCP segments (defeating `tcp_split`) but does NOT reassemble TLS records. It reads only the first TLS record, extracts what it can, and makes a blocking decision. By putting incomplete SNI in the first record, the DPI sees no match and passes the traffic.

**Parameters:**
- `split_position`: Where to split the record data

**Output:** `DesyncAction::Replace(combined_records)` — the original data + 5 bytes overhead (extra TLS header)

**Test results (April 2025, Russian ISP):**

| Domain | Baseline | tls_record_frag |
|--------|----------|-----------------|
| twitter.com | FAIL (timeout) | **OK** (172ms) |
| discord.com | FAIL (timeout) | **OK** (223ms) |
| bbc.com | FAIL (timeout) | **OK** (184ms) |

---

## 3. Multi-Stream Fragmentation (`multi_stream_frag`) — NEW in 2.0

**Layer:** TLS record
**File:** `crates/desyncd-desync/src/multi_stream_frag.rs`

Extends `tls_record_frag` by splitting the ClientHello into **N TLS records** (default 3, configurable up to 8). Split points are calculated to distribute the SNI hostname across multiple records.

```
Original:
  [TLS Header | ClientHello data (with SNI "twitter.com")]

After multi_stream_frag (N=3):
  [TLS Hdr | fragment1] [TLS Hdr | fragment2 (SNI start)] [TLS Hdr | fragment3 (SNI end)]
       Record 1                Record 2                         Record 3
```

**How it bypasses DPI:**
Beyond defeating first-record-only inspectors (like `tls_record_frag`), Multi-Stream Frag also defeats DPI systems that attempt to read the first **N-1** records. With enough fragments, the SNI is spread so thin that fixed-buffer DPI systems cannot reassemble it.

**Split point strategy:**
1. One split before the SNI offset (ensures SNI is NOT in the first record)
2. One split at the SNI offset (splits the hostname itself across records)
3. Remaining splits distributed evenly in the remaining space

**When it works:** Against all DPI that inspects individual TLS records without full reassembly.
**When it fails:** Against DPI that performs complete TLS record reassembly (rare in practice).

**Parameters:**
- `split_position`: Primary split reference point
- `sni_mode` (repurposed): Number of fragments as a string, e.g., `"3"`, `"5"`. Default: 3

**Output:** `DesyncAction::Replace(combined_records)` — overhead: (N-1) * 5 bytes

**Test results (April 2025, Russian ISP):**

| Domain | Baseline | tls_record_frag | **multi_stream_frag** |
|--------|----------|-----------------|----------------------|
| twitter.com | FAIL | OK (1541ms) | **OK (429ms)** |
| discord.com | FAIL | OK (289ms) | **OK (223ms)** |
| bbc.com | FAIL | OK (259ms) | **OK (184ms)** |

Multi-Stream Frag consistently shows **lower latency** than single-split `tls_record_frag`, likely because the smaller individual records are processed faster by both the DPI and the destination server.

---

## 4. Fake Packet Injection (`fake_packet`)

**Layer:** TCP
**File:** `crates/desyncd-desync/src/fake_packet.rs`

Injects decoy TLS records before the real ClientHello. The fake records contain garbage data designed to confuse DPI state machines.

**Two modes:**
- **SOCKS mode:** Generates a fake TLS record with random content type and data. However, since it's on the same TCP stream, the real server also receives it — this breaks TLS handshakes with most servers. **Only useful as a decoy for DPI that reads the first record.**
- **NFQ mode (Linux):** Builds a fake ClientHello with scrambled SNI and corrupted packet properties (bad TTL, bad checksum, bad TCP MD5 signature). The corrupted properties cause routers to drop the packet before it reaches the server, but the DPI (sitting before the router) still processes it.

**When it works:** NFQ mode on Linux, where fake packets with TTL=1 are dropped by the first router hop but processed by the ISP's DPI.
**When it fails:** SOCKS mode (server receives the fake data and rejects the TLS handshake).

**Parameters:**
- `fake_type`: `BadChecksum`, `BadTtl`, `BadMd5Sig`, `BadSeq`
- Stealth: `fake_size_range` controls the random size of fake records

**Output:** `DesyncAction::InjectBefore([fake_chunks])`

---

## 5. Disorder (`disorder`)

**Layer:** TCP transport
**File:** `crates/desyncd-desync/src/disorder.rs`

Sends TCP segments in **reverse order**. The payload is split at the specified position, and the second chunk is sent first, followed by the first chunk. The server's TCP stack reorders by sequence number, but DPI processing packets in arrival order sees incomplete data.

```
Original:     [AAAAABBBBB]
                   |
After disorder: [BBBBB] then [AAAAA]
                 Sent 1st     Sent 2nd
```

**When it works:** Against DPI that processes packets in arrival order without TCP reassembly.
**When it fails:** Against DPI that performs TCP reassembly (e.g., TSPU).

**Output:** `DesyncAction::Split([second_half, first_half])`

---

## 6. SNI Manipulation (`sni_manip`)

**Layer:** TLS
**File:** `crates/desyncd-desync/src/sni_manip.rs`

Modifies the SNI extension bytes within the TLS ClientHello.

**Modes:**
- **MixedCase:** Randomizes the case of hostname bytes (e.g., `"WwW.tWiTtEr.CoM"`). DNS is case-insensitive per RFC 4343, and TLS servers treat SNI as case-insensitive per RFC 6066.
- **Remove:** Replaces SNI bytes with dots, effectively removing the readable hostname while maintaining TLS structure integrity.

**When it works:** Against DPI that does exact case-sensitive SNI string matching.
**When it fails:** Against DPI that normalizes case before comparison (e.g., TSPU lowercases SNI before matching).

**Output:** `DesyncAction::Replace(modified_payload)` — same size as original

---

## 7. HTTP Host Manipulation (`http_host`)

**Layer:** HTTP
**File:** `crates/desyncd-desync/src/http_host.rs`

Modifies the HTTP `Host` header in plaintext HTTP requests.

**Modes:**
- **MixedCase:** `Host: WwW.eXaMpLe.CoM`
- **ExtraSpace:** `Host:  example.com` (double space after colon)
- **Tab:** `Host:\texample.com` (tab instead of space)
- **Duplicate:** Adds a second `Host` header with a decoy value

**When it works:** Against HTTP-level DPI on plain HTTP connections.
**When it fails:** Not applicable to HTTPS (TLS) connections — HTTP Host header is encrypted.

**Output:** `DesyncAction::Replace(modified_request)`

---

## 8. Technique Chaining (`combo`)

**Layer:** Chain
**File:** `crates/desyncd-desync/src/combo.rs`

Applies multiple techniques in sequence. Each technique transforms the payload, and the result is fed to the next technique.

**Example:**
```toml
[strategies.aggressive]
techniques = [
    { name = "tls_record_frag", split_position = "Sni" },
    { name = "tcp_split", split_position = { Absolute = 20 } },
]
```

This first fragments the TLS records (record layer), then splits the result into TCP segments (transport layer) — a double-layer defense.

---

## Protocol Morphing — NEW in 2.0

**File:** `crates/desyncd-adapt/src/morphing.rs`

Protocol Morphing is not a bypass technique itself — it's an **intelligent DPI classifier** that determines which type of DPI your ISP uses and selects the optimal counter-strategy.

### How it works

1. **5 diagnostic probes** (baseline + 4 techniques) are sent to the target domain
2. The response pattern is analyzed to classify the DPI type
3. Only the recommended techniques are tested with parameter variations
4. Result: optimal strategy found in ~12 probes instead of ~20

### DPI Classification

| Probe Results | DPI Profile | Counter-Strategy |
|---|---|---|
| `tls_record_frag` OK, `tcp_split` FAIL | **TlsRecordInspector** (TSPU) | `tls_record_frag` / `multi_stream_frag` |
| `tcp_split` OK, `tls_record_frag` FAIL | **TcpNaive** | `tcp_split` |
| Only `sni_manip` OK | **SniExactMatch** | `sni_manip` |
| `disorder` OK, `tcp_split` FAIL | **OrderDependent** | `disorder` |
| All FAIL + connection refused | **IpBlocked** | No SNI bypass possible |
| All OK | **Permissive** | Use fastest technique |

### Usage

```bash
desyncd adapt --domain twitter.com --morphing --save
```

### Real-world classification results (April 2025)

| Domain | Profile | Confidence | Best Strategy | Score |
|--------|---------|------------|---------------|-------|
| twitter.com | TlsRecordInspector (TSPU) | **90%** | `tls_record_frag SniOffset(1)` | 98.5 |
| discord.com | TlsRecordInspector (TSPU) | **90%** | `tls_record_frag SniOffset(-2)` | 97.8 |
| bbc.com | TlsRecordInspector (TSPU) | **90%** | `tls_record_frag SniOffset(-2)` | 98.3 |
| roblox.com | Not blocked | 100% | — | — |

---

<a id="техники-обхода"></a>

# Техники обхода

[English](#techniques) | **Русский**

Подробная документация всех техник обхода DPI, реализованных в desyncd 2.0.

## Как работает DPI

Системы глубокого анализа пакетов (DPI) анализируют сетевой трафик для обнаружения и блокировки определённых сайтов. Основной метод — **инспекция SNI** — проверка поля Server Name Indication в TLS ClientHello для определения домена, к которому подключается пользователь.

desyncd модифицирует пакеты так, чтобы DPI не смогла извлечь SNI, в то время как сервер назначения корректно собирает данные.

## Обзор техник

| # | Техника | Уровень | Эффективность vs ТСПУ | Скорость |
|---|---------|---------|----------------------|----------|
| 1 | `tcp_split` | TCP | Нет | Минимальная |
| 2 | `tls_record_frag` | TLS | **Высокая** | Минимальная |
| 3 | `multi_stream_frag` | TLS | **Высокая** | Минимальная |
| 4 | `fake_packet` | TCP | Нет (SOCKS) | Низкая |
| 5 | `disorder` | TCP | Нет | Минимальная |
| 6 | `sni_manip` | TLS | Нет | Нет |
| 7 | `http_host` | HTTP | Неприменимо | Нет |
| 8 | `combo` | Цепочка | Зависит | Зависит |

---

## 1. TCP Split (`tcp_split`)

Разбивает payload на несколько TCP-сегментов в заданной позиции. Каждый сегмент отправляется отдельным `write()` с `TCP_NODELAY`.

**Когда работает:** Против DPI, не выполняющей реассемблирование TCP.
**Когда НЕ работает:** Против ТСПУ (выполняет TCP reassembly).

---

## 2. TLS Record Fragmentation (`tls_record_frag`)

Фрагментирует ClientHello на **2 TLS-записи**. Каждая запись имеет собственный 5-байтный заголовок. Полностью соответствует RFC 5246.

**Почему работает против ТСПУ:** ТСПУ реассемблирует TCP, но НЕ реассемблирует TLS-записи. Она читает только первую TLS-запись. Поместив неполный SNI в первую запись, DPI не находит совпадение и пропускает трафик.

**Результаты тестов (апрель 2025):** twitter.com, discord.com, bbc.com — все обходятся.

---

## 3. Multi-Stream Fragmentation (`multi_stream_frag`) — НОВОЕ в 2.0

Расширяет `tls_record_frag`, разбивая ClientHello на **N TLS-записей** (по умолчанию 3, максимум 8). Точки разбиения рассчитываются так, чтобы SNI был распределён между записями.

**Стратегия размещения точек разбиения:**
1. Одна точка перед SNI (SNI не попадает в первую запись)
2. Одна точка на позиции SNI (имя хоста разрезается пополам)
3. Остальные точки распределяются равномерно

**Преимущество над `tls_record_frag`:**
- Побеждает DPI с окном чтения N-1 записей
- Показывает более низкую задержку в тестах (twitter: 429ms vs 1541ms)

**Результаты тестов (апрель 2025):**

| Домен | baseline | tls_record_frag | **multi_stream_frag** |
|-------|----------|-----------------|----------------------|
| twitter.com | FAIL | OK (1541ms) | **OK (429ms)** |
| discord.com | FAIL | OK (289ms) | **OK (223ms)** |
| bbc.com | FAIL | OK (259ms) | **OK (184ms)** |

---

## 4-7. Остальные техники

- **fake_packet** — инъекция фейковых TLS-записей. В SOCKS-режиме ломает TLS, работает только в NFQ.
- **disorder** — отправка TCP-сегментов в обратном порядке. Против ТСПУ неэффективна.
- **sni_manip** — изменение регистра SNI. ТСПУ нормализует регистр перед сравнением.
- **http_host** — модификация HTTP Host. Неприменимо к HTTPS.

---

## Protocol Morphing — НОВОЕ в 2.0

Интеллектуальный классификатор DPI. Определяет тип DPI вашего провайдера за 5 диагностических проб и выбирает оптимальную стратегию.

### Классификация

| Результаты проб | Профиль DPI | Стратегия |
|---|---|---|
| `tls_record_frag` OK, `tcp_split` FAIL | **ТСПУ** | `tls_record_frag` / `multi_stream_frag` |
| `tcp_split` OK, `tls_record_frag` FAIL | **TCP-наивный** | `tcp_split` |
| Только `sni_manip` OK | **SNI exact-match** | `sni_manip` |
| Всё FAIL + connection refused | **IP-блокировка** | Обход невозможен |
| Всё OK | **Слабый DPI** | Самая быстрая техника |

### Использование

```bash
desyncd adapt --domain twitter.com --morphing --save
```

### Результаты классификации (апрель 2025, российский провайдер)

| Домен | Профиль | Уверенность | Лучшая стратегия | Оценка |
|-------|---------|-------------|------------------|--------|
| twitter.com | ТСПУ | **90%** | `tls_record_frag SniOffset(1)` | 98.5 |
| discord.com | ТСПУ | **90%** | `tls_record_frag SniOffset(-2)` | 97.8 |
| bbc.com | ТСПУ | **90%** | `tls_record_frag SniOffset(-2)` | 98.3 |
| roblox.com | Не заблокирован | 100% | — | — |
