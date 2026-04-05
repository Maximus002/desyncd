//! Secure DNS resolver with in-process caching.
//!
//! Bypasses DNS poisoning by querying public DNS servers via
//! DNS-over-TLS (DoT, RFC 7858) on port 853. Unlike plain UDP/53,
//! DoT is encrypted — the ISP cannot inspect or tamper with queries.
//!
//! Servers: Cloudflare (1.1.1.1) and Google (8.8.8.8).
//!
//! Falls back to plain UDP/53 if DoT fails, then to system DNS.
//!
//! This crate also provides [`DnsCache`], an in-process LRU-like cache
//! that memoizes `domain -> SocketAddr` for a configurable TTL so that
//! repeat proxy connections don't re-enter the resolver every time.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream;
use tracing::{debug, trace, warn};

/// DoT server: (IP, SNI hostname for certificate validation).
const DOT_SERVERS: &[(IpAddr, &str)] = &[
    (IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), "cloudflare-dns.com"),
    (IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)), "cloudflare-dns.com"),
    (IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), "dns.google"),
    (IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), "dns.google"),
];

/// Plain UDP DNS servers (fallback if DoT fails).
const UDP_DNS_SERVERS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
];

/// Timeout per DNS query.
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

/// Build a shared TLS config for DoT connections (cached).
fn dot_tls_config() -> Arc<rustls::ClientConfig> {
    static TLS_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    TLS_CONFIG.get_or_init(|| {
        let root_store = rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        );
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("TLS protocol versions")
        .with_root_certificates(root_store)
        .with_no_client_auth();
        Arc::new(config)
    }).clone()
}

/// Pool of persistent DoT connections to avoid repeated TLS handshakes.
struct DotPool {
    /// One cached connection per server index.
    conns: Vec<Mutex<Option<TlsStream<TcpStream>>>>,
}

impl DotPool {
    fn new() -> Self {
        let conns = DOT_SERVERS.iter().map(|_| Mutex::new(None)).collect();
        Self { conns }
    }

    /// Get or create a DoT connection for the given server index.
    async fn get_or_connect(
        &self,
        server_idx: usize,
        tls_config: &Arc<rustls::ClientConfig>,
    ) -> anyhow::Result<tokio::sync::MutexGuard<'_, Option<TlsStream<TcpStream>>>> {
        let mut guard = self.conns[server_idx].lock().await;
        if guard.is_none() {
            let (ip, sni) = DOT_SERVERS[server_idx];
            let addr = SocketAddr::new(ip, 853);
            let tcp = tokio::time::timeout(DNS_TIMEOUT, TcpStream::connect(addr)).await??;
            let connector = tokio_rustls::TlsConnector::from(tls_config.clone());
            let server_name = rustls::pki_types::ServerName::try_from(sni.to_string())?;
            let tls_stream = tokio::time::timeout(
                DNS_TIMEOUT,
                connector.connect(server_name, tcp),
            ).await??;
            trace!(server = %ip, "DoT: new TLS connection established");
            *guard = Some(tls_stream);
        }
        Ok(guard)
    }
}

fn dot_pool() -> &'static DotPool {
    static POOL: OnceLock<DotPool> = OnceLock::new();
    POOL.get_or_init(DotPool::new)
}

/// Resolve a domain to IP addresses using secure DNS.
///
/// Tries DNS-over-TLS first (encrypted, tamper-proof), then falls back
/// to plain UDP/53 if DoT is unreachable.
pub async fn resolve_secure(domain: &str) -> anyhow::Result<Vec<IpAddr>> {
    // Try DoT first.
    match resolve_dot(domain).await {
        Ok(ips) if !ips.is_empty() => return Ok(ips),
        Ok(_) => debug!(%domain, "DoT returned no A records, trying UDP fallback"),
        Err(e) => debug!(%domain, error = %e, "DoT failed, trying UDP fallback"),
    }

    // Fallback: plain UDP/53.
    for &server in UDP_DNS_SERVERS {
        match query_dns_udp(domain, server).await {
            Ok(ips) if !ips.is_empty() => {
                debug!(%domain, server = %server, ips = ?ips, "UDP DNS resolved (fallback)");
                return Ok(ips);
            }
            _ => continue,
        }
    }

    anyhow::bail!("all DNS methods failed for {}", domain)
}

/// Resolve using both system DNS and secure DNS, prefer secure.
pub async fn resolve_with_fallback(domain: &str) -> anyhow::Result<Vec<IpAddr>> {
    match resolve_secure(domain).await {
        Ok(secure_ips) => {
            // Compare with system DNS for poisoning detection.
            if let Ok(system_ips) = resolve_system(domain).await {
                let secure_set: std::collections::HashSet<_> = secure_ips.iter().collect();
                let system_set: std::collections::HashSet<_> = system_ips.iter().collect();

                if secure_set != system_set {
                    warn!(
                        %domain,
                        system = ?system_ips,
                        secure = ?secure_ips,
                        "DNS mismatch detected (possible poisoning), using secure DNS"
                    );
                }
            }
            Ok(secure_ips)
        }
        Err(e) => {
            debug!(%domain, error = %e, "secure DNS failed, falling back to system");
            resolve_system(domain).await
        }
    }
}

/// Resolve via DNS-over-TLS (port 853).
///
/// DNS-over-TLS: same wire format as TCP DNS (2-byte length prefix + query),
/// but over a TLS connection. The ISP sees only encrypted traffic to port 853.
/// Uses a persistent connection pool to avoid repeated TLS handshakes.
async fn resolve_dot(domain: &str) -> anyhow::Result<Vec<IpAddr>> {
    let tls_config = dot_tls_config();
    let pool = dot_pool();

    for (idx, &(server_ip, _)) in DOT_SERVERS.iter().enumerate() {
        match query_dns_dot_pooled(domain, idx, &tls_config, pool).await {
            Ok(ips) if !ips.is_empty() => {
                debug!(
                    %domain, server = %server_ip, ips = ?ips,
                    "DoT resolved"
                );
                return Ok(ips);
            }
            Ok(_) => {
                debug!(%domain, server = %server_ip, "DoT: no A records");
            }
            Err(e) => {
                debug!(%domain, server = %server_ip, error = %e, "DoT query failed");
            }
        }
    }

    anyhow::bail!("all DoT servers failed for {}", domain)
}

/// Send a DNS query over a pooled DoT connection.
/// On connection failure, invalidates the cached connection and retries once.
async fn query_dns_dot_pooled(
    domain: &str,
    server_idx: usize,
    tls_config: &Arc<rustls::ClientConfig>,
    pool: &DotPool,
) -> anyhow::Result<Vec<IpAddr>> {
    // Try with existing/new pooled connection.
    let result = query_on_pooled_conn(domain, server_idx, tls_config, pool).await;
    match result {
        Ok(ips) => Ok(ips),
        Err(e) => {
            // Connection may be stale — drop it and retry with a fresh one.
            trace!(server_idx, error = %e, "DoT pooled connection failed, reconnecting");
            {
                let mut guard = pool.conns[server_idx].lock().await;
                *guard = None;
            }
            query_on_pooled_conn(domain, server_idx, tls_config, pool).await
        }
    }
}

/// Execute a DNS query on a pooled connection.
async fn query_on_pooled_conn(
    domain: &str,
    server_idx: usize,
    tls_config: &Arc<rustls::ClientConfig>,
    pool: &DotPool,
) -> anyhow::Result<Vec<IpAddr>> {
    let mut guard = pool.get_or_connect(server_idx, tls_config).await?;
    let stream = guard.as_mut().ok_or_else(|| anyhow::anyhow!("no connection"))?;

    let query = build_dns_query(domain);
    let len_prefix = (query.len() as u16).to_be_bytes();
    stream.write_all(&len_prefix).await?;
    stream.write_all(&query).await?;
    stream.flush().await?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(DNS_TIMEOUT, stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    if resp_len == 0 {
        anyhow::bail!("DNS response empty");
    }

    let mut resp_buf = vec![0u8; resp_len];
    tokio::time::timeout(DNS_TIMEOUT, stream.read_exact(&mut resp_buf)).await??;

    parse_dns_response(&resp_buf)
}

/// Resolve using system DNS (tokio's built-in resolver).
async fn resolve_system(domain: &str) -> anyhow::Result<Vec<IpAddr>> {
    let addr_str = format!("{}:0", domain);
    let addrs: Vec<IpAddr> = tokio::net::lookup_host(&addr_str)
        .await?
        .map(|sa| sa.ip())
        .collect();
    Ok(addrs)
}

/// Send a DNS A-record query via plain UDP to a specific server.
async fn query_dns_udp(domain: &str, server: IpAddr) -> anyhow::Result<Vec<IpAddr>> {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    let server_addr = SocketAddr::new(server, 53);

    let query = build_dns_query(domain);
    socket.send_to(&query, server_addr).await?;

    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(DNS_TIMEOUT, socket.recv(&mut buf)).await??;

    parse_dns_response(&buf[..n])
}

/// Build a DNS A-record query packet (RFC 1035 wire format).
fn build_dns_query(domain: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);

    // Header.
    let id = fastrand::u16(..);
    buf.extend_from_slice(&id.to_be_bytes());        // ID
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: standard query, RD=1
    buf.extend_from_slice(&1u16.to_be_bytes());      // QDCOUNT = 1
    buf.extend_from_slice(&0u16.to_be_bytes());      // ANCOUNT = 0
    buf.extend_from_slice(&0u16.to_be_bytes());      // NSCOUNT = 0
    buf.extend_from_slice(&0u16.to_be_bytes());      // ARCOUNT = 0

    // Question section: encode domain as labels.
    for label in domain.split('.') {
        let len = label.len().min(63);
        buf.push(len as u8);
        buf.extend_from_slice(&label.as_bytes()[..len]);
    }
    buf.push(0); // Root label.

    buf.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A (1)
    buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN (1)

    buf
}

/// Parse a DNS response and extract A record IP addresses.
fn parse_dns_response(data: &[u8]) -> anyhow::Result<Vec<IpAddr>> {
    if data.len() < 12 {
        anyhow::bail!("DNS response too short");
    }

    let flags = u16::from_be_bytes([data[2], data[3]]);
    let rcode = flags & 0x000F;
    if rcode != 0 {
        anyhow::bail!("DNS error: rcode={}", rcode);
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

    let mut pos = 12;

    // Skip questions.
    for _ in 0..qdcount {
        pos = skip_dns_name(data, pos)?;
        pos += 4; // QTYPE (2) + QCLASS (2)
    }

    // Parse answers.
    let mut ips = Vec::new();

    for _ in 0..ancount {
        if pos >= data.len() {
            break;
        }

        pos = skip_dns_name(data, pos)?;

        if pos + 10 > data.len() {
            break;
        }

        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > data.len() {
            break;
        }

        if rtype == 1 && rdlength == 4 {
            // A record.
            let ip = Ipv4Addr::new(data[pos], data[pos + 1], data[pos + 2], data[pos + 3]);
            ips.push(IpAddr::V4(ip));
        }

        pos += rdlength;
    }

    Ok(ips)
}

/// Skip a DNS name (handles labels and compression pointers).
fn skip_dns_name(data: &[u8], mut pos: usize) -> anyhow::Result<usize> {
    loop {
        if pos >= data.len() {
            anyhow::bail!("DNS name extends past end of packet");
        }

        let len = data[pos] as usize;

        if len == 0 {
            pos += 1;
            break;
        }

        if len & 0xC0 == 0xC0 {
            // Compression pointer — 2 bytes, done.
            if pos + 2 > data.len() {
                anyhow::bail!("DNS compression pointer extends past end of packet");
            }
            pos += 2;
            break;
        }

        // Regular label.
        if pos + 1 + len > data.len() {
            anyhow::bail!("DNS label extends past end of packet");
        }
        pos += 1 + len;
    }

    Ok(pos)
}

// -----------------------------------------------------------------------------
// DnsCache — TTL-based in-process cache for domain -> SocketAddr.
// -----------------------------------------------------------------------------

/// A single cache entry keyed by `(domain, port)`.
#[derive(Clone)]
struct CacheEntry {
    /// Resolved address (IPv4 preferred).
    addr: SocketAddr,
    /// Time at which this entry should be considered stale.
    expires_at: Instant,
}

/// In-process DNS cache that memoizes resolved `domain -> SocketAddr` for a
/// configurable TTL.
///
/// This sits on the proxy hot path so that every new connection to an
/// already-seen domain can skip both the system resolver (20–50 ms blocking
/// `getaddrinfo` call on cache miss) and the DoT round-trip (~50–150 ms).
///
/// On cache miss, we call [`resolve_with_fallback`] which prefers DoT
/// (encrypted, anti-poisoning) and falls back to the system resolver.
/// We store the first IPv4 address we find (or the first address of any
/// family if no IPv4 is available).
///
/// The cache is bounded by a soft size limit: when a miss would insert into
/// a full cache, we evict the oldest-expiring entry. No explicit LRU tracking
/// — the TTL-based expiry naturally keeps hot domains alive.
pub struct DnsCache {
    ttl: Duration,
    max_entries: usize,
    entries: Mutex<HashMap<(String, u16), CacheEntry>>,
}

impl DnsCache {
    /// Create a new cache with the given TTL. Default soft cap = 1024 entries.
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            max_entries: 1024,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Create a new cache with a custom entry cap.
    pub fn with_capacity(ttl: Duration, max_entries: usize) -> Self {
        Self {
            ttl,
            max_entries,
            entries: Mutex::new(HashMap::with_capacity(max_entries)),
        }
    }

    /// Resolve `domain:port` to a `SocketAddr`, using the cache when possible.
    ///
    /// Hot path (cache hit, ~µs):
    ///   1. Acquire mutex, look up `(domain, port)`, check expiry, return.
    ///
    /// Cold path (cache miss, 20–150 ms):
    ///   1. Drop the mutex.
    ///   2. Call [`resolve_with_fallback`] (DoT → UDP → system).
    ///   3. Pick IPv4-preferred address.
    ///   4. Re-acquire mutex, insert, return.
    ///
    /// The mutex is NOT held across the network call, so concurrent lookups
    /// for different domains do not serialize. Two concurrent lookups for
    /// the SAME domain may both resolve; whichever wins the re-insert race
    /// is fine — they'll produce the same answer.
    pub async fn resolve(&self, domain: &str, port: u16) -> anyhow::Result<SocketAddr> {
        let key = (domain.to_string(), port);

        // --- Cache hit fast path ---
        {
            let guard = self.entries.lock().await;
            if let Some(entry) = guard.get(&key) {
                if entry.expires_at > Instant::now() {
                    trace!(%domain, port, addr = %entry.addr, "dns_cache: hit");
                    return Ok(entry.addr);
                }
            }
        }

        // --- Cache miss: perform real resolution without holding the lock ---
        trace!(%domain, port, "dns_cache: miss, resolving");
        let ips = resolve_with_fallback(domain).await?;
        let chosen = ips
            .iter()
            .find(|ip| ip.is_ipv4())
            .copied()
            .or_else(|| ips.first().copied())
            .ok_or_else(|| anyhow::anyhow!("no IPs resolved for {}", domain))?;
        let addr = SocketAddr::new(chosen, port);

        // --- Re-acquire and insert ---
        let mut guard = self.entries.lock().await;
        if guard.len() >= self.max_entries {
            // Evict the entry with the soonest expiry (natural LRU-by-TTL).
            if let Some(victim_key) = guard
                .iter()
                .min_by_key(|(_, e)| e.expires_at)
                .map(|(k, _)| k.clone())
            {
                guard.remove(&victim_key);
            }
        }
        guard.insert(
            key,
            CacheEntry {
                addr,
                expires_at: Instant::now() + self.ttl,
            },
        );

        debug!(%domain, port, %addr, "dns_cache: resolved and cached");
        Ok(addr)
    }

    /// Return the number of entries currently cached (for tests/metrics).
    #[cfg(test)]
    async fn len(&self) -> usize {
        self.entries.lock().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_dns_query() {
        let query = build_dns_query("example.com");

        assert!(query.len() > 12);
        assert_eq!(query[4], 0);
        assert_eq!(query[5], 1); // QDCOUNT = 1

        assert_eq!(query[12], 7); // "example" length
        assert_eq!(&query[13..20], b"example");
        assert_eq!(query[20], 3); // "com" length
        assert_eq!(&query[21..24], b"com");
        assert_eq!(query[24], 0); // root label
    }

    #[test]
    fn test_parse_dns_response() {
        // Minimal DNS response with one A record for 1.2.3.4.
        let mut response = vec![
            0x00, 0x01, // ID
            0x81, 0x80, // Flags: response, RD, RA
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];

        // Question: example.com A IN
        response.extend_from_slice(&[7]);
        response.extend_from_slice(b"example");
        response.extend_from_slice(&[3]);
        response.extend_from_slice(b"com");
        response.push(0);
        response.extend_from_slice(&[0, 1]); // QTYPE=A
        response.extend_from_slice(&[0, 1]); // QCLASS=IN

        // Answer: compression pointer + A record
        response.extend_from_slice(&[0xC0, 0x0C]); // Name pointer
        response.extend_from_slice(&[0, 1]);        // TYPE = A
        response.extend_from_slice(&[0, 1]);        // CLASS = IN
        response.extend_from_slice(&[0, 0, 0, 60]); // TTL
        response.extend_from_slice(&[0, 4]);        // RDLENGTH
        response.extend_from_slice(&[1, 2, 3, 4]);  // 1.2.3.4

        let ips = parse_dns_response(&response).unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[tokio::test]
    async fn test_dns_cache_insert_and_hit() {
        // Pre-populate the cache manually so the test doesn't require network.
        let cache = DnsCache::new(Duration::from_secs(60));
        {
            let mut guard = cache.entries.lock().await;
            guard.insert(
                ("example.com".to_string(), 443),
                CacheEntry {
                    addr: "1.2.3.4:443".parse().unwrap(),
                    expires_at: Instant::now() + Duration::from_secs(60),
                },
            );
        }
        let addr = cache.resolve("example.com", 443).await.unwrap();
        assert_eq!(addr, "1.2.3.4:443".parse().unwrap());
        assert_eq!(cache.len().await, 1);
    }

    #[tokio::test]
    async fn test_dns_cache_expiry() {
        // Insert an already-expired entry. The resolver then has to be
        // called; since we can't mock it here we just verify that the
        // expired entry is NOT returned directly.
        let cache = DnsCache::new(Duration::from_millis(1));
        {
            let mut guard = cache.entries.lock().await;
            guard.insert(
                ("expired.example".to_string(), 443),
                CacheEntry {
                    addr: "9.9.9.9:443".parse().unwrap(),
                    expires_at: Instant::now() - Duration::from_secs(1), // expired
                },
            );
        }
        // The cached value is stale — resolve() must go to the network.
        // We assert that it does NOT return 9.9.9.9 (the stale entry).
        // If the network is unreachable the call errors out, which is
        // also fine — the important thing is the stale hit was not used.
        let res = cache.resolve("expired.example", 443).await;
        if let Ok(addr) = res {
            assert_ne!(addr.ip(), "9.9.9.9".parse::<IpAddr>().unwrap());
        }
    }

    #[tokio::test]
    async fn test_resolve_dot_real() {
        if std::env::var("CI").is_ok() {
            return;
        }

        let ips = resolve_secure("google.com").await.unwrap();
        assert!(!ips.is_empty(), "should resolve google.com");
        println!("google.com resolved via DoT: {:?}", ips);
    }

    #[tokio::test]
    async fn test_resolve_dot_whatsapp() {
        if std::env::var("CI").is_ok() {
            return;
        }

        let ips = resolve_secure("whatsapp.com").await.unwrap();
        assert!(!ips.is_empty(), "should resolve whatsapp.com");
        println!("whatsapp.com resolved via DoT: {:?}", ips);

        // Verify TCP connectivity to resolved IP.
        let addr = SocketAddr::new(ips[0], 443);
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(addr),
        )
        .await;
        println!("TCP to {:?}: {:?}", addr, result.is_ok() && result.unwrap().is_ok());
    }
}
