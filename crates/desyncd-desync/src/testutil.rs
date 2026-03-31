//! Test utilities shared across desync technique tests.

/// Build a minimal TLS ClientHello with the given SNI for testing.
pub fn build_test_client_hello(sni: &str) -> Vec<u8> {
    let sni_bytes = sni.as_bytes();
    let sni_ext_data_len = 2 + 1 + 2 + sni_bytes.len();
    let sni_ext_len = 4 + sni_ext_data_len;
    let extensions_len = sni_ext_len;
    let ch_body_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extensions_len;
    let hs_len = 4 + ch_body_len;

    let mut buf = Vec::new();
    buf.push(0x16);
    buf.extend_from_slice(&0x0301u16.to_be_bytes());
    buf.extend_from_slice(&(hs_len as u16).to_be_bytes());
    buf.push(0x01);
    buf.push(0x00);
    buf.extend_from_slice(&(ch_body_len as u16).to_be_bytes());
    buf.extend_from_slice(&0x0303u16.to_be_bytes());
    buf.extend_from_slice(&[0u8; 32]);
    buf.push(0);
    buf.extend_from_slice(&2u16.to_be_bytes());
    buf.extend_from_slice(&0x1301u16.to_be_bytes());
    buf.push(1);
    buf.push(0);
    buf.extend_from_slice(&(extensions_len as u16).to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes()); // SNI ext type
    buf.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
    let sni_list_len = 1 + 2 + sni_bytes.len();
    buf.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
    buf.push(0x00);
    buf.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(sni_bytes);
    buf
}
