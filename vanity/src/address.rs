/// BIP-352 Silent Payment address encoding.
///
/// Correct length: 2 (hrp) + 1 (sep) + 1 (ver) + ceil(66*8/5) (data) + 6 (checksum)
///               = 2 + 1 + 1 + 106 + 6 = 116 characters.

use secp256k1::PublicKey;

pub fn encode_sp_address(
    scan_pub:  &PublicKey,
    spend_pub: &PublicKey,
    hrp_str:   &str,
    version:   u8,
) -> String {
    let mut witness = Vec::with_capacity(66);
    witness.extend_from_slice(&scan_pub.serialize());
    witness.extend_from_slice(&spend_pub.serialize());
    let data_5bit = convert_bits_8to5(&witness);
    bech32_encode_segwit(hrp_str, version, &data_5bit)
}

fn bech32_encode_segwit(hrp: &str, version: u8, data_5bit: &[u8]) -> String {
    const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let mut values: Vec<u8> = Vec::with_capacity(1 + data_5bit.len());
    values.push(version & 0x1f);
    values.extend_from_slice(data_5bit);
    let checksum = bech32m_checksum(hrp, &values);
    let mut result = String::with_capacity(hrp.len() + 1 + values.len() + 6);
    result.push_str(hrp);
    result.push('1');
    for &v in &values {
        result.push(CHARSET[v as usize] as char);
    }
    for i in 0..6 {
        result.push(CHARSET[((checksum >> (5 * (5 - i))) & 0x1f) as usize] as char);
    }
    result
}

fn convert_bits_8to5(data: &[u8]) -> Vec<u8> {
    let mut acc:  u32 = 0;
    let mut bits: u32 = 0;
    let mut out        = Vec::with_capacity((data.len() * 8 + 4) / 5);
    for &byte in data {
        acc  = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(((acc >> bits) & 0x1f) as u8);
        }
    }
    if bits > 0 {
        out.push(((acc << (5 - bits)) & 0x1f) as u8);
    }
    out
}

fn bech32m_checksum(hrp: &str, data: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &b in hrp.as_bytes() { chk = polymod_step(chk) ^ (u32::from(b) >> 5); }
    chk = polymod_step(chk);
    for &b in hrp.as_bytes() { chk = polymod_step(chk) ^ (u32::from(b) & 0x1f); }
    chk = polymod_step(chk);
    for &v in data { chk = polymod_step(chk) ^ u32::from(v); }
    for _ in 0..6 { chk = polymod_step(chk); }
    chk ^ 0x2bc830a3
}

#[inline]
fn polymod_step(pre: u32) -> u32 {
    let b = pre >> 25;
    (pre & 0x1ff_ffff) << 5
        ^ (if (b >> 0) & 1 != 0 { 0x3b6a57b2 } else { 0 })
        ^ (if (b >> 1) & 1 != 0 { 0x26508e6d } else { 0 })
        ^ (if (b >> 2) & 1 != 0 { 0x1ea119fa } else { 0 })
        ^ (if (b >> 3) & 1 != 0 { 0x3d4233dd } else { 0 })
        ^ (if (b >> 4) & 1 != 0 { 0x2a1462b3 } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Secp256k1, SecretKey};

    #[test]
    fn test_address_length() {
        let secp = Secp256k1::new();
        let scan_pub  = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1u8;32]).unwrap());
        let spend_pub = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[2u8;32]).unwrap());
        let addr = encode_sp_address(&scan_pub, &spend_pub, "sp", 0);
        println!("address ({} chars): {}", addr.len(), addr);
        assert!(addr.starts_with("sp1q"), "must start with sp1q");
        assert_eq!(addr.len(), 116, "SP v0 mainnet must be 116 chars");
    }

    #[test]
    fn test_address_charset() {
        let secp = Secp256k1::new();
        let scan_pub  = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[5u8;32]).unwrap());
        let spend_pub = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[6u8;32]).unwrap());
        let addr = encode_sp_address(&scan_pub, &spend_pub, "sp", 0);
        let valid = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        for c in addr[3..].chars() {
            assert!(valid.contains(c), "invalid bech32 char: '{}'", c);
        }
    }
}