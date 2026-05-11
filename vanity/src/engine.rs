use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use secp256k1::{Secp256k1, All, SecretKey};

use crate::generator::{generate_keypair, generate_spend_only, KeyMaterial};
use crate::address::encode_sp_address;
use crate::matcher::Matcher;

#[derive(Debug, Clone)]
pub struct VanityResult {
    pub address:      String,
    pub key_material: KeyMaterial,
    pub attempts:     u64,
}

pub fn search_loop(
    matcher: &Matcher,
    hrp:     &str,
    version: u8,
    found:   Arc<AtomicBool>,
) -> Option<VanityResult> {
    let secp: Secp256k1<All> = Secp256k1::new();

    let scan_km  = generate_keypair(&secp);
    let scan_sk  = SecretKey::from_slice(&scan_km.scan_priv)
        .expect("generate_keypair always produces a valid secret key");
    let scan_pub = scan_km.scan_pub;

    let mut attempts: u64 = 0;

    loop {
        if found.load(Ordering::Relaxed) {
            return None;
        }

        attempts += 1;
        let km      = generate_spend_only(&secp, &scan_sk, &scan_pub);
        let address = encode_sp_address(&km.scan_pub, &km.spend_pub, hrp, version);

        if matcher.matches(&address) {
            found.store(true, Ordering::Relaxed);
            return Some(VanityResult { address, key_material: km, attempts });
        }
    }
}