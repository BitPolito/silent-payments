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

/// Single-threaded search loop with fixed-scan-key optimisation.
///
/// Strategy:
///   1. Generate one scan keypair at thread startup  → 1 EC mul, amortised over all iterations.
///   2. Each iteration: generate only a new spend key → 1 EC mul instead of 2.
///
/// Expected speedup: ~2x vs the naive double-keygen approach.
pub fn search_loop(
    matcher: &Matcher,
    hrp:     &str,
    version: u8,
    found:   Arc<AtomicBool>,
) -> Option<VanityResult> {
    let secp: Secp256k1<All> = Secp256k1::new();

    // One scan key fixed for the lifetime of this thread's search.
    let initial   = generate_keypair(&secp);
    let scan_sk   = SecretKey::from_slice(&initial.scan_priv).unwrap();
    let scan_pub  = initial.scan_pub;

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