use std::time::Instant;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use secp256k1::{Secp256k1, All, SecretKey};

use crate::generator::{generate_keypair_with_rng, generate_spend_only_with_rng, KeyMaterial};
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
    search_loop_until(matcher, hrp, version, found, None)
}

pub fn search_loop_until(
    matcher: &Matcher, hrp: &str, version: u8,
    found: Arc<AtomicBool>, deadline: Option<Instant>,
) -> Option<VanityResult> {
    search_with_rng(matcher, hrp, version, found, deadline, &mut rand::thread_rng())
}

fn search_with_rng(
    matcher: &Matcher, hrp: &str, version: u8, found: Arc<AtomicBool>,
    deadline: Option<Instant>, rng: &mut impl rand::RngCore,
) -> Option<VanityResult> {
    let secp: Secp256k1<All> = Secp256k1::new();

    let scan_km  = generate_keypair_with_rng(&secp, rng);
    let scan_sk  = SecretKey::from_slice(&scan_km.scan_priv)
        .expect("generate_keypair always produces a valid secret key");
    let scan_pub = scan_km.scan_pub;

    let mut attempts: u64 = 0;

    loop {
        if found.load(Ordering::Relaxed) || deadline.is_some_and(|end| Instant::now() >= end) {
            return None;
        }

        attempts += 1;
        let km = if matcher.is_prefix() { generate_keypair_with_rng(&secp, rng) }
                 else { generate_spend_only_with_rng(&secp, &scan_sk, &scan_pub, rng) };
        let address = encode_sp_address(&km.scan_pub, &km.spend_pub, hrp, version);

        if matcher.matches(&address) {
            found.store(true, Ordering::Relaxed);
            return Some(VanityResult { address, key_material: km, attempts });
        }
    }
}

#[cfg(test)]
mod regression {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};
    use crate::matcher::MatchMode;
    use std::time::Duration;

    #[test]
    fn seeded_prefix_search_rotates_the_scan_key() {
        let secp = Secp256k1::new();
        let mut replay = StdRng::seed_from_u64(352);
        let initial = generate_keypair_with_rng(&secp, &mut replay);
        let initial_address = encode_sp_address(&initial.scan_pub, &initial.spend_pub, "sp", 0);
        let expected = (0..100).find_map(|_| {
            let next = generate_keypair_with_rng(&secp, &mut replay);
            let address = encode_sp_address(&next.scan_pub, &next.spend_pub, "sp", 0);
            if address.as_bytes()[5] != initial_address.as_bytes()[5] { Some(address) } else { None }
        }).unwrap();
        let matcher = Matcher::new(&expected[5..6], MatchMode::Prefix);
        let result = search_with_rng(&matcher, "sp", 0, Arc::new(AtomicBool::new(false)),
            Some(Instant::now() + Duration::from_secs(5)), &mut StdRng::seed_from_u64(352)).unwrap();
        assert_eq!(result.address, expected);
    }
}
