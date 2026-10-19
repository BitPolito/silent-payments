/// Integration and unit tests for the vanity Silent Payment library.
///
/// Run with:
///   cargo test
///   cargo test -- --nocapture          # show println! output
///   cargo test address                 # filter by name

#[cfg(test)]
mod address_tests {
    use vanity::address::encode_sp_address;
    use secp256k1::{Secp256k1, SecretKey, PublicKey};

    fn pubkey(secp: &Secp256k1<secp256k1::All>, byte: u8) -> PublicKey {
        PublicKey::from_secret_key(secp, &SecretKey::from_slice(&[byte; 32]).unwrap())
    }

    #[test]
    fn mainnet_starts_with_sp1q() {
        let secp = Secp256k1::new();
        let addr = encode_sp_address(&pubkey(&secp, 1), &pubkey(&secp, 2), "sp", 0);
        assert!(addr.starts_with("sp1q"), "expected sp1q prefix, got: {addr}");
    }

    #[test]
    fn testnet_starts_with_tsp1q() {
        let secp = Secp256k1::new();
        let addr = encode_sp_address(&pubkey(&secp, 3), &pubkey(&secp, 4), "tsp", 0);
        assert!(addr.starts_with("tsp1q"), "expected tsp1q prefix, got: {addr}");
    }

    #[test]
    fn mainnet_length_is_116() {
        let secp = Secp256k1::new();
        let addr = encode_sp_address(&pubkey(&secp, 1), &pubkey(&secp, 2), "sp", 0);
        assert_eq!(addr.len(), 116, "SP v0 mainnet must be 116 chars, got {}", addr.len());
    }

    #[test]
    fn only_bech32_charset_after_hrp() {
        let secp  = Secp256k1::new();
        let addr  = encode_sp_address(&pubkey(&secp, 5), &pubkey(&secp, 6), "sp", 0);
        let valid = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        // skip "sp1" prefix (3 chars)
        for c in addr[3..].chars() {
            assert!(valid.contains(c), "invalid bech32 char '{c}' in address: {addr}");
        }
    }

    #[test]
    fn different_keys_produce_different_addresses() {
        let secp  = Secp256k1::new();
        let addr1 = encode_sp_address(&pubkey(&secp, 1), &pubkey(&secp, 2), "sp", 0);
        let addr2 = encode_sp_address(&pubkey(&secp, 3), &pubkey(&secp, 4), "sp", 0);
        assert_ne!(addr1, addr2);
    }

    #[test]
    fn same_keys_always_same_address() {
        let secp  = Secp256k1::new();
        let addr1 = encode_sp_address(&pubkey(&secp, 7), &pubkey(&secp, 8), "sp", 0);
        let addr2 = encode_sp_address(&pubkey(&secp, 7), &pubkey(&secp, 8), "sp", 0);
        assert_eq!(addr1, addr2, "address encoding must be deterministic");
    }
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod matcher_tests {
    use vanity::matcher::{MatchMode, Matcher};

    #[test]
    fn contains_match() {
        let m = Matcher::new("cafe", MatchMode::Contains);
        assert!(m.matches("sp1qqqcafexyz"));
        assert!(!m.matches("sp1qqqxyzdef"));
    }

    #[test]
    fn contains_skips_fixed_sp1qq() {
        let m = Matcher::new("sp1qq", MatchMode::Contains);
        assert!(!m.matches("sp1qqqcafexyz"));
        let m2 = Matcher::new("cafe", MatchMode::Contains);
        assert!(m2.matches("sp1qqqcafexyz"));
    }

    #[test]
    fn contains_case_insensitive() {
        let m = Matcher::new("CAFE", MatchMode::Contains);
        assert!(m.matches("sp1qqqcafexyz"), "pattern must be lowercased");
    }

    #[test]
    fn prefix_skips_fixed_sp1qq() {
        let m = Matcher::new("abc", MatchMode::Prefix);
        assert!(m.matches("sp1qqabcxyz"));
        assert!(!m.matches("sp1qqqabc"));
    }

    #[test]
    fn prefix_works_for_testnet() {
        let m = Matcher::new("qqq", MatchMode::Prefix);
        // "tsp1" + "qqqabc"
        assert!(m.matches("tsp1qqqqqabc"));
    }

    #[test]
    fn suffix_match() {
        let m = Matcher::new("dead", MatchMode::Suffix);
        assert!(m.matches("sp1qqqbeef00dead"));
        assert!(!m.matches("sp1deadqqqbeef00"));
    }

    #[test]
    fn expected_attempts_grows_with_pattern_length() {
        let m1 = Matcher::new("a",  MatchMode::Contains);
        let m2 = Matcher::new("ab", MatchMode::Contains);
        assert!(m2.expected_attempts() > m1.expected_attempts());
    }

    #[test]
    fn empty_pattern_always_matches() {
        let m = Matcher::new("", MatchMode::Contains);
        assert!(m.matches("sp1anything"));
    }
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod generator_tests {
    use vanity::generator::{generate_keypair, generate_spend_only};
    use secp256k1::{Secp256k1, SecretKey};

    #[test]
    fn keypair_scan_and_spend_differ() {
        let secp = Secp256k1::new();
        let km   = generate_keypair(&secp);
        assert_ne!(km.scan_priv, km.spend_priv, "scan and spend private keys must differ");
        assert_ne!(km.scan_pub,  km.spend_pub,  "scan and spend public keys must differ");
    }

    #[test]
    fn spend_only_preserves_scan_key() {
        let secp     = Secp256k1::new();
        let base     = generate_keypair(&secp);
        let scan_sk  = SecretKey::from_slice(&base.scan_priv).unwrap();
        let spend_km = generate_spend_only(&secp, &scan_sk, &base.scan_pub);

        assert_eq!(spend_km.scan_priv, base.scan_priv, "scan_priv must be preserved");
        assert_eq!(spend_km.scan_pub,  base.scan_pub,  "scan_pub must be preserved");
    }

    #[test]
    fn spend_only_generates_new_spend_key() {
        let secp    = Secp256k1::new();
        let base    = generate_keypair(&secp);
        let scan_sk = SecretKey::from_slice(&base.scan_priv).unwrap();
        let km1     = generate_spend_only(&secp, &scan_sk, &base.scan_pub);
        let km2     = generate_spend_only(&secp, &scan_sk, &base.scan_pub);
        // Statistically impossible to collide
        assert_ne!(km1.spend_priv, km2.spend_priv);
    }

    #[test]
    fn public_keys_derived_from_private() {
        let secp    = Secp256k1::new();
        let km      = generate_keypair(&secp);
        let derived = secp256k1::PublicKey::from_secret_key(
            &secp,
            &SecretKey::from_slice(&km.scan_priv).unwrap(),
        );
        assert_eq!(derived, km.scan_pub, "scan_pub must match derived pubkey");
    }
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod engine_tests {
    use vanity::engine::search_loop;
    use vanity::matcher::{MatchMode, Matcher};
    use std::sync::{Arc, atomic::AtomicBool};

    #[test]
    fn search_loop_finds_trivial_pattern() {
        // 'q' appears in almost every address
        let matcher = Matcher::new("q", MatchMode::Contains);
        let found   = Arc::new(AtomicBool::new(false));
        let result  = search_loop(&matcher, "sp", 0, found);
        assert!(result.is_some());
        let r = result.unwrap();
        assert!(r.address.contains('q'));
        assert!(r.attempts >= 1);
    }

    #[test]
    fn search_loop_stops_when_found_is_set() {
        // Pre-set the flag — search_loop must return None immediately
        let matcher = Matcher::new("q", MatchMode::Contains);
        let found   = Arc::new(AtomicBool::new(true));   // already true!
        let result  = search_loop(&matcher, "sp", 0, found);
        assert!(result.is_none(), "should return None when flag is pre-set");
    }

    #[test]
    fn result_address_matches_pattern() {
        let pattern = "qq";
        let matcher = Matcher::new(pattern, MatchMode::Contains);
        let found   = Arc::new(AtomicBool::new(false));
        let result  = search_loop(&matcher, "sp", 0, found).unwrap();
        assert!(
            result.address.contains(pattern),
            "returned address '{}' must contain '{}'",
            result.address, pattern
        );
    }

    #[test]
    fn result_keys_consistent() {
        use secp256k1::{Secp256k1, SecretKey};
        let matcher = Matcher::new("q", MatchMode::Contains);
        let found   = Arc::new(AtomicBool::new(false));
        let result  = search_loop(&matcher, "sp", 0, found).unwrap();

        let secp    = Secp256k1::new();
        let derived = secp256k1::PublicKey::from_secret_key(
            &secp,
            &SecretKey::from_slice(&result.key_material.spend_priv).unwrap(),
        );
        assert_eq!(
            derived, result.key_material.spend_pub,
            "spend_pub must match spend_priv"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod parallel_tests {
    use vanity::matcher::{MatchMode, Matcher};
    use vanity::parallel::find_vanity_address_full;

    #[test]
    fn finds_single_char_pattern_multithreaded() {
        let matcher = Matcher::new("q", MatchMode::Contains);
        let result  = find_vanity_address_full(matcher, 2, "sp", 0);
        assert!(result.address.contains('q'));
        assert!(result.attempts >= 1);
    }

    #[test]
    fn finds_pattern_on_testnet() {
        let matcher = Matcher::new("q", MatchMode::Contains);
        let result  = find_vanity_address_full(matcher, 1, "tsp", 0);
        assert!(result.address.starts_with("tsp1"), "must be testnet address");
        assert!(result.address.contains('q'));
    }

    #[test]
    fn result_address_matches_prefix_mode() {
        // After "sp1" the address must start with "qq"
        let matcher = Matcher::new("g", MatchMode::Prefix);
        let result  = find_vanity_address_full(matcher, 2, "sp", 0);
        let after   = &result.address["sp1qq".len()..];
        assert!(
            after.starts_with("g"),
            "address after HRP separator must start with 'qq': {}",
            result.address
        );
    }

    #[test]
    fn result_address_matches_suffix_mode() {
        let matcher = Matcher::new("qq", MatchMode::Suffix);
        let result  = find_vanity_address_full(matcher, 2, "sp", 0);
        assert!(
            result.address.ends_with("qq"),
            "address must end with 'qq': {}",
            result.address
        );
    }

    #[test]
    fn single_thread_gives_valid_result() {
        let matcher = Matcher::new("q", MatchMode::Contains);
        let result  = find_vanity_address_full(matcher, 1, "sp", 0);
        assert!(result.address.starts_with("sp1q"));
        assert_eq!(result.address.len(), 116);
    }
}
#[test]
fn expired_deadline_stops_workers() {
    use std::time::Instant;
    use vanity::{matcher::{Matcher, MatchMode}, parallel::parallel_search_until};
    assert!(parallel_search_until(Matcher::new("qqqqqq", MatchMode::Contains), 2, "sp", 0, Some(Instant::now())).is_none());
}

#[test]
fn prefix_search_makes_progress_on_both_networks() {
    use std::time::{Instant, Duration};
    use vanity::{matcher::{Matcher, MatchMode}, parallel::parallel_search_until};
    for hrp in ["sp", "tsp"] {
        let result = parallel_search_until(Matcher::new("g", MatchMode::Prefix), 1, hrp, 0,
            Some(Instant::now() + Duration::from_secs(5))).expect("one-symbol prefix must be reachable");
        assert!(result.address.starts_with(&format!("{hrp}1qqg")));
    }
}

#[test]
fn cli_rejects_missing_arguments_and_impossible_prefixes() {
    for args in [vec!["q", "--threads"], vec!["q", "--mode", "prefix"], vec!["!"], vec!["q", "--threads", "65"]] {
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_vanity")).args(args).output().unwrap();
        assert_eq!(result.status.code(), Some(1));
    }
}

#[test]
fn cli_deadline_exit_code() {
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_vanity"))
        .args(["qqqqqqqqqq", "--timeout", "0"]).output().unwrap();
    assert_eq!(result.status.code(), Some(2));
}

#[test]
fn encoding_matches_shared_python_and_bip_fixtures() {
    use secp256k1::{Secp256k1, SecretKey, PublicKey};
    let cases: serde_json::Value = serde_json::from_str(include_str!("../../core/test/key_vectors.json")).unwrap();
    let secp = Secp256k1::new();
    for case in cases.as_array().unwrap() {
        let scan = SecretKey::from_slice(&hex::decode(case["scan_priv_key"].as_str().unwrap()).unwrap()).unwrap();
        let spend = SecretKey::from_slice(&hex::decode(case["spend_priv_key"].as_str().unwrap()).unwrap()).unwrap();
        let hrp = if case["network"] == "testnet" { "tsp" } else { "sp" };
        let address = vanity::address::encode_sp_address(&PublicKey::from_secret_key(&secp, &scan), &PublicKey::from_secret_key(&secp, &spend), hrp, 0);
        assert_eq!(address, case["address"].as_str().unwrap());
    }
}
