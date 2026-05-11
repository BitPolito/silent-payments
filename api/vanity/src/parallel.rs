/// Parallel vanity search using rayon.

use std::sync::{Arc, Mutex, atomic::AtomicBool};
use rayon::prelude::*;

use crate::engine::{search_loop, VanityResult};
use crate::matcher::Matcher;

/// Search for a vanity Silent Payment address using all available CPU cores.
///
/// * `matcher`     – pre-built [`Matcher`] describing the desired pattern
/// * `num_threads` – worker threads; 0 → use all logical CPUs
/// * `hrp`         – `"sp"` (mainnet) or `"tsp"` (testnet)
/// * `version`     – SP version (currently always 0)

pub fn parallel_search(
    matcher:     Matcher,
    num_threads: usize,
    hrp:         &str,
    version:     u8,
) -> VanityResult {
    let n_threads = if num_threads == 0 {
        rayon::current_num_threads()
    } else {
        num_threads
    };

    let found  = Arc::new(AtomicBool::new(false));
    let result = Arc::new(Mutex::new(None::<VanityResult>));

    let hrp_owned = hrp.to_owned();

    (0..n_threads).into_par_iter().for_each(|_| {
        if let Some(r) = search_loop(
            &matcher,
            &hrp_owned,
            version,
            Arc::clone(&found),
        ) {
            let mut guard = result.lock().unwrap();
            if guard.is_none() {
                *guard = Some(r);
            }
        }
    });

    Arc::try_unwrap(result)
        .expect("no other owners after rayon join")
        .into_inner()
        .unwrap()
        .expect("parallel_search: rayon returned but no result was written")
}

pub fn find_vanity_address(pattern: &str, num_threads: usize) -> VanityResult {
    let matcher = Matcher::new(pattern, crate::matcher::MatchMode::Contains);
    parallel_search(matcher, num_threads, "sp", 0)
}

pub fn find_vanity_address_full(
    matcher:     Matcher,
    num_threads: usize,
    hrp:         &str,
    version:     u8,
) -> VanityResult {
    parallel_search(matcher, num_threads, hrp, version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_short_pattern() {
        let result = find_vanity_address("q", 2);
        assert!(result.address.contains('q'));
        println!(
            "Found '{}' in {} attempts across threads",
            result.address,
            result.attempts
        );
    }

    #[test]
    fn concurrent_searches_use_distinct_scan_keys() {
        use std::collections::HashSet;

        let results: Vec<_> = (0..4)
            .map(|_| find_vanity_address("q", 1))
            .collect();

        let scan_keys: HashSet<_> = results
            .iter()
            .map(|r| r.key_material.scan_priv)
            .collect();

        assert_eq!(
            scan_keys.len(),
            results.len(),
            "every search must produce a unique scan key"
        );
    }
}