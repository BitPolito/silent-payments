/// Parallel vanity search using rayon.
///
/// Spawns `num_threads` worker threads (or `rayon::current_num_threads()` when
/// `num_threads == 0`).  Each thread runs its own `engine::search_loop`.  The
/// first thread to find a match signals the others via an `AtomicBool`, then
/// the winning result is returned to the caller.

use std::sync::{Arc, Mutex, atomic::AtomicBool};
use rayon::prelude::*;

use crate::engine::{search_loop, VanityResult};
use crate::matcher::Matcher;

/// Search for a vanity Silent Payment address using all available CPU cores.
///
/// * `pattern`     – vanity string (e.g. `"cafe"`)
/// * `num_threads` – worker threads; 0 → use all logical CPUs
/// * `hrp`         – `"sp"` (mainnet) or `"tsp"` (testnet)
/// * `version`     – SP version (0)
///
/// Blocks until a match is found and returns the result.
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

    let found   = Arc::new(AtomicBool::new(false));
    let result  = Arc::new(Mutex::new(None::<VanityResult>));

    // We need `hrp` and `matcher` to be shareable across threads.
    let hrp_owned = hrp.to_owned();

    (0..n_threads).into_par_iter().for_each(|_| {
        if let Some(r) = search_loop(
            &matcher,
            &hrp_owned,
            version,
            Arc::clone(&found),
        ) {
            let mut guard = result.lock().unwrap();
            *guard = Some(r);
        }
    });

    // By the time rayon's par_iter returns, exactly one thread has written the result.
    Arc::try_unwrap(result)
        .expect("no other owners after rayon join")
        .into_inner()
        .unwrap()
        .expect("parallel_search: rayon returned but no result was written")
}

/// Convenience wrapper: search with default thread count and mainnet HRP.
pub fn find_vanity_address(pattern: &str, num_threads: usize) -> VanityResult {
    let matcher = Matcher::new(pattern, crate::matcher::MatchMode::Contains);
    parallel_search(matcher, num_threads, "sp", 0)
}

/// Full-control wrapper used by FFI and CLI.
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
        // "q" appears in virtually every SP address — should be instant.
        let result = find_vanity_address("q", 2);
        assert!(result.address.contains('q'));
        println!(
            "Found '{}' in {} attempts across threads",
            result.address,
            result.attempts
        );
    }
}