/// Criterion benchmarks for the vanity Silent Payment library.
///
/// Run with:
///   cargo bench
///   cargo bench -- address_encoding   # single group
///   cargo bench --bench vanity_bench  # this file only

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use vanity::address::encode_sp_address;
use vanity::engine::search_loop;
use vanity::generator::generate_keypair;
use vanity::matcher::{MatchMode, Matcher};
use vanity::parallel::find_vanity_address_full;

use secp256k1::Secp256k1;
use std::sync::{Arc, atomic::AtomicBool};

// ── 1. Address encoding ──────────────────────────────────────────────────────

fn bench_address_encoding(c: &mut Criterion) {
    let secp      = Secp256k1::new();
    let km        = generate_keypair(&secp);

    c.bench_function("encode_sp_address", |b| {
        b.iter(|| {
            encode_sp_address(
                black_box(&km.scan_pub),
                black_box(&km.spend_pub),
                "sp",
                0,
            )
        })
    });
}

// ── 2. Keypair generation ────────────────────────────────────────────────────

fn bench_keygen(c: &mut Criterion) {
    let secp = Secp256k1::new();

    c.bench_function("generate_keypair", |b| {
        b.iter(|| generate_keypair(black_box(&secp)))
    });
}

// ── 3. Matcher ───────────────────────────────────────────────────────────────

fn bench_matcher(c: &mut Criterion) {
    let address = "sp1qqgptxnkpme9rycjsq7gq5rnsrvpq67j6yqmk9rw6v8rkwrpvg3xsqqnfzr7";

    let mut group = c.benchmark_group("matcher");

    for (label, mode) in [
        ("contains", MatchMode::Contains),
        ("prefix",   MatchMode::Prefix),
        ("suffix",   MatchMode::Suffix),
    ] {
        let m = Matcher::new("qqq", mode);
        group.bench_with_input(
            BenchmarkId::new(label, "qqq"),
            &m,
            |b, matcher| b.iter(|| matcher.matches(black_box(address))),
        );
    }

    group.finish();
}

// ── 4. Single-threaded search loop (N iterations) ────────────────────────────
//
// We don't let the loop actually *find* a match — we just want to measure how
// many address candidates per second the engine can generate.
//
// Trick: use a pattern that is highly unlikely to match ("zzzzzz" = ~10^9
// expected attempts) and time a fixed number of address generations by
// wrapping `search_loop` in a timeout-style AtomicBool we flip after N steps.
// Instead of patching engine.rs we benchmark the two hot sub-operations
// (keygen + encode) directly at the rate the engine calls them.

fn bench_engine_throughput(c: &mut Criterion) {
    let secp = Secp256k1::new();

    // Measure the cost of one full "candidate" (spend keygen + encode).
    use secp256k1::SecretKey;
    use vanity::generator::generate_spend_only;

    let scan_km  = generate_keypair(&secp);
    let scan_sk  = SecretKey::from_slice(&scan_km.scan_priv).unwrap();
    let scan_pub = scan_km.scan_pub;

    let mut group = c.benchmark_group("engine");
    group.throughput(Throughput::Elements(1));

    group.bench_function("one_candidate", |b| {
        b.iter(|| {
            let km = generate_spend_only(black_box(&secp), &scan_sk, &scan_pub);
            encode_sp_address(&km.scan_pub, &km.spend_pub, "sp", 0)
        })
    });

    group.finish();
}

// ── 5. search_loop: measure real found-in-N rate for a trivial pattern ───────

fn bench_search_loop_trivial(c: &mut Criterion) {
    // 'q' appears in virtually every SP address (bech32 charset is biased).
    let matcher = Matcher::new("q", MatchMode::Contains);

    c.bench_function("search_loop/pattern_q", |b| {
        b.iter(|| {
            let found = Arc::new(AtomicBool::new(false));
            search_loop(black_box(&matcher), "sp", 0, found)
        })
    });
}

// ── 6. Parallel search: 1-char pattern, varying thread counts ───────────────

fn bench_parallel_threads(c: &mut Criterion) {
    let mut group = c.benchmark_group("parallel_search");
    // Keep the pattern trivial so wall time stays short even in CI.
    let pattern = "q";

    for threads in [1usize, 2, 4] {
        group.bench_with_input(
            BenchmarkId::new("threads", threads),
            &threads,
            |b, &t| {
                b.iter(|| {
                    let matcher = Matcher::new(pattern, MatchMode::Contains);
                    find_vanity_address_full(matcher, t, "sp", 0)
                })
            },
        );
    }

    group.finish();
}

// ── Criterion entry points ───────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_address_encoding,
    bench_keygen,
    bench_matcher,
    bench_engine_throughput,
    bench_search_loop_trivial,
    bench_parallel_threads,
);
criterion_main!(benches);