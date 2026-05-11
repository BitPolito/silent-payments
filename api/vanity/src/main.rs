/// Standalone CLI for vanity Silent Payment address generation.
///
/// Usage:
///   vanity <pattern> [--threads N] [--mode contains|prefix|suffix] [--testnet]
///
/// Example:
///   vanity cafe --threads 8
///   vanity dead --mode prefix

use std::time::Instant;
use vanity::matcher::{Matcher, MatchMode};
use vanity::parallel::find_vanity_address_full;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: vanity <pattern> [--threads N] [--mode contains|prefix|suffix] [--testnet]");
        std::process::exit(1);
    }

    let pattern = &args[1];
    let mut num_threads = 0usize;
    let mut mode_str    = "contains".to_string();
    let mut testnet     = false;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--threads" => {
                i += 1;
                num_threads = args[i].parse().unwrap_or(0);
            }
            "--mode" => {
                i += 1;
                mode_str = args[i].clone();
            }
            "--testnet" => { testnet = true; }
            _ => {}
        }
        i += 1;
    }

    let mode = match mode_str.as_str() {
        "prefix" => MatchMode::Prefix,
        "suffix" => MatchMode::Suffix,
        _        => MatchMode::Contains,
    };

    let hrp     = if testnet { "tsp" } else { "sp" };
    let matcher = Matcher::new(pattern, mode);

    eprintln!(
        "Searching for pattern '{}' (mode: {}, threads: {}, network: {})…",
        pattern, mode_str, if num_threads == 0 { "all".to_string() } else { num_threads.to_string() },
        hrp
    );
    eprintln!("Expected attempts (rough estimate): ~{}", matcher.expected_attempts());

    let start  = Instant::now();
    let result = find_vanity_address_full(matcher, num_threads, hrp, 0);
    let elapsed = start.elapsed();

    println!("address:    {}", result.address);
    println!("scan_priv:  {}", hex::encode(result.key_material.scan_priv));
    println!("spend_priv: {}", hex::encode(result.key_material.spend_priv));
    println!("scan_pub:   {}", result.key_material.scan_pub);
    println!("spend_pub:  {}", result.key_material.spend_pub);
    println!("attempts:   {}", result.attempts);
    println!("time:       {:.2?}", elapsed);
    println!(
        "rate:       {:.0} addr/s",
        result.attempts as f64 / elapsed.as_secs_f64()
    );
}