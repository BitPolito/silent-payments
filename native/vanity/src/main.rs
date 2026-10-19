use std::time::{Duration, Instant};
use vanity::matcher::{Matcher, MatchMode};
use vanity::parallel::parallel_search_until;

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    if std::env::args().nth(1).as_deref() == Some("--self-test") {
        use secp256k1::{Secp256k1, SecretKey, PublicKey};
        let secp = Secp256k1::new();
        let key = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1; 32]).unwrap());
        let address = vanity::address::encode_sp_address(&key, &key, "sp", 0);
        if address.len() != 116 { return Err("Self-test failed".into()); }
        println!("vanity: ok");
        return Ok(());
    }
    let pattern = args.next().ok_or("Usage: vanity <pattern> [--mode contains|prefix|suffix] [--threads N] [--timeout SECONDS] [--testnet]")?.to_lowercase();
    if pattern.is_empty() || pattern.len() > 64 || !pattern.bytes().all(|b| b"qpzry9x8gf2tvdw0s3jn54khce6mua7l".contains(&b)) {
        return Err("Invalid bech32m pattern (1–64 symbols required)".into());
    }
    let mut threads = 0;
    let mut mode = MatchMode::Contains;
    let mut testnet = false;
    let mut timeout = 600.0;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--threads" => { threads = args.next().ok_or("Missing threads")?.parse::<usize>().map_err(|_| "Invalid threads")?; if threads > 64 { return Err("Maximum 64 threads".into()); } },
            "--mode" => mode = match args.next().as_deref() { Some("prefix") => MatchMode::Prefix, Some("suffix") => MatchMode::Suffix, Some("contains") => MatchMode::Contains, _ => return Err("Invalid mode".into()) },
            "--testnet" => testnet = true,
            "--timeout" => { timeout = args.next().ok_or("Missing timeout")?.parse::<f64>().map_err(|_| "Invalid timeout")?; },
            _ => return Err(format!("Unknown argument: {arg}")),
        }
    }
    if !timeout.is_finite() || timeout < 0.0 || timeout > 86400.0 { return Err("Invalid timeout".into()); }
    if matches!(mode, MatchMode::Prefix) && !b"gf2tvdw0".contains(&pattern.as_bytes()[0]) {
        return Err("Prefix must begin with one of gf2tvdw0 (compressed scan-key encoding)".into());
    }
    let start = Instant::now();
    let result = parallel_search_until(Matcher::new(&pattern, mode), threads, if testnet { "tsp" } else { "sp" }, 0, Some(start + Duration::from_secs_f64(timeout)));
    let Some(r) = result else { eprintln!("Vanity search timed out"); std::process::exit(2); };
    println!("address: {}", r.address);
    println!("scan_priv: {}", hex::encode(r.key_material.scan_priv));
    println!("spend_priv: {}", hex::encode(r.key_material.spend_priv));
    println!("attempts: {}", r.attempts);
    println!("time: {:.3}", start.elapsed().as_secs_f64());
    Ok(())
}

fn main() { if let Err(message) = run() { eprintln!("{message}"); std::process::exit(1); } }
