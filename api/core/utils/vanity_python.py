"""
BIP-352 Silent Payment vanity address generator.

Two backends:
1. Rust binary (fast)     — subprocess vanity binary
2. Pure Python (fallback) — loop su generate_sp_address da receive.py

CLI:
    python vanity_python.py "asche0" --threads 8
    python vanity_python.py "cafe"   --mode prefix --threads 4

API:
    from utils.vanity_python import get_sp_vanity_address
    addresses, key_material = get_sp_vanity_address("asche0")
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
import qrcode
import json
from pathlib import Path
from typing import List, Tuple, Optional
import re


# ---------------------------------------------------------------------------
# Locate binary — cerca api/bin/vanity o target/release/vanity
# ---------------------------------------------------------------------------

def _find_repo_root() -> Path:
    """Risale le directory a partire da questo file cercando la cartella vanity/."""
    candidate = Path(__file__).resolve().parent
    for _ in range(8):
        if (candidate / "vanity").is_dir():
            return candidate
        candidate = candidate.parent
    return Path(__file__).resolve().parent

_REPO_ROOT = _find_repo_root()

def _find_bin() -> Optional[Path]:
    """Cerca il binario vanity."""
    candidates = [
        Path(__file__).resolve().parent.parent.parent / "bin" / "vanity",  # api/bin/vanity su Vercel
        _REPO_ROOT / "vanity" / "target" / "release" / "vanity",           # locale
        _REPO_ROOT / "bin" / "vanity",
    ]
    for p in candidates:
        if p.exists():
            return p
    return None

def is_bech32m(s: str) -> bool:
    pattern = r'^[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+$'
    return bool(re.fullmatch(pattern, s.lower()))

# ---------------------------------------------------------------------------
# Fix sys.path per il fallback Python
# ---------------------------------------------------------------------------

def _fix_python_path():
    """Assicura che src/ sia nel sys.path per importare receive e utils."""
    candidate = Path(__file__).resolve().parent
    for _ in range(8):
        if (candidate / "receive.py").exists():
            src_dir = str(candidate)
            if src_dir not in sys.path:
                sys.path.insert(0, src_dir)
            return
        candidate = candidate.parent

def generate_qrcode(sp_address, output_file="/tmp/silent_payment_qr.png", scan_priv=None, spend_priv=None):
    if scan_priv and spend_priv:
        data = json.dumps({
            "address":    sp_address,
            "scan_priv":  scan_priv,
            "spend_priv": spend_priv,
        }, separators=(',', ':')) 
    else:
        data = sp_address

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(output_file)


# ---------------------------------------------------------------------------
# Rust binary backend
# ---------------------------------------------------------------------------

def _rust_vanity(
    pattern:     str,
    mode:        str = "contains",
    num_threads: int = 0,
    testnet:     bool = False,
) -> Tuple[List[str], dict]:
    bin_path = _find_bin()
    if bin_path is None:
        raise RuntimeError(
            "Binario vanity non trovato.\n"
            f"Cerca in: {[str(p) for p in [Path(__file__).resolve().parent.parent.parent / 'bin' / 'vanity', _REPO_ROOT / 'vanity' / 'target' / 'release' / 'vanity']]}\n"
            "Per buildare: cd api/vanity && cargo build --release"
        )

    cmd = [str(bin_path), pattern, "--mode", mode, "--threads", str(num_threads)]
    if testnet:
        cmd.append("--testnet")

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"vanity fallito (exit {result.returncode}): {result.stderr}")

    output = {}
    for line in result.stdout.splitlines():
        if ": " in line:
            key, _, value = line.partition(": ")
            output[key.strip()] = value.strip()

    try:
        address    = output["address"]
        scan_priv  = output["scan_priv"]
        spend_priv = output["spend_priv"]
    except KeyError as e:
        raise RuntimeError(f"Output inatteso dal binario vanity, campo mancante: {e}\nOutput: {result.stdout}")

    generate_qrcode(address, scan_priv=scan_priv, spend_priv=spend_priv)
    return [address], {"scan_priv_key": scan_priv, "spend_priv_key": spend_priv}


# ---------------------------------------------------------------------------
# Pure-Python fallback
# ---------------------------------------------------------------------------

def _python_vanity(
    pattern: str,
    mode:    str  = "contains",
    testnet: bool = False,
) -> Tuple[List[str], dict]:
    _fix_python_path()
    from receive import generate_sp_address

    def _matches(address: str) -> bool:
        pat  = pattern.lower()
        addr = address.lower()
        if mode == "prefix":
            sep   = addr.find("1")
            after = addr[sep + 1:] if sep != -1 else addr
            return after.startswith(pat)
        elif mode == "suffix":
            return addr.endswith(pat)
        return pat in addr

    network  = "testnet" if testnet else "mainnet"
    attempts = 0
    while True:
        addresses, key_material = generate_sp_address(network=network)
        attempts += 1
        if _matches(addresses[0]):
            print(f"[python fallback] trovato dopo {attempts} tentativi", file=sys.stderr)
            return addresses, key_material


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_sp_vanity_address(
    vanity_string: str,
    mode:          str  = "contains",
    num_threads:   int  = 0,
    testnet:       bool = False,
    force_python:  bool = False,
) -> Tuple[List[str], dict]:
    """
    Genera un indirizzo Silent Payment BIP-352 contenente vanity_string.

    Parameters
    ----------
    vanity_string : str
        Pattern da cercare nell'indirizzo.
    mode : str
        'contains' (default), 'prefix' (dopo HRP), 'suffix'.
    num_threads : int
        Thread per il backend Rust (0 = tutti i core).
    testnet : bool
        Usa HRP 'tsp' invece di 'sp'.
    force_python : bool
        Forza il fallback Python anche se il binario è disponibile.

    Returns
    -------
    (addresses, key_material)
        addresses[0] è l'indirizzo trovato.
        key_material ha 'scan_priv_key' e 'spend_priv_key' come hex.
    """
    if not is_bech32m(vanity_string):
        print("String not valid for Bech32m encoding")
        return
    
    bin_path = _find_bin()

    if bin_path is not None and not force_python:
        return _rust_vanity(vanity_string, mode, num_threads, testnet)

    print(
        "[vanity] binario non trovato — uso il fallback Python.",
        file=sys.stderr,
    )
    return _python_vanity(vanity_string, mode, testnet)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Genera un indirizzo Silent Payment BIP-352 con pattern vanity."
    )
    parser.add_argument("vanity_string", type=str)
    parser.add_argument("--mode",        choices=["contains", "prefix", "suffix"], default="contains")
    parser.add_argument("--threads",     type=int, default=0)
    parser.add_argument("--testnet",     action="store_true")
    parser.add_argument("--python-only", action="store_true")
    args = parser.parse_args()

    backend = "python" if (args.python_only or _find_bin() is None) else "rust"
    print(f"[vanity] backend: {backend}  |  bin: {_find_bin()}", file=sys.stderr)

    t0 = time.perf_counter()
    addresses, key_material = get_sp_vanity_address(
        args.vanity_string,
        mode         = args.mode,
        num_threads  = args.threads,
        testnet      = args.testnet,
        force_python = args.python_only,
    )
    elapsed = time.perf_counter() - t0

    print(f"address:    {addresses[0]}")
    print(f"scan_priv:  {key_material['scan_priv_key']}")
    print(f"spend_priv: {key_material['spend_priv_key']}")
    print(f"time:       {elapsed:.2f}s", file=sys.stderr)