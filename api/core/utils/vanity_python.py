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
import base64
import io
import os
import subprocess
import sys
import time
import qrcode
import json
from pathlib import Path
from typing import List, Tuple, Optional, Dict, Any
import re
from functools import lru_cache


# ---------------------------------------------------------------------------
# Locate binary — cerca api/bin/vanity o target/release/vanity
# ---------------------------------------------------------------------------

def _find_repo_root() -> Path:
    # The runtime bundle deliberately omits the Rust source/target directory.
    return Path(__file__).resolve().parents[2]

_REPO_ROOT = _find_repo_root()

def _find_bin() -> Optional[Path]:
    """Cerca il binario vanity."""
    bundled = _REPO_ROOT / 'bin' / 'vanity'
    candidates = [bundled] if is_vercel_runtime() else [
        _REPO_ROOT / 'vanity' / 'target' / 'release' / 'vanity',
        _REPO_ROOT / 'vanity' / 'target' / 'debug' / 'vanity', bundled,
    ]
    executable = [p for p in candidates if p.is_file() and os.access(p, os.X_OK)]
    for path in sorted(executable, key=lambda p: p.stat().st_mtime, reverse=True):
        if _binary_usable(str(path), path.stat().st_mtime_ns):
            return path
    return None


@lru_cache(maxsize=8)
def _binary_usable(path, modified):
    try:
        result = subprocess.run([path, '--self-test'], capture_output=True, timeout=2, text=True)
        return result.returncode == 0 and result.stdout.strip() == 'vanity: ok'
    except (OSError, subprocess.SubprocessError):
        return False


def is_vercel_runtime() -> bool:
    """True when running on Vercel serverless (limited CPU time)."""
    return bool(os.environ.get('VERCEL'))


VALID_VANITY_MODES = frozenset({'contains', 'prefix', 'suffix'})

def _bounded_env(name, default, cap):
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        value = default
    return max(1, min(value, cap))


def vanity_runtime_limits() -> Dict[str, Any]:
    deployed = is_vercel_runtime()
    return {
        'environment': 'vercel' if deployed else 'local',
        'max_pattern_len': _bounded_env('VANITY_MAX_PATTERN_LEN', 5, 64),
        'timeout_sec': _bounded_env('VANITY_TIMEOUT_SEC', 50 if deployed else 600, 50 if deployed else 86400),
        'max_threads': _bounded_env('VANITY_MAX_THREADS', 2 if deployed else 4, 2 if deployed else 64),
    }


def normalize_vanity_mode(mode: str) -> str:
    if not isinstance(mode, str):
        raise ValueError('Invalid vanity mode')
    m = mode.lower().strip()
    if m not in VALID_VANITY_MODES:
        raise ValueError('Invalid vanity mode')
    return m


def effective_vanity_threads(requested: int) -> int:
    """Map client threads (0 = auto) to a bounded worker count."""
    cap = max(1, vanity_runtime_limits()['max_threads'])
    try:
        n = int(requested)
    except (TypeError, ValueError):
        n = 0
    if n <= 0:
        return cap
    return min(n, cap)


def max_vanity_pattern_len() -> int:
    return vanity_runtime_limits()['max_pattern_len']


def vanity_search_timeout_sec() -> int:
    return vanity_runtime_limits()['timeout_sec']


def is_bech32m(s: str) -> bool:
    pattern = r'^[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+$'
    return bool(re.fullmatch(pattern, s.lower()))


def vanity_pattern_error(s: str, max_len: Optional[int] = None) -> Optional[str]:
    """Return an error message, or None if the pattern is valid."""
    limit = max_len if max_len is not None else max_vanity_pattern_len()
    if not s:
        return 'Pattern is required'
    if not is_bech32m(s):
        return 'Invalid vanity pattern (bech32m characters only)'
    if len(s) > limit:
        return f'Pattern too long (max {limit} on this server)'
    return None

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

def _qr_image(sp_address: str):
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(sp_address)
    qr.make(fit=True)
    return qr.make_image(fill_color="black", back_color="white")


def qr_png_base64(sp_address: str) -> str:
    """PNG QR encoding the public silent payment address only (safe to share)."""
    buf = io.BytesIO()
    _qr_image(sp_address).save(buf, format='PNG')
    return base64.b64encode(buf.getvalue()).decode('ascii')


def generate_qrcode(sp_address, output_file="/tmp/silent_payment_qr.png", scan_priv=None, spend_priv=None):
    """Legacy file writer; API responses use qr_png_base64 with address-only data."""
    _qr_image(sp_address).save(output_file)


# ---------------------------------------------------------------------------
# Rust binary backend
# ---------------------------------------------------------------------------

def _rust_vanity(
    pattern:     str,
    mode:        str = "contains",
    num_threads: int = 0,
    testnet:     bool = False,
    timeout_sec: Optional[int] = None,
) -> Tuple[List[str], dict]:
    bin_path = _find_bin()
    if bin_path is None:
        if is_vercel_runtime():
            raise RuntimeError('Vanity search is unavailable (binary not bundled).')
        raise RuntimeError(
            "Binario vanity non trovato.\n"
            f"Cerca in: {[str(p) for p in [Path(__file__).resolve().parent.parent.parent / 'bin' / 'vanity', _REPO_ROOT / 'vanity' / 'target' / 'release' / 'vanity']]}\n"
            "Per buildare: cd api/vanity && cargo build --release"
        )

    timeout = timeout_sec if timeout_sec is not None else vanity_search_timeout_sec()
    cmd = [str(bin_path), pattern, "--mode", mode, "--threads", str(num_threads), "--timeout", str(timeout)]
    if testnet:
        cmd.append("--testnet")

    timeout = timeout_sec if timeout_sec is not None else vanity_search_timeout_sec()
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
    if result.returncode == 2:
        raise TimeoutError('Vanity search timed out')
    if result.returncode != 0:
        if is_vercel_runtime():
            raise RuntimeError('Vanity search failed or timed out.')
        raise RuntimeError(f"Vanity generator failed (exit {result.returncode})")

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
        raise RuntimeError("Generator output is missing required fields") from e

    from core.receive import generate_sp_address
    from core.utils.hardened_keys import validate_private_key
    keys = {'scan_priv_key': validate_private_key(scan_priv).hex(), 'spend_priv_key': validate_private_key(spend_priv).hex()}
    reconstructed, _ = generate_sp_address(keys, network='testnet' if testnet else 'mainnet')
    if reconstructed != [address] or not vanity_matches(address, pattern, mode):
        raise RuntimeError('Invalid generator result')
    return [address], keys


# ---------------------------------------------------------------------------
# Pure-Python fallback
# ---------------------------------------------------------------------------

def vanity_matches(address: str, pattern: str, mode: str) -> bool:
    address, pattern = address.lower(), pattern.lower()
    start = 6 if address.startswith('tsp1qq') else 5
    searchable = address[start:]
    if mode == 'prefix':
        return searchable.startswith(pattern)
    if mode == 'suffix':
        return address.endswith(pattern)
    return pattern in searchable


def _python_vanity(
    pattern: str,
    mode:    str  = "contains",
    testnet: bool = False,
    timeout_sec: Optional[int] = None,
) -> Tuple[List[str], dict]:
    pattern = pattern.strip().lower()
    error = vanity_pattern_error(pattern)
    if error:
        raise ValueError(error)
    mode = normalize_vanity_mode(mode)
    if mode == 'prefix' and pattern[0] not in 'gf2tvdw0':
        raise ValueError('Prefix must begin with one of gf2tvdw0')
    _fix_python_path()
    from core.receive import generate_sp_address

    network = "testnet" if testnet else "mainnet"
    deadline = time.perf_counter() + (timeout_sec if timeout_sec is not None else vanity_search_timeout_sec())
    attempts = 0
    while time.perf_counter() < deadline:
        addresses, key_material = generate_sp_address(network=network)
        attempts += 1
        if vanity_matches(addresses[0], pattern, mode):
            print(f"[python fallback] trovato dopo {attempts} tentativi", file=sys.stderr)
            return addresses, key_material
    raise TimeoutError('Vanity search timed out')


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_sp_vanity_address(
    vanity_string: str,
    mode:        str  = "contains",
    num_threads: int  = 0,
    testnet:     bool = False,
) -> Tuple[List[str], dict]:
    """
    Genera un indirizzo Silent Payment BIP-352 contenente vanity_string.
    Usa il binario Rust se presente; fallback Python solo in locale se manca il binario.
    """
    vanity_string = vanity_string.strip().lower()
    limits = vanity_runtime_limits()
    err = vanity_pattern_error(vanity_string, limits['max_pattern_len'])
    if err:
        print(err, file=sys.stderr)
        raise ValueError(err)

    mode = normalize_vanity_mode(mode)
    if mode == 'prefix' and vanity_string[0] not in 'gf2tvdw0':
        raise ValueError('Prefix must begin with one of gf2tvdw0')
    threads = effective_vanity_threads(num_threads)
    timeout = limits['timeout_sec']
    bin_path = _find_bin()

    if is_vercel_runtime() and bin_path is None:
        raise FileNotFoundError('Vanity generator is unavailable')

    if bin_path is not None:
        return _rust_vanity(vanity_string, mode, threads, bool(testnet), timeout)
    if is_vercel_runtime():
        raise FileNotFoundError('Vanity generator is unavailable')
    return _python_vanity(vanity_string, mode, bool(testnet), timeout)


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
    if args.python_only:
        addresses, key_material = _python_vanity(
            args.vanity_string,
            args.mode,
            args.testnet,
            vanity_search_timeout_sec(),
        )
    else:
        addresses, key_material = get_sp_vanity_address(
            args.vanity_string,
            mode=args.mode,
            num_threads=args.threads,
            testnet=args.testnet,
        )
    elapsed = time.perf_counter() - t0

    if not addresses:
        print('Vanity search failed or timed out', file=sys.stderr)
        sys.exit(1)

    print(f"address:    {addresses[0]}")
    print(f"scan_priv:  {key_material['scan_priv_key']}")
    print(f"spend_priv: {key_material['spend_priv_key']}")
    print(f"time:       {elapsed:.2f}s", file=sys.stderr)