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

def is_vercel_runtime() -> bool:
    """True when running on Vercel serverless (limited CPU time)."""
    return bool(os.environ.get('VERCEL'))


VALID_VANITY_MODES = frozenset({'contains', 'prefix', 'suffix'})

# Local: users run on their own hardware — default cap 5; raise with VANITY_MAX_PATTERN_LEN (bounded by cap).
_LOCAL_PATTERN_DEFAULT = 5
try:
    _LOCAL_PATTERN_CAP = int(os.environ.get('VANITY_MAX_PATTERN_LEN_CAP', '64'))
except (TypeError, ValueError):
    _LOCAL_PATTERN_CAP = 64
_LOCAL_PATTERN_CAP = max(1, _LOCAL_PATTERN_CAP)


def _local_max_pattern_len() -> int:
    try:
        n = int(os.environ.get('VANITY_MAX_PATTERN_LEN', str(_LOCAL_PATTERN_DEFAULT)))
    except (TypeError, ValueError):
        n = _LOCAL_PATTERN_DEFAULT
    return max(1, min(n, _LOCAL_PATTERN_CAP))


def vanity_runtime_limits() -> Dict[str, Any]:
    """
    Pattern length, timeout, and parallelism depend on where the API runs.

    - Vercel: short patterns, few threads, Rust only (no Python brute-force).
    - Local: default max 5 bech32m symbols (raise with VANITY_MAX_PATTERN_LEN, cap with VANITY_MAX_PATTERN_LEN_CAP).

    Override with env VANITY_MAX_PATTERN_LEN / VANITY_TIMEOUT_SEC / VANITY_MAX_THREADS.
    """
    if is_vercel_runtime():
        try:
            v_max = int(os.environ.get('VANITY_MAX_PATTERN_LEN', '5'))
        except (TypeError, ValueError):
            v_max = 5
        try:
            v_timeout = int(os.environ.get('VANITY_TIMEOUT_SEC', '55'))
        except (TypeError, ValueError):
            v_timeout = 55
        try:
            v_threads = int(os.environ.get('VANITY_MAX_THREADS', '2'))
        except (TypeError, ValueError):
            v_threads = 2
        return {
            'environment': 'vercel',
            'max_pattern_len': max(1, v_max),
            'timeout_sec': max(1, v_timeout),
            'max_threads': max(1, v_threads),
        }
    return {
        'environment': 'local',
        'max_pattern_len': _local_max_pattern_len(),
        'timeout_sec': int(os.environ.get('VANITY_TIMEOUT_SEC', '600')),
        'max_threads': _local_max_threads(),
    }


def _local_max_threads() -> int:
    try:
        t = int(os.environ.get('VANITY_MAX_THREADS', '4'))
    except (TypeError, ValueError):
        t = 4
    return max(1, t)


def normalize_vanity_mode(mode: str) -> str:
    m = (mode or 'contains').lower().strip()
    return m if m in VALID_VANITY_MODES else 'contains'


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

    cmd = [str(bin_path), pattern, "--mode", mode, "--threads", str(num_threads)]
    if testnet:
        cmd.append("--testnet")

    timeout = timeout_sec if timeout_sec is not None else vanity_search_timeout_sec()
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        if is_vercel_runtime():
            raise RuntimeError('Vanity search failed or timed out.')
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

    return [address], {"scan_priv_key": scan_priv, "spend_priv_key": spend_priv}


# ---------------------------------------------------------------------------
# Pure-Python fallback
# ---------------------------------------------------------------------------

def _python_vanity(
    pattern: str,
    mode:    str  = "contains",
    testnet: bool = False,
    timeout_sec: Optional[int] = None,
) -> Tuple[List[str], dict]:
    _fix_python_path()
    from receive import generate_sp_address

    def _searchable(addr: str) -> str:
        lower = addr.lower()
        if testnet and lower.startswith("tsp1qq"):
            return addr[6:]
        if not testnet and lower.startswith("sp1qq"):
            return addr[5:]
        if testnet and lower.startswith("tsp1q"):
            return addr[5:]
        if not testnet and lower.startswith("sp1q"):
            return addr[4:]
        sep = lower.find("1")
        return addr[sep + 2 :] if sep != -1 else addr

    def _matches(address: str) -> bool:
        pat = pattern.lower()
        addr = address.lower()
        slice_ = _searchable(addr)
        if mode == "prefix":
            return slice_.startswith(pat)
        if mode == "suffix":
            return addr.endswith(pat)
        return pat in slice_

    network = "testnet" if testnet else "mainnet"
    deadline = time.perf_counter() + (timeout_sec if timeout_sec is not None else vanity_search_timeout_sec())
    attempts = 0
    while time.perf_counter() < deadline:
        addresses, key_material = generate_sp_address(network=network)
        attempts += 1
        if _matches(addresses[0]):
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
        return None, None

    mode = normalize_vanity_mode(mode)
    threads = effective_vanity_threads(num_threads)
    timeout = limits['timeout_sec']
    bin_path = _find_bin()

    if is_vercel_runtime() and bin_path is None:
        print('[vanity] Rust binary required on Vercel', file=sys.stderr)
        return None, None

    try:
        if bin_path is not None:
            return _rust_vanity(vanity_string, mode, threads, bool(testnet), timeout)
        if is_vercel_runtime():
            return None, None
        print('[vanity] binario non trovato — uso il fallback Python.', file=sys.stderr)
        return _python_vanity(vanity_string, mode, bool(testnet), timeout)
    except (subprocess.TimeoutExpired, TimeoutError):
        print(f"[vanity] timeout dopo {timeout}s", file=sys.stderr)
        return None, None
    except RuntimeError as e:
        # Rust exit != 0, missing output, or Vercel-safe message — never invent an address.
        print(f'[vanity] {e}', file=sys.stderr)
        return None, None


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