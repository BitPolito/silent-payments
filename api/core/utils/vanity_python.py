"""
BIP-352 Silent Payment vanity address generator.

Two backends:
1. Rust FFI (fast)        — libvanity.so via ctypes
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
import ctypes
import sys
import time
import qrcode
from pathlib import Path
from typing import List, Tuple, Optional

# ---------------------------------------------------------------------------
# Locate shared library — risale l'albero fino a trovare vanity/
# ---------------------------------------------------------------------------

_LIB_NAMES = ["libvanity.so", "vanity.dll", "libvanity.dylib"]

def _find_repo_root() -> Path:
    """Risale le directory a partire da questo file cercando la cartella vanity/."""
    candidate = Path(__file__).resolve().parent
    for _ in range(8):
        if (candidate / "vanity").is_dir():
            return candidate
        candidate = candidate.parent
    return Path(__file__).resolve().parent

_REPO_ROOT = _find_repo_root()

_SEARCH_DIRS = [
    _REPO_ROOT / "vanity" / "target" / "release",
    _REPO_ROOT / "vanity" / "target" / "debug",
    Path(__file__).parent,
]

def _find_lib() -> Optional[Path]:
    for d in _SEARCH_DIRS:
        for name in _LIB_NAMES:
            p = d / name
            if p.exists():
                return p
    return None

# ---------------------------------------------------------------------------
# Fix sys.path per il fallback Python
# Aggiunge src/ al path in modo che `from receive import ...` funzioni
# indipendentemente da dove viene eseguito lo script.
# ---------------------------------------------------------------------------

def _fix_python_path():
    """Assicura che src/ sia nel sys.path per importare receive e utils."""
    # Cerca la directory src/ risalendo l'albero
    candidate = Path(__file__).resolve().parent
    for _ in range(8):
        if (candidate / "receive.py").exists():
            src_dir = str(candidate)
            if src_dir not in sys.path:
                sys.path.insert(0, src_dir)
            return
        candidate = candidate.parent
        
def generate_qrcode(sp_address, output_file="silent_payment_qr.png"):
    qr = qrcode.QRCode(
        version=None, 
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(sp_address)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(output_file)


# ---------------------------------------------------------------------------
# ctypes bindings
# ---------------------------------------------------------------------------

class _VanityFfiResult(ctypes.Structure):
    _fields_ = [
        ("address",    ctypes.c_char_p),
        ("scan_priv",  ctypes.c_char_p),
        ("spend_priv", ctypes.c_char_p),
        ("attempts",   ctypes.c_ulonglong),
    ]

def _load_lib() -> Optional[ctypes.CDLL]:
    lib_path = _find_lib()
    if lib_path is None:
        return None
    try:
        lib = ctypes.CDLL(str(lib_path))
        lib.vanity_find.restype  = ctypes.POINTER(_VanityFfiResult)
        lib.vanity_find.argtypes = [
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
        ]
        lib.vanity_free_result.restype  = None
        lib.vanity_free_result.argtypes = [ctypes.POINTER(_VanityFfiResult)]
        return lib
    except OSError:
        return None

_LIB: Optional[ctypes.CDLL] = _load_lib()

_MODE_MAP = {"contains": 0, "prefix": 1, "suffix": 2}

# ---------------------------------------------------------------------------
# Rust backend
# ---------------------------------------------------------------------------

def _rust_vanity(
    pattern:     str,
    mode:        str  = "contains",
    num_threads: int  = 0,
    testnet:     bool = False,
) -> Tuple[List[str], dict]:
    assert _LIB is not None
    ptr = _LIB.vanity_find(
        pattern.encode(),
        ctypes.c_int(_MODE_MAP.get(mode, 0)),
        ctypes.c_int(num_threads),
        ctypes.c_int(1 if testnet else 0),
    )
    if not ptr:
        raise RuntimeError("vanity_find returned NULL")
    try:
        r = ptr.contents
        address    = r.address.decode()
        generate_qrcode(address)
        scan_priv  = r.scan_priv.decode()
        spend_priv = r.spend_priv.decode()
    finally:
        _LIB.vanity_free_result(ptr)
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
        Forza il fallback Python anche se libvanity.so è disponibile.

    Returns
    -------
    (addresses, key_material)
        addresses[0] è l'indirizzo trovato.
        key_material ha 'scan_priv_key' e 'spend_priv_key' come hex.
    """
    if _LIB is not None and not force_python:
        return _rust_vanity(vanity_string, mode, num_threads, testnet)

    if _LIB is None and not force_python:
        print(
            "[vanity] libvanity.so non trovata — uso il fallback Python.\n"
            f"         Cerca in: {[str(d) for d in _SEARCH_DIRS]}\n"
            "         Per usare Rust: cd vanity && cargo build --release",
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

    backend = "python" if (args.python_only or _LIB is None) else "rust"
    print(f"[vanity] backend: {backend}  |  lib: {_find_lib()}", file=sys.stderr)

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