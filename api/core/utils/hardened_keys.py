"""Independent raw demo keys; not BIP32-derived or seed recoverable."""
import secrets
from core.utils.schnorr_lib import n


def validate_private_key(value: bytes | str) -> bytes:
    if isinstance(value, str):
        if len(value) != 64:
            raise ValueError('Private keys must be exactly 32 bytes (64 hex characters)')
        try:
            value = bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError('Invalid private key hex') from exc
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError('Private keys must be exactly 32 bytes')
    if not 0 < int.from_bytes(value, 'big') < n:
        raise ValueError('Private key scalar is out of range')
    return value


def generate_private_key() -> bytes:
    while True:
        value = secrets.token_bytes(32)
        if 0 < int.from_bytes(value, 'big') < n:
            return value


def generate_hardened_keys() -> dict:
    """Legacy function name; generates independent raw scan/spend keys."""
    return {'scan_priv_key': generate_private_key(), 'spend_priv_key': generate_private_key()}
