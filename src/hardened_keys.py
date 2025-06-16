'''
Two keys are needed to create a silent payments address: the spend key and the scan key. 
To ensure compatibility, wallets MAY use BIP32 derivation with the following derivation paths for the spend and scan key. 
When using BIP32 derivation, wallet software MUST use hardened derivation for both the spend and scan key.

A scan and spend key pair using BIP32 derivation are defined (taking inspiration from BIP44) in the following manner:

scan_private_key: m / purpose' / coin_type' / account' / 1' / 0
spend_private_key: m / purpose' / coin_type' / account' / 0' / 0

purpose is a constant set to 352 following the BIP43 recommendation. Refer to BIP43 and BIP44 for more details.
'''

import hmac
from schnorr_lib import *

def hmac_sha512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha512).digest()


def derive_hardened_key(master_key: bytes, index: int) -> bytes:
    index_bytes = index.to_bytes(4, byteorder='big')
    return hmac_sha512(master_key, b'\x00' + master_key + index_bytes)


def generate_hardened_keys() -> Tuple[bytes, bytes]:
    master_key = os.urandom(32)  # 32 bytes 

    scan_private_key = derive_hardened_key(master_key, 1)  # m/1'
    spend_private_key = derive_hardened_key(master_key, 0)  # m/0'

    # Store the keys in a dictionary
    key_material = {
        'scan_priv_key': scan_private_key,
        'spend_priv_key': spend_private_key
    }
    
    return key_material

