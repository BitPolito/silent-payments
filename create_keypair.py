import os
from schnorr_lib import pubkey_point_gen_from_int, n, bytes_from_point, has_even_y

def create_keypair(n_keys: int = 1):
    # Create json
    users = {
        "$schema": "./users_schema.json",
        "users": []
    }

    # Generate n keys
    for i in range(0, n_keys):
        privkey = os.urandom(32)
        privkey_int = int(privkey.hex(), 16) % n

        publickey = pubkey_point_gen_from_int(privkey_int)

        # Check if the point P has the y-coordinate even; negate the private key otherwise
        privkey_even = privkey_int if has_even_y(publickey) else n - privkey_int

        hex_privkey = hex(privkey_even).replace('0x', '').rjust(64, '0')
        users["users"].append({
            "privateKey": hex_privkey,
            "publicKey": bytes_from_point(publickey).hex()
        })
        
    return users