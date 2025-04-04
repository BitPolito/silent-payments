import os
import hashlib
from schnorr_lib import pubkey_point_gen_from_int, point_mul, has_even_y, bytes_from_point

# Elliptic curve Diffie-Hellman exchange with secp256k1

# Elliptic curve secp256k1 parameters
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def ecdh():
    #  Generate private key of user 'a'
    privkey_a = os.urandom(32)
    privkey_int_a = int(privkey_a.hex(), 16) % n

    # Compute public key of user 'a' as a point
    pubkey_a = pubkey_point_gen_from_int(privkey_int_a)

    # Check if the public key has the y-coordinate even otherwise reflect the private key and use the even-convention
    if not has_even_y(pubkey_a):
        privkey_int_a = (n - privkey_int_a) % n
        pubkey_a = pubkey_point_gen_from_int(privkey_int_a)

    #  Generate private key of user 'b'
    privkey_b = os.urandom(32)
    privkey_int_b = int(privkey_b.hex(), 16) % n

    # Compute public key of user 'b' as a point
    pubkey_b = pubkey_point_gen_from_int(privkey_int_b)

    # Check if the public key has the y-coordinate even otherwise reflect the private key and use the even-convention
    if not has_even_y(pubkey_b):
        privkey_int_b = (n - privkey_int_b) % n
        pubkey_b = pubkey_point_gen_from_int(privkey_int_b)

    # Compute the shared key for 'a'
    shared_key_a = point_mul(pubkey_b, privkey_int_a)

    # Compute the shared key for 'b'
    shared_key_b = point_mul(pubkey_a, privkey_int_b)

    # Check if they are the same point
    if shared_key_a != shared_key_b:
        raise ValueError("ECDH fails.")

    # Shared symmetric 32-byte-key
    shared_x = shared_key_a[0]  # x coordinate
    shared_key = hashlib.sha256(shared_x.to_bytes(32, "big")).digest()
    print(shared_key)

    return {
        "privatekey_a_hex": hex(privkey_int_a)[2:].rjust(64, "0"),
        "publickey_a_hex": bytes_from_point(pubkey_a).hex(),
        "privatekey_b_hex": hex(privkey_int_b)[2:].rjust(64, "0"),
        "publickey_b_hex": bytes_from_point(pubkey_b).hex(),
        "shared_key_hex": shared_key.hex(),
    }
