from typing import Tuple, Optional
from binascii import unhexlify
import hashlib
import os

# Elliptic curve parameters
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

# Points are tuples of X and Y coordinates
# the point at infinity is represented by the None keyword
Point = Tuple[int, int]



def bytes_from_int(a: int) -> bytes:
    '''Get bytes from an int'''
    return a.to_bytes(32, byteorder="big")



def bytes_from_hex(a: str) -> bytes:
    '''Get bytes from a hex string'''
    return unhexlify(a)



def bytes_from_point(P: Point) -> bytes:
    '''Get bytes from a point P: Tuple[int, int]'''
    return bytes_from_int(x(P))



def int_from_bytes(b: bytes) -> int:
    '''Get an int from bytes'''
    return int.from_bytes(b, byteorder="big")



def int_from_hex(a: str) -> int:
    '''Get an int from a hex string'''
    return int.from_bytes(unhexlify(a), byteorder="big")



def x(P: Point) -> int:
    '''Get x coordinate from a point P: Tuple[int, int]'''
    return P[0]



def y(P: Point) -> int:
    '''Get y coordinate from a point P: Tuple[int, int]'''
    return P[1]



def point_add(P1: Optional[Point], P2: Optional[Point]) -> Optional[Point]:
    '''Add two points P1 and P2 on the elliptic curve. Returns the resulting point or None if the result is the point at infinity.'''
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    if (x(P1) == x(P2)) and (y(P1) != y(P2)):
        return None
    if P1 == P2:
        lam = (3 * x(P1) * x(P1) * pow(2 * y(P1), p - 2, p)) % p
    else:
        lam = ((y(P2) - y(P1)) * pow(x(P2) - x(P1), p - 2, p)) % p
    x3 = (lam * lam - x(P1) - x(P2)) % p
    return x3, (lam * (x(P1) - x3) - y(P1)) % p



def point_mul(P: Optional[Point], d: int) -> Optional[Point]:
    '''Multiply a point P by an integer d. Returns the resulting point or None if the result is the point at infinity.'''
    R = None
    for i in range(256):
        if (d >> i) & 1:
            R = point_add(R, P)
        P = point_add(P, P)
    return R



def tagged_hash(tag: str, msg: bytes) -> bytes:
    '''Computes a tagged hash using the formula: SHA256(SHA256(tag) || SHA256(tag) || msg)'''
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()



def is_infinity(P: Optional[Point]) -> bool:
    '''Checks if a point P is the point at infinity. Returns True if P is None, False otherwise.'''
    return P is None



def xor_bytes(b0: bytes, b1: bytes) -> bytes:
    '''Returns the byte-wise XOR of two byte strings b0 and b1.'''
    return bytes(a ^ b for (a, b) in zip(b0, b1))


# Get a point from bytes
def lift_x_square_y(b: bytes) -> Optional[Point]:
    '''Given a 32-byte sequence b, returns a point P on the elliptic curve such that x(P) = b. If no such point exists, returns None.'''
    x = int_from_bytes(b)
    if x >= p:
        return None
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if pow(y, 2, p) != y_sq:
        return None
    return x, y


def lift_x_even_y(b: bytes) -> Optional[Point]:
    '''Given a 32-byte sequence b, returns a point P on the elliptic curve such that x(P) = b and y(P) is even. If no such point exists, returns None.'''
    P = lift_x_square_y(b)
    if P is None:
        return None
    else:
        return x(P), y(P) if y(P) % 2 == 0 else p - y(P)

def point_from_bytes(b: bytes) -> Optional[Point]:
    '''Decodes a SEC1 compressed public key (33 bytes) into a Point.'''
    if len(b) != 33:
        return None
    
    prefix = b[0]
    x_bytes = b[1:]
    
    P = lift_x_square_y(x_bytes)
    if P is None:
        return None
        
    x_coord, y_coord = P
    
    if prefix == 2:
        return (x_coord, y_coord if y_coord % 2 == 0 else p - y_coord)
    elif prefix == 3:
        return (x_coord, y_coord if y_coord % 2 != 0 else p - y_coord)
    else:
        return None



def sha256(b: bytes) -> bytes:
    '''Returns the SHA256 hash of the input bytes b.'''
    return hashlib.sha256(b).digest()



def is_square(a: int) -> bool:
    '''Checks if an integer a is a square'''
    return int(pow(a, (p - 1) // 2, p)) == 1



def has_square_y(P: Optional[Point]) -> bool:
    '''Check if a point has square y coordinate'''
    infinity = is_infinity(P)
    if infinity:
        return False
    assert P is not None
    return is_square(y(P))



def has_even_y(P: Point) -> bool:
    '''Check if a point has even y coordinate'''
    return y(P) % 2 == 0



def pubkey_gen_from_int(seckey: int) -> bytes:
    '''Generate public key from an int'''
    P = point_mul(G, seckey)
    assert P is not None
    return bytes_from_point(P)



def pubkey_gen_from_hex(seckey: str) -> bytes:
    '''Generate public key from a hex'''
    d0 = int_from_hex(seckey)
    if not (1 <= d0 <= n - 1):
        raise ValueError(
            'The secret key must be an integer in the range 1..n-1.')
    P = point_mul(G, d0)
    assert P is not None
    return bytes_from_point(P)



def pubkey_point_gen_from_int(seckey: int) -> Point:
    '''Generate public key (as a point) from an int'''
    P = point_mul(G, seckey)
    assert P is not None 
    return P



def get_aux_rand() -> bytes:
    '''Generate auxiliary random of 32 bytes'''
    return os.urandom(32)


# Extract R_x int value from signature
def get_int_R_from_sig(sig: bytes) -> int:
    return int_from_bytes(sig[0:32])



def get_int_s_from_sig(sig: bytes) -> int:
    '''Extract s int value from signature'''
    return int_from_bytes(sig[32:64])



def get_bytes_R_from_sig(sig: bytes) -> bytes:
    '''Extract R_x bytes from signature'''
    return sig[0:32]



def get_bytes_s_from_sig(sig: bytes) -> bytes:
    '''Extract s bytes from signature'''
    return sig[32:64]



def schnorr_sign(msg: bytes, privateKey: str) -> bytes:
    '''Generates a Schnorr signature for a given message and private key.'''
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')
    d0 = int_from_hex(privateKey)
    if not (1 <= d0 <= n - 1):
        raise ValueError(
            'The secret key must be an integer in the range 1..n-1.')
    P = point_mul(G, d0)
    assert P is not None
    d = d0 if has_even_y(P) else n - d0
    t = xor_bytes(bytes_from_int(d), tagged_hash("BIP0340/aux", get_aux_rand()))
    k0 = int_from_bytes(tagged_hash("BIP0340/nonce", t + bytes_from_point(P) + msg)) % n
    if k0 == 0:
        raise RuntimeError('Failure. This happens only with negligible probability.')
    R = point_mul(G, k0)
    assert R is not None
    k = n - k0 if not has_even_y(R) else k0
    e = int_from_bytes(tagged_hash("BIP0340/challenge", bytes_from_point(R) + bytes_from_point(P) + msg)) % n
    sig = bytes_from_point(R) + bytes_from_int((k + e * d) % n)
    
    if not schnorr_verify(msg, bytes_from_point(P), sig):
        raise RuntimeError('The created signature does not pass verification.')
    return sig



def schnorr_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    '''Verifies a Schnorr signature for a given message, public key, and signature.'''
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')
    if len(pubkey) != 32:
        raise ValueError('The public key must be a 32-byte array.')
    if len(sig) != 64:
        raise ValueError('The signature must be a 64-byte array.')
    P = lift_x_even_y(pubkey)
    r = get_int_R_from_sig(sig)
    s = get_int_s_from_sig(sig)
    if (P is None) or (r >= p) or (s >= n):
        return False
    e = int_from_bytes(tagged_hash("BIP0340/challenge", get_bytes_R_from_sig(sig) + pubkey + msg)) % n
    R = point_add(point_mul(G, s), point_mul(P, n - e))
    if (R is None) or (not has_even_y(R)):
        # print("Please, recompute the sign. R is None or has even y")
        return False
    if x(R) != r:
        # print("There's something wrong")
        return False
    return True

