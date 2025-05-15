'''
The basic proof generation uses a random scalar k, the secret a, and the point being proven C = a⋅B.

    Let R1 = k⋅G.
    Let R2 = k⋅B.
    Let e = hash(R1 || R2).
    Let s = (k + e⋅a).

Providing only C, e and s as a proof does not reveal a or k.

Verifying the proof involves recreating R1 and R2 with only e and s as follows:

    Let R1 = s⋅G - e⋅A.
    Let R2 = s⋅B - e⋅C.

This can be verified by substituting s = (k + e⋅a):

    s⋅G - e⋅A = (k + e⋅a)⋅G - e⋅A = k⋅G + e⋅(a⋅G) - e⋅A = k⋅G + e⋅A - e⋅A = k⋅G.
    s⋅B - e⋅C = (k + e⋅a)⋅B - e⋅C = k⋅B + e⋅(a⋅B) - e⋅C = k⋅B + e⋅C - e⋅C = k⋅B.

Thus verifying e = hash(R1 || R2) proves the discrete logarithm equivalency of A and C. 
'''

from schnorr_lib import n, G, Point, point_add, point_mul, is_infinity, xor_bytes, bytes_from_point, bytes_from_int, int_from_bytes, tagged_hash
import os


# The following generates a proof that the result of a⋅B and the result of a⋅G are both generated from the same scalar a without having to reveal a 
'''
    Input:

    The secret key a: a 256-bit unsigned integer
    The public key B: a point on the curve
    Auxiliary random data r: a 32-byte array
    The generator point G: a point on the curve
    An optional message m: a 32-byte array
'''
# The algorithm GenerateProof(a, B, r, G, m) is defined as:
def dleq_proof_generation(a: int, B: Point, r: bytes, G: Point = G, m: bytes = None) -> bytes:
    # Fail if a = 0 or a ≥ n.
    if a == 0 or a >= n: 
        raise ValueError('ERROR: private key not valid.')
    
    # Fail if is_infinite(B).
    if is_infinity(B):
        raise ValueError('ERROR: point not valid.')

    # Let A = a⋅G.
    A = point_mul(G, a)

    # Let C = a⋅B.
    C = point_mul(B, a)

    # Let t be the byte-wise xor of bytes(32, a) and hashBIP0374/aux(r)
    t = xor_bytes(bytes_from_int(a)[0:32], tagged_hash(r))

    # Let m' = m if m is provided, otherwise an empty byte array
    m_ = m if m is not None else b''

    # Let rand = hashBIP0374/nonce(t || cbytes(A) || cbytes(C) || m')
    rand = tagged_hash(nonce, t + bytes_from_point(A) + bytes_from_point(C) + m_)
    

    # Let k = int(rand) mod n
    k = int_from_bytes(rand) % n

    # Fail if k = 0
    if k == 0:
        raise ValueError('ERROR: zero value occurred')

    # Let R1 = k⋅G
    R1 = point_mul(G, k)

    # Let R2 = k⋅B
    R2 = point_mul(B, k)

    # Let e = int(hashBIP0374/challenge(cbytes(A) || cbytes(B) || cbytes(C) || cbytes(G) || cbytes(R1) || cbytes(R2) || m'))
    e = int_from_bytes(tagged_hash(challenge_tag, bytes_from_point(A) + bytes_from_point(B) + bytes_from_point(C) + bytes_from_point(G) + bytes_from_point(R1) + bytes_from_point(R2) + m_))

    # Let s = (k + e⋅a) mod n
    s = (k + e*a) % n

    # Let proof = bytes(32, e) || bytes(32, s)
    proof = bytes_from_int(e)[0:32] + bytes_from_int(s)[0:32]

    # If VerifyProof(A, B, C, proof) (see below) returns failure, abort
    if not verify_proof(A, B, C, proof): 
        raise ValueError('ERROR: proof not verified')
    
    return proof 


# The following verifies the proof generated in the previous section. 
# If the following algorithm succeeds, the points A and C were both generated from the same scalar. 
# The former from multiplying by G, and the latter from multiplying by B. 

'''
Input:
    The public key of the secret key used in the proof generation A: a point on the curve
    The public key used in the proof generation B: a point on the curve
    The result of multiplying the secret and public keys used in the proof generation C: a point on the curve
    A proof proof: a 64-byte array
    The generator point used in the proof generation G: a point on the curve
    An optional message m: a 32-byte array
'''

#  The algorithm VerifyProof(A, B, C, proof, G, m) is defined as: 
def verify_proof(A: Point, B: Point, C: Point, proof: bytes, G: Point = G, m: bytes = None) -> bool:
    
    # Fail if any of is_infinite(A), is_infinite(B), is_infinite(C), is_infinite(G)
    if is_infinity(A) or is_infinity(B) or is_infinity(C) or is_infinity(G):
        return False
    
    # Let e = int(proof[0:32])
    e = int(proof[0:32])
    
    # Let s = int(proof[32:64]); fail if s ≥ n
    s = int(proof[32:64])
    if s >= n:
        return False
    
    # Let R1 = s⋅G - e⋅A.
    R1 = point_add(point_mul(G,s), point_mul(A, n-e))
    
    # Fail if is_infinite(R1).
    if is_infinity(R1):
        return False
    
    # Let R2 = s⋅B - e⋅C.
    R2 = point_add(point_mul(B,s), point_mul(C, n-e))
    
    # Fail if is_infinite(R2).
    if is_infinity(R2):
        return False
    
    # Let m' = m if m is provided, otherwise an empty byte array.
    m_ = m if m is not None else b''
    
    # Fail if e ≠ int(hashBIP0374/challenge(cbytes(A) || cbytes(B) || cbytes(C) || cbytes(G) || cbytes(R1) || cbytes(R2) || m')).
    e_ = int_from_bytes(tagged_hash(challenge_tag, bytes_from_point(A) + bytes_from_point(B) + bytes_from_point(C) + bytes_from_point(G) + bytes_from_point(R1) + bytes_from_point(R2) + m_))
    if e != e_:
        return False
    
    # Return success iff no failure occurred before reaching this point
    return True

