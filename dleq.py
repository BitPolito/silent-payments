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

from schnorr_lib import *



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
def dleq_proof_generation(a: int, B: Point, r, m ):

    # Fail if a = 0 or a ≥ n.
    if a == 0 or a >= n: 
        raise ValueError('ERROR: private key not valid.')
    
    # Fail if is_infinite(B).

    # Let A = a⋅G.

    # Let C = a⋅B.

    # Let t be the byte-wise xor of bytes(32, a) and hashBIP0374/aux(r)

    # Let m' = m if m is provided, otherwise an empty byte array

    # Let rand = hashBIP0374/nonce(t || cbytes(A) || cbytes(C) || m')

    # Let k = int(rand) mod n

    # Fail if k = 0

    # Let R1 = k⋅G

    # Let R2 = k⋅B

    # Let e = int(hashBIP0374/challenge(cbytes(A) || cbytes(B) || cbytes(C) || cbytes(G) || cbytes(R1) || cbytes(R2) || m'))

    # Let s = (k + e⋅a) mod n

    # Let proof = bytes(32, e) || bytes(32, s)

    # If VerifyProof(A, B, C, proof) (see below) returns failure, abort
    
    # return proof 


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
def verify_proof() -> bool:
    
    # Fail if any of is_infinite(A), is_infinite(B), is_infinite(C), is_infinite(G)
    
    # Let e = int(proof[0:32]).
    
    # Let s = int(proof[32:64]); fail if s ≥ n.
    
    # Let R1 = s⋅G - e⋅A.
    
    # Fail if is_infinite(R1).
    
    # Let R2 = s⋅B - e⋅C.
    
    # Fail if is_infinite(R2).
    
    # Let m' = m if m is provided, otherwise an empty byte array.
    
    # Fail if e ≠ int(hashBIP0374/challenge(cbytes(A) || cbytes(B) || cbytes(C) || cbytes(G) || cbytes(R1) || cbytes(R2) || m')).
    
    # Return success iff no failure occurred before reaching this point
    return True