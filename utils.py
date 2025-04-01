import hashlib 
import btclib


def hash_function(tag, x): 
    # SHA256(SHA256(tag) || SHA256(tag) || x)
    hash = hashlib.sha256(hashlib.sha256(tag) + hashlib.sha256(tag) + x)
    return hash


