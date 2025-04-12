from schnorr_lib import *

# outpoint (36 bytes): the COutPoint of an input (32-byte txid, least significant byte first || 4-byte vout, least significant byte first)
def get_outpoint(vin: dict) -> bytes:
    txid, vout = vin['txid'], vin['vout'] 
    txid_bytes = bytes.fromhex(txid)[::-1] # Convert txid to bytes and reverse the order (little-endian)
    vout_bytes = vout.to_bytes(4, 'little') # Convert vout to bytes (little-endian)
    return txid_bytes + vout_bytes

# ser32(i): serializes a 32-bit unsigned integer i as a 4-byte sequence, most significant byte first. 
def ser32(i: int) -> bytes:
    return i.to_bytes(4, 'big') 

# ser256(p): serializes the integer p as a 32-byte sequence, most significant byte first.
def ser256(p: int) -> bytes:
    return p.to_bytes(32, 'big')

# serP(P): serializes the coordinate pair P = (x,y) as a byte sequence using SEC1's compressed form: 
# (0x02 or 0x03) || ser256(x), where the header byte depends on the parity of the omitted Y coordinate.
def serP(P: Point) -> bytes:
    x_bytes = ser256(bytes_from_point(P)) 
    prefix = b'\x02' if has_even_y(P) else b'\x03' # Determine the parity of y to choose the prefix
    return prefix + x_bytes 

def tag_hash(tag, x) -> bytes: 
    # SHA256(SHA256(tag) || SHA256(tag) || x)
    hash = hashlib.sha256(hashlib.sha256(tag).digest + hashlib.sha256(tag).digest + x).digest
    return hash 

