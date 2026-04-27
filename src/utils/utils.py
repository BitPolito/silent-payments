from utils.schnorr_lib import *
from utils.segwit_addr import bech32_encode, convertbits, Encoding, decode
import binascii
from typing import Tuple, Optional, List
import hashlib
import os

def decode_input():
    # return everything needed
    pass

def get_transaction_type(txinwitness: str, scriptPubKey: str)  -> str: 
    lpkh=len(scriptPubKey)-4
    if scriptPubKey[:6]=="76a914" and scriptPubKey[lpkh:]=="88ac":
        return "P2PKH"   
    if scriptPubKey[:4]=="0014":
        return "P2WPKH"   
    if scriptPubKey[:4]=="5120":
        return "P2TR"
    lsh=len(scriptPubKey)-2
    if scriptPubKey[:4]=="a914" and scriptPubKey[lsh:]=="87" and txinwitness != "":
        return "P2SH-P2WPKH"
    return "Unknown"

def select_inputs(vin: List[dict]) -> List[dict]: 
    # Inputs For Shared Secret Derivation   
    valid_types = ['P2PKH', 'P2WPKH', 'P2TR', 'P2SH-P2WPKH']
    valid_inputs = [] 
    print("DEBUG VIN: ", vin)
    for tx in vin:
        print("DEBUG TX: ", tx)
        txinwitness = tx['txinwitness']
        scriptPubKey = tx['prevout']['scriptPubKey']['hex']
        # check if input is a valid type transaction
        type = get_transaction_type(txinwitness, scriptPubKey)
        if type in valid_types: 
            valid_inputs.append(tx) 
    return valid_inputs

def decode_scriptSig(scriptSig: str) -> Tuple[str, str, str]: 
    scriptSig_bytes = bytes_from_hex(scriptSig)
    
    signature_length = scriptSig_bytes[0]
    signature = scriptSig_bytes[1:1 + signature_length]
    
    pubkey_length = scriptSig_bytes[1 + signature_length]
    public_key = scriptSig_bytes[2 + signature_length:2 + signature_length + pubkey_length]

    signature_hex = binascii.hexlify(signature).decode('utf-8')
    public_key_hex = binascii.hexlify(public_key).decode('utf-8')

    tx_type = "Unknown"
    
    return tx_type, signature_hex, public_key_hex


# outpoint (36 bytes): the COutPoint of an input (32-byte txid, least significant byte first || 4-byte vout, least significant byte first)
def get_outpointL(vin: list[dict]) -> bytes:
    outpoint_list = []
    for tx in vin:
        txid, vout = tx['txid'], tx['vout'] 
        txid_bytes = bytes_from_hex(txid) 
        vout_bytes = vout.to_bytes(4, 'little')
        outpoint_list.append(txid_bytes + vout_bytes)
    outpointL = min(outpoint_list)
    return outpointL

# ser32(i): serializes a 32-bit unsigned integer i as a 4-byte sequence, most significant byte first. 
def ser32(i: int) -> bytes:
    return i.to_bytes(4, 'big') 

# ser256(p): serializes the integer p as a 32-byte sequence, most significant byte first.
def ser256(p: int) -> bytes:
    return p.to_bytes(32, 'big')

# serP(P): serializes the coordinate pair P = (x,y) as a byte sequence using SEC1's compressed form: 
# (0x02 or 0x03) || ser256(x), where the header byte depends on the parity of the omitted Y coordinate.
def serP(P: Point) -> bytes: 
    x_bytes = ser256(int_from_bytes(bytes_from_point(P)))
    prefix = b'\x02' if has_even_y(P) else b'\x03' # Determine the parity of y to choose the prefix
    return prefix + x_bytes 

def generate_label(b_scan: bytes, m: int) -> bytes:
    # hashBIP0352/Label(ser256(bscan) || ser32(m)) 
    return tagged_hash('BIP0352/Label', ser256(int_from_bytes(b_scan)) + ser32(m))

def compute_labels(b_scan: bytes, labels: Optional[List[int]]) -> List[Point]:
    labels_list = [pubkey_point_gen_from_int(int_from_bytes(generate_label(b_scan, 0)))]
    if labels:
        for m in labels:
            label_point = pubkey_point_gen_from_int(int_from_bytes(generate_label(b_scan, m)))
            labels_list.append(label_point)
    return labels_list

# hashBIP0352/Inputs(outpointL || A) 
def get_input_hash(inputs: List[dict], input_pubkey_sum: Point) -> bytes:
    return tagged_hash('BIP0352/Inputs', get_outpointL(inputs) + bytes_from_point(input_pubkey_sum))

def decode_silent_payment_address(address: str, hrp: str = 'sp') -> Tuple:
    #from segwit_addr import decode
    _, data = decode(hrp, address)
    if data is None: 
        raise ValueError('ERROR: Invalid data.')
    B_scan = bytes(data[:33])
    B_spend = bytes(data[33:])
    return B_scan, B_spend

def encode_silent_payment_address(B_scan: Point, B_m: Point, hrp: str = 'tsp', version: int = 0) -> str:
    if B_scan is None or B_m is None:
        raise ValueError('ERROR: Invalid data.')
    ret = bech32_encode(hrp, [version] + convertbits(serP(B_scan) + serP(B_m), 8, 5), Encoding.BECH32M)
    if decode(hrp, ret) == (None, None):
        raise ValueError('ERROR: Invalid data.')
    return ret

def create_labeled_silent_payment_address(b_scan: bytes, B_spend: Point, m: int, hrp: str = 'tsp', version: int = 0) -> str:
    #from schnorr_lib import G, point_mul, point_add, pubkey_point_gen_from_int, int_from_bytes
    #from utils import generate_label
    B_scan = pubkey_point_gen_from_int(int_from_bytes(b_scan))
    B_m = point_add(B_spend, point_mul(G, int_from_bytes(generate_label(b_scan, m))))
    if B_scan is None or B_m is None:
        raise ValueError('ERROR: Invalid data.')
    labeled_address = encode_silent_payment_address(B_scan, B_m, hrp, version)
    return labeled_address

def random_message() -> bytes:
    return hashlib.sha256(os.urandom(32)).digest()

def create_tweak(ecdh_shared_secret: Point, k: int) -> bytes:
    tk = tagged_hash('BIP0352/SharedSecret', serP(ecdh_shared_secret) + ser32(k))
    if int_from_bytes(tk) == 0 or int_from_bytes(tk) >= n:
        raise ValueError('ERROR: tweak not valid.')
    return tk