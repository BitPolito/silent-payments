from core.utils.schnorr_lib import *
from core.utils.segwit_addr import bech32_encode, convertbits, Encoding, decode
import binascii
from typing import Tuple, Optional, List
import hashlib
import os

def get_transaction_type(txinwitness: str, scriptPubKey: str, scriptSig: str = '') -> str:
    '''Determines the type of a transaction input based on its scriptPubKey and txinwitness.'''
    lpkh = len(scriptPubKey) - 4
    if scriptPubKey[:6] == "76a914" and scriptPubKey[lpkh:] == "88ac":
        return "P2PKH"
    if scriptPubKey[:4] == "0014":
        return "P2WPKH"
    if scriptPubKey[:4] == "5120":
        return "P2TR"
    lsh = len(scriptPubKey) - 2
    if scriptPubKey[:4] == "a914" and scriptPubKey[lsh:] == "87" and txinwitness != "":
        if scriptSig[:6] == "160014" and len(scriptSig) == 46:
            return "P2SH-P2WPKH"
        return "Unknown"
    return "Unknown"

def validate_inputs(inputs: List[dict], vin: List[dict]) -> List[dict]:
    '''Validates the inputs by checking their types and removing any invalid ones'''
    from core.receive import _pubkey_point_from_input
    return [tx for tx in inputs if _pubkey_point_from_input(tx) is not None]


def has_unsupported_witness(vin):
    for tx in vin:
        script = tx['prevout']['scriptPubKey']['hex']
        if len(script) >= 4:
            version, size = bytes.fromhex(script[:4])
            if 0x52 <= version <= 0x60 and 2 <= size <= 40 and len(script) == 4 + 2 * size:
                return True
    return False


def select_inputs(vin: List[dict]) -> List[dict]:
    '''Selects the inputs to be used in the transaction.'''
    valid_types = ['P2PKH', 'P2WPKH', 'P2TR', 'P2SH-P2WPKH']
    valid_inputs = []
    for tx in vin:
        txinwitness = tx.get('txinwitness', '')
        scriptPubKey = tx['prevout']['scriptPubKey']['hex']
        scriptSig = tx.get('scriptSig', '')
        type = get_transaction_type(txinwitness, scriptPubKey, scriptSig)
        if type in valid_types:
            valid_inputs.append(tx)
    return valid_inputs

def decode_serialized_witness(witness_hex: str) -> Tuple[Optional[str], Optional[str]]:
    '''Decode a serialized txinwitness (es. P2WPKH) and extracts sign and pubkey. Return a Tuple (signature_hex, pubkey_hex).'''
    if not witness_hex:
        return None, None
        
    try:
        data = bytes_from_hex(witness_hex)
        num_items = data[0]
        
        # P2WPKH has only 2 elements
        if num_items != 2:
            return None, None
            
        offset = 1
        sig_len = data[offset]
        offset += 1
        sig = data[offset : offset + sig_len] 
        offset += sig_len 
        
        pubkey_len = data[offset]
        offset += 1
        pubkey = data[offset : offset + pubkey_len]
        
        return sig.hex(), pubkey.hex()
        
    except Exception as e:
        # Cattura eventuali errori se la stringa hex è malformata
        print(f"Errore nel parsing del witness: {e}")
        return None, None

def decode_scriptSig(scriptSig: str) -> Tuple[str, str, str]:
    '''Decode a scriptSig (es. P2PKH) and extracts sign and pubkey. Return a Tuple (tx_type, signature_hex, pubkey_hex).'''
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
    '''Returns the smallest outpoint lexicographically used in the transaction.'''
    outpoint_list = []
    for tx in vin:
        txid, vout = tx['txid'], tx['vout'] 
        txid_bytes = bytes_from_hex(txid)[::-1]
        vout_bytes = vout.to_bytes(4, 'little')
        outpoint_list.append(txid_bytes + vout_bytes)
    outpointL = min(outpoint_list)
    return outpointL

def ser32(i: int) -> bytes:
    '''Serializes a 32-bit unsigned integer i as a 4-byte sequence, most significant byte first.'''
    return i.to_bytes(4, 'big') 

def ser256(p: int) -> bytes:
    '''Serializes the integer p as a 32-byte sequence, most significant byte first.'''
    return p.to_bytes(32, 'big')

def serP(P: Point) -> bytes: 
    '''Serializes a point P as a byte sequence using SEC1's compressed form: (0x02 or 0x03) || ser256(x), where the header byte depends on the parity of the omitted Y coordinate.'''
    x_bytes = ser256(int_from_bytes(bytes_from_point(P)))
    prefix = b'\x02' if has_even_y(P) else b'\x03' # Determine the parity of y to choose the prefix
    return prefix + x_bytes 

def generate_label(b_scan: bytes, m: int) -> bytes:
    '''Generates a label for a given b_scan and m using the formula: hashBIP0352/Label(ser256(bscan) || ser32(m)) '''
    return tagged_hash('BIP0352/Label', ser256(int_from_bytes(b_scan)) + ser32(m))

def compute_labels(b_scan: bytes, labels: Optional[List[int]]) -> dict:
    '''Computes the labels for a given b_scan and a list of m values. Returns a dictionary mapping points to their corresponding m values.'''
    result = {}
    m0_point = pubkey_point_gen_from_int(int_from_bytes(generate_label(b_scan, 0)))
    result[m0_point] = 0
    if labels:
        for m in labels:
            pt = pubkey_point_gen_from_int(int_from_bytes(generate_label(b_scan, m)))
            result[pt] = m
    return result

# hashBIP0352/Inputs(outpointL || A) 
def get_input_hash(inputs: List[dict], input_pubkey_sum: Point) -> bytes:
    '''Computes the input hash using the formula: hashBIP0352/Inputs(outpointL || A)'''
    return tagged_hash('BIP0352/Inputs', get_outpointL(inputs) + serP(input_pubkey_sum))

def decode_silent_payment_address(address: str, hrp: str | None = None) -> Tuple:
    '''Decodes a silent payment address and returns the B_scan and B_spend points.'''
    if not isinstance(address, str):
        raise ValueError('Invalid address')
    hrp = hrp or ('tsp' if address.lower().startswith('tsp1') else 'sp')
    version, data = decode(hrp, address)
    if version is None or version == 31:
        raise ValueError('Unsupported Silent Payment version')
    if data is None: 
        raise ValueError('ERROR: Invalid data.')
    B_scan = bytes(data[:33])
    B_spend = bytes(data[33:66])
    if len(data) < 66 or any(k[0] not in (2, 3) or point_from_bytes(k) is None for k in (B_scan, B_spend)):
        raise ValueError('Invalid compressed public keys')
    return B_scan, B_spend

def encode_silent_payment_address(B_scan: Point, B_m: Point, hrp: str = 'tsp', version: int = 0) -> str:
    '''Encodes a silent payment address from the given B_scan and B_m points.'''
    if B_scan is None or B_m is None:
        raise ValueError('ERROR: Invalid data.')
    ret = bech32_encode(hrp, [version] + convertbits(serP(B_scan) + serP(B_m), 8, 5), Encoding.BECH32M)
    if decode(hrp, ret) == (None, None):
        raise ValueError('ERROR: Invalid data.')
    return ret

def create_labeled_silent_payment_address(b_scan: bytes, B_spend: Point, m: int, hrp: str = 'tsp', version: int = 0) -> str:
    '''Creates a labeled silent payment address from the given b_scan, B_spend, and m values.'''
    B_scan = pubkey_point_gen_from_int(int_from_bytes(b_scan))
    B_m = point_add(B_spend, point_mul(G, int_from_bytes(generate_label(b_scan, m))))
    if B_scan is None or B_m is None:
        raise ValueError('ERROR: Invalid data.')
    labeled_address = encode_silent_payment_address(B_scan, B_m, hrp, version)
    return labeled_address

def random_message() -> bytes:
    '''Generates a random message for signing.'''
    return hashlib.sha256(os.urandom(32)).digest()

def create_tweak(ecdh_shared_secret: Point, k: int) -> bytes:
    '''Creates a tweak for signing using the formula: hashBIP0352/SharedSecret(serP(ecdh_shared_secret) || ser32(k))'''
    tk = tagged_hash('BIP0352/SharedSecret', serP(ecdh_shared_secret) + ser32(k))
    if int_from_bytes(tk) == 0 or int_from_bytes(tk) >= n:
        raise ValueError('ERROR: tweak not valid.')
    return tk