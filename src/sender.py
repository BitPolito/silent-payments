''''
The sender performs coin selection as usual with the following restrictions: 
- At least one input MUST be from the Inputs For Shared Secret Derivation list 
- Exclude inputs with SegWit version > 1 (see Scanning silent payment eligible transactions)
- For each taproot output spent the sending wallet MUST have access to the private key corresponding to the taproot output key, unless H is used as the internal public key
''' 

from schnorr_lib import *
from utils import *
from receiver import generate_sp_address
from segwit_addr import *


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
        return "P2SH-P2PKH"  
    return None



def select_inputs(vin: list[dict]) -> list[dict]: 
    # Inputs For Shared Secret Derivation
    valid_types = ['P2PKH', 'P2WPKH', 'P2TR', 'P2SH-P2WPKH'] 
    valid_inputs = [] 
    for tx in vin:
        txinwitness = tx['txinwitness']
        scriptPubKey = tx['prevout']['scriptPubKey']['hex']
        # check if input is a valid type transaction
        type = get_transaction_type(txinwitness, scriptPubKey)
        if type in valid_types: 
            valid_inputs.append(tx) 
    return valid_inputs



def create_outputs(inputs: list[dict], recipients: list[str], change: bool = False) -> list:

    # collect keys for valid inputs
    keys = []
    for tx in inputs:
        keys.append(int_from_hex(tx['private_key']))

    # For each private key a_i corresponding to a BIP341 taproot output
    # check that the private key produces a point with an even Y coordinate and negate the private key if not
    for a_i in keys:
        P = pubkey_point_gen_from_int(a_i)
        if not has_even_y(P):
            keys.remove(a_i)

    # let a = sum(a_i) ---> if a=0 fail
    a = sum(keys)
    if a == 0:
        raise ValueError('ERROR: zero key sum.')
    A = point_mul(G, a) 

    # let input_hash = hashBIP0352/Inputs(outpointL || A)
    # where outpointL is the smallest outpoint lexicographically used in the transaction and A = a·G
    outpointL = get_outpointL(inputs)
    input_hash = tagged_hash('BIP0352/Inputs', outpointL + bytes_from_point(A)) 

    # Group receiver silent payment addresses by B_scan (e.g. each group consists of one B_scan and one or more B_m)
    
    outputs = []
    # For each group:
    for rp in recipients:
        # decode sp address
        B_scan, B_m = decode(hrp='sp', addr=rp) 
        # Let ecdh_shared_secret = input_hash·a·Bscan
        ecdh_shared_secret = point_mul(B_scan, int_from_bytes(input_hash) * a)
        # Let k = 0
        k = int(0)
        # For each Bm in the group: 
        for B_m in rp: 
            # Let tk = hashBIP0352/SharedSecret(serP(ecdh_shared_secret) || ser32(k))
            t_k = tagged_hash('BIP0352/SharedSecret', serP(ecdh_shared_secret) + ser32(k))
            # If tk is not valid tweak, i.e., if tk = 0 or tk is larger or equal to the secp256k1 group order, fail
            if t_k == 0 or t_k >= n: 
                raise ValueError('ERROR') 
            
            # Let Pmn = Bm + tk·G
            P_mn = point_add(B_m, point_mul(G, t_k))
            # Encode Pmn as a BIP341 taproot output
            taproot_output = taproot_encode(P_mn)
            outputs.append(taproot_output)

            # Optionally, repeat with k++ to create additional outputs for the current Bm
            # If no additional outputs are required, continue to the next Bm with k++
            k += 1
    
    # Optionally, if the sending wallet implements receiving silent payments, 
    # it can create change outputs by sending to its own silent payment address using label m = 0, following the steps above
    if change:
        change_address = generate_sp_address(label=0)
        outputs.append(change_address)

    return outputs


def taproot_encode(P: Point) -> str: 
    pubkey = bytes_from_point(P)
    tap = encode('bc', 0, pubkey)
    return tap


def sending_run(vin: list[dict], recipients: list[str]) -> list[str]:
    print(f'sender is loading...') 
    inputs = select_inputs(vin)
    print(f'selected {len(inputs)} valid inputs: {inputs}')
    outputs = create_outputs(inputs, recipients)
    return outputs

