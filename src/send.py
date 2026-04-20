''''
The sender performs coin selection as usual with the following restrictions: 
- At least one input MUST be from the Inputs For Shared Secret Derivation list 
- Exclude inputs with SegWit version > 1 (see Scanning silent payment eligible transactions)
- For each taproot output spent the sending wallet MUST have access to the private key corresponding to the taproot output key, unless H is used as the internal public key
''' 

from utils.schnorr_lib import *
from utils.utils import *
from utils.segwit_addr import *


def create_outputs(inputs: list[dict], recipients: list[str]) -> list:
    # For each private key a_i corresponding to a BIP341 taproot output
    # check that the private key produces a point with an even Y coordinate and negate the private key if not
    keys = []
    for tx in inputs:
        a_i = int_from_hex(tx['private_key'])
        P = pubkey_point_gen_from_int(a_i)
        if not has_even_y(P):
            a_i = p - a_i
        keys.append(a_i)

    # let a = sum(a_i) ---> if a=0 fail
    a = sum(keys)
    if a == 0:
        raise ValueError('ERROR: zero key sum.')
    A = point_mul(G, a) 

    # let input_hash = hashBIP0352/Inputs(outpointL || A)
    # where outpointL is the smallest outpoint lexicographically used in the transaction and A = a·G
    input_hash = get_input_hash(inputs, A)
    print(f'input hash: {input_hash}')
    
    # Group receiver silent payment addresses by B_scan (e.g. each group consists of one B_scan and one or more B_m)
    sp_groups: dict[bytes, list[bytes]] = {}
    for receip in recipients:
        B_scan, B_m = decode_silent_payment_address(receip)
        print(f'B_scan: {B_scan}')
        print(f'B_m: {B_m}')
        if B_scan in sp_groups:
            sp_groups[B_scan].append(B_m)
        else:
            sp_groups[B_scan] = [B_m]
    print(f'SP groups: {sp_groups}')
    outputs = []
    # For each group:
    for B_scan, B_m_list in sp_groups.items(): 
        # Let ecdh_shared_secret = input_hash·a·Bscan
        print(f'B_scan: {lift_x_even_y(B_scan)}')
        print(int_from_bytes(input_hash) * a)
        print(int_from_bytes(input_hash))
        print(a)
        ecdh_shared_secret = point_mul(lift_x_even_y(B_scan), int_from_bytes(input_hash) * a)
        print(ecdh_shared_secret)
        # Let k = 0
        k = int(0) 
        # For each B_m in the group: 
        for B_m in B_m_list:           
            # Let tk = hashBIP0352/SharedSecret(serP(ecdh_shared_secret) || ser32(k))
            t_k = int_from_bytes(tagged_hash('BIP0352/SharedSecret', serP(ecdh_shared_secret) + ser32(k)))
            # If tk is not valid tweak, i.e., if tk = 0 or tk is larger or equal to the secp256k1 group order, fail
            if t_k == 0 or t_k >= n: 
                raise ValueError('ERROR: wrong tweak value.') 
            
            # Let Pmn = Bm + tk·G
            P_mn = point_add(lift_x_even_y(B_m), point_mul(G, t_k))
            # Encode Pmn as a BIP341 taproot output
            taproot_output = bytes_from_point(P_mn).hex()
            outputs.append(taproot_output)

            # Optionally, repeat with k++ to create additional outputs for the current Bm
            # If no additional outputs are required, continue to the next Bm with k++
            k += 1
    
    return outputs


def sending_run(vin: list[dict], recipients: list[str]) -> list[str]:
    print(f'sender is loading...') 
    inputs = select_inputs(vin)
    print(f'selected {len(inputs)} valid inputs: {inputs}')
    outputs = create_outputs(inputs, recipients)
    return outputs

