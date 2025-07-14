import argparse
import json
from utils import (
    encode_silent_payment_address, 
    create_labeled_silent_payment_address,
    generate_label,
    compute_labels,
    get_input_hash,
    decode_scriptSig, 
    select_inputs,
    random_message,
    create_tweak
)
from schnorr_lib import (
    n, 
    G, 
    bytes_from_hex,
    bytes_from_int,
    bytes_from_point,
    pubkey_point_gen_from_int, 
    point_add, 
    point_mul, 
    is_infinity, 
    lift_x_even_y,
    int_from_hex,
    int_from_bytes,
    schnorr_sign,
    schnorr_verify
)
from hardened_keys import generate_hardened_keys
from typing import Tuple, List, Optional, Dict


# generating silent payments address
def generate_sp_address(key_material: Optional[dict] = None, labels: Optional[List[int]] = None, network: str = 'mainnet', version: int = 0) -> Tuple[List[str], dict]:
    
    # if there are no keys in input create a private key pair
    if not key_material: 
        key_material = generate_hardened_keys()
        b_scan = key_material['scan_priv_key']
        b_spend = key_material['spend_priv_key']
    else: 
        b_scan = bytes_from_hex(key_material['scan_priv_key'])
        b_spend = bytes_from_hex(key_material['spend_priv_key'])
    
    # Receiver's scan and spend public key 
    B_scan = pubkey_point_gen_from_int(int_from_bytes(b_scan))
    B_spend = pubkey_point_gen_from_int(int_from_bytes(b_spend))
    
    # human-readable part based on the network
    hrp = 'sp' if network == 'mainnet' else 'tsp' 

    sp_addresses = []

    # If no label is applied then Bm = Bspend 
    sp_addresses.append(encode_silent_payment_address(B_scan, B_spend, hrp, version))

    # If a label is provided, apply the tweak
    if labels:
        for m in labels:
            sp_addresses.append(create_labeled_silent_payment_address(b_scan, B_spend, m, hrp, version))

    return sp_addresses, key_material


# If each of the checks in Scanning silent payment eligible transactions passes, the receiving wallet must:
def scan(vin: List[dict], outputs: List[str], key_material: dict, labels: Optional[List[int]] = None) -> List:
    
    inputs = select_inputs(vin)
    print(f'inputs: {inputs}')
    
    # Let A = A1 + A2 + ... + An, where each Ai is the public key of an input from the Inputs For Shared Secret Derivation list
    A = None
    for tx in inputs:
        _, _, pubkey = decode_scriptSig(tx['scriptSig'])
        print(f'pubkey: {pubkey}')
        # parity = bytes_from_hex(pubkey)[:1]
        pubkey_bytes = bytes_from_hex(pubkey)[1:]
        print(f'pubkey_bytes: {pubkey_bytes.hex()}')
        if len(pubkey_bytes) != 32:
            raise ValueError('ERROR: pubkey_bytes length is not 32 bytes.')
        A = point_add(A, lift_x_even_y(pubkey_bytes))
    if not A or is_infinity(A):
        raise ValueError('ERROR: point A is infinity or None.')

    # Let input_hash = hashBIP0352/Inputs(outpointL || A) 
    # where outpointL is the smallest outpoint lexicographically used in the transaction
    input_hash = get_input_hash(inputs, A)
    print(f'input_hash: {input_hash.hex()}')
    
    # Let ecdh_shared_secret = input_hash·bscan·A
    b_scan = int_from_hex(key_material['scan_priv_key'])
    s = int_from_bytes(input_hash) * b_scan % n
    ecdh_shared_secret = point_mul(A, s)
    print(f'ecdh_shared_secret: {ecdh_shared_secret}')
    if not ecdh_shared_secret:
        raise ValueError('ERROR: ecdh_shared_secret is None.')
    
    # compute labels 
    # always check for the change label, i.e. hashBIP0352/Label(ser256(bscan) || ser32(m)) where m = 0
    labels_list = compute_labels(bytes_from_int(b_scan), labels)
    print(f'labels_list: {[bytes_from_point(label).hex() for label in labels_list]}')
    
    # Check for outputs
    # Let outputs_to_check be the taproot output keys from all taproot outputs in the transaction (spent and unspent).
    # Starting with k = 0
    wallet = []
    k = int(0)
    while True:
        t_k = create_tweak(ecdh_shared_secret, k)
        print(f't_k: {t_k.hex()}')
        
        # Compute Pk = Bspend + tk·G
        B_spend = pubkey_point_gen_from_int(int_from_hex(key_material['spend_priv_key']))
        Pk = point_add(B_spend, point_mul(G, int_from_bytes(t_k)))
        print(f'Pk: {Pk}')
        if Pk is None:
            break
        Pk_hex = bytes_from_point(Pk).hex()
        print(f'Pk_hex: {Pk_hex}')

        # For each output in outputs_to_check:
        for out in outputs:
            print(f'out hex: {out}')
            # If Pk equals output:
            if out == Pk_hex:
                # Add Pk to the wallet
                wallet.append({
                    'pub_key': Pk_hex, 
                    'priv_key_tweak': t_k.hex()
                    })
                print(f'wallet: {wallet}')
                # Remove output from outputs_to_check and rescan outputs_to_check with k++
                outputs.remove(out)
                k += 1
                break
            
            # Else, check for labels
            elif labels_list:
                out_point = lift_x_even_y(bytes_from_hex(out))
                print(f'out_point: {out_point}')
                # Compute label = output - Pk
                label = point_add(out_point, point_mul(Pk, n - 1)) 
                print(f'label: {bytes_from_point(label).hex()}')
                # Check if label exists in the list of labels used by the wallet
                # If a match is found:
                if label in labels_list:
                    # Add Pk + label to the wallet
                    Pkm = point_add(Pk, label)
                    print(f'Pkm: {Pkm}')
                    if not Pkm:
                        raise ValueError('ERROR: Pkm is None.')
                    wallet.append({
                        'pub_key': Pk_hex, 
                        'priv_key_tweak': (t_k + bytes_from_point(label)).hex()
                    })
                    # Remove output from outputs_to_check and rescan outputs_to_check with k++
                    outputs.remove(out)
                    k += 1
                    break
                # If a label is not found, negate output and check a second time
                else:
                    neg_out = point_mul(out_point, n - 1)
                    print(f'neg_out: {neg_out}')
                    label_neg = point_add(neg_out, point_mul(Pk, n - 1))
                    print(f'label_neg: {bytes_from_point(label_neg).hex()}')
                    if label_neg in labels_list:
                        Pkm = point_add(Pk, label_neg)
                        if not Pkm:
                            raise ValueError('ERROR: Pkm is None.') 
                        wallet.append({
                            'pub_key': Pk_hex, 
                            'priv_key_tweak': (t_k + bytes_from_point(label_neg)).hex()
                        })
                        outputs.remove(out)
                        k += 1
                        break
        else:
            break
    return wallet



def get_spending_key(bspend: int, tk: int, bscan: int, m: int, labels: bool = False) -> str:
    '''
    Recall that a silent payment output is of the form Bspend + tk·G + hashBIP0352/Label(ser256(bscan) || ser32(m))·G, where hashBIP0352/Label(ser256(bscan) || ser32(m))·G is an optional label. 
    To spend a silent payment output:
    - Let d = (bspend + tk + hashBIP0352/Label(ser256(bscan) || ser32(m))) mod n, where hashBIP0352/Label(ser256(bscan) || ser32(m)) is the optional label
    - Spend the BIP341 output with the private key d
    '''
    d = (bspend + tk) % n
    if labels:
        label_hash = generate_label(bytes_from_int(bscan), m)
        print(f'label_hash: {label_hash}')
        d = (d + int_from_bytes(label_hash)) % n
    print(f'tweak: {hex(d)}')
    return hex(d)



# running the receiving process
def run(vin: Optional[list[dict]] = None, outputs: Optional[list[str]] = None, key_material: Optional[dict] = None, labels: Optional[list] = None) -> Tuple[List[str], List[Dict]]:
    print('receiver.py loading...') 
    if vin is None or outputs is None:
        raise ValueError('vin and outputs are required and cannot be None')
    address, key_material = generate_sp_address(key_material, labels)
    wallet = scan(vin, outputs, key_material, labels)
    print(f'wallet: {wallet}')
    msg = random_message()
    for output in wallet:
        pub_key = bytes_from_hex(output['pub_key'])
        full_private_key = output['priv_key_tweak']
        sig = schnorr_sign(msg, full_private_key)
        if not schnorr_verify(msg, pub_key, sig):
            raise ValueError(f'ERROR: Invalid signature for pubkey {pub_key.hex()}.')
        output['signature'] = sig.hex()
        print(f'sig: {sig.hex()}')
    return address, wallet



if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=(
            'Run the Silent Payments receiving process or utility functions.\n'
            'All arguments must be provided via command line.\n'
            'vin, outputs, key_material, and labels can be JSON strings or paths to JSON files.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--vin', required=False, help='List of input dicts (JSON string or path to JSON file)')
    parser.add_argument('--outputs', required=False, help='List of output strings (JSON string or path to JSON file)')
    parser.add_argument('--key_material', required=False, help='Key material (JSON string or path to JSON file)')
    parser.add_argument('--labels', required=False, help='List of integer labels (JSON string or path to JSON file)')
    parser.add_argument('--network', required=False, default='mainnet', help='Network for address generation (default: mainnet)')
    parser.add_argument('--version', required=False, type=int, default=0, help='Version for address generation (default: 0)')
    parser.add_argument('--bspend', required=False, type=int, help='bspend (int) for spending')
    parser.add_argument('--tk', required=False, type=int, help='tk (int) for spending')
    parser.add_argument('--bscan', required=False, type=int, help='bscan (int) for spending')
    parser.add_argument('--m', required=False, type=int, help='m (int) for spending')
    parser.add_argument('--label', required=False, action='store_true', help='label (bool) for spending')
    parser.add_argument('--function', choices=['run', 'scan', 'generate_sp_address', 'get_spending_key'], required=True, help='Function to execute')
    args = parser.parse_args()

    def load_json_arg(arg):
        if arg is None:
            return None
        try:
            with open(arg, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, OSError):
            return json.loads(arg)

    vin = load_json_arg(args.vin) if args.vin else None
    outputs = load_json_arg(args.outputs) if args.outputs else None
    key_material = load_json_arg(args.key_material) if args.key_material else None
    labels = load_json_arg(args.labels) if args.labels else None
    network = args.network
    version = args.version

    if args.function == 'run':
        if vin is None or outputs is None:
            raise ValueError('vin and outputs are required for run')
        result = run(vin, outputs, key_material, labels)
        print(result)
    elif args.function == 'scan':
        if vin is None or outputs is None or key_material is None:
            raise ValueError('vin, outputs, and key_material are required for scan')
        result = scan(vin, outputs, key_material, labels)
        print(result)
    elif args.function == 'generate_sp_address':
        result = generate_sp_address(key_material, labels, network, version)
        print(result)
    elif args.function == 'get_spending_key':
        if args.bspend is None or args.tk is None or args.bscan is None or args.m is None:
            raise ValueError('bspend, tk, bscan, and m are required for spending')
        result = get_spending_key(args.bspend, args.tk, args.bscan, args.m, args.label)
        print(result)
