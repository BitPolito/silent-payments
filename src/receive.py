import argparse
import json
from utils.utils import (
    encode_silent_payment_address, 
    create_labeled_silent_payment_address,
    generate_label,
    compute_labels,
    get_input_hash,
    decode_scriptSig, 
    select_inputs,
    random_message,
    create_tweak,
    get_transaction_type,
    get_outpointL,
    serP
)
from utils.schnorr_lib import (
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
    schnorr_verify,
    has_even_y
)
from utils.hardened_keys import generate_hardened_keys
from typing import Tuple, List, Optional, Dict

def _pubkey_point_from_input(tx: dict):
    scriptPubKey = tx['prevout']['scriptPubKey']['hex']
    txinwitness  = tx.get('txinwitness', '')
    tx_type      = get_transaction_type(txinwitness, scriptPubKey, tx.get('scriptSig', ''))

    if tx_type == 'P2PKH':
        script_bytes = bytes_from_hex(tx['scriptSig'])
        items = []
        pos = 0
        while pos < len(script_bytes):
            opcode = script_bytes[pos]
            pos += 1
            if opcode == 0x00:
                items.append(b'')
            elif 0x01 <= opcode <= 0x4b:
                items.append(script_bytes[pos:pos + opcode])
                pos += opcode
            elif opcode == 0x4c:
                push_len = script_bytes[pos]; pos += 1
                items.append(script_bytes[pos:pos + push_len])
                pos += push_len
            elif opcode == 0x4d:
                push_len = int.from_bytes(script_bytes[pos:pos+2], 'little'); pos += 2
                items.append(script_bytes[pos:pos + push_len])
                pos += push_len
    
        # Prendi il primo elemento che sia una compressed pubkey valida (33 bytes, prefix 02/03)
        raw = None
        for item in items:
            if len(item) == 33 and item[0] in (0x02, 0x03):
                raw = item
                break
        if raw is None:
            return None

    elif tx_type in ('P2WPKH', 'P2SH-P2WPKH'):
        if isinstance(txinwitness, list):
            items = [bytes_from_hex(x) for x in txinwitness if x]
        else:
            wit_bytes = bytes_from_hex(txinwitness)
            pos = 0
            num_items = wit_bytes[pos]; pos += 1
            items = []
            for _ in range(num_items):
                item_len = wit_bytes[pos]; pos += 1
                items.append(wit_bytes[pos:pos + item_len])
                pos += item_len
        if not items:
            return None
        raw = items[-1]

    elif tx_type == 'P2TR':
        if isinstance(txinwitness, list):
            items = [bytes_from_hex(x) for x in txinwitness if x]
        else:
            wit_bytes = bytes_from_hex(txinwitness)
            pos = 0
            num_items = wit_bytes[pos]; pos += 1
            items = []
            for _ in range(num_items):
                item_len = wit_bytes[pos]; pos += 1
                items.append(wit_bytes[pos:pos + item_len])
                pos += item_len
        if not items:
            return None
        # Rimuovi annex se presente (inizia con 0x50)
        if items[-1][0:1] == b'\x50':
            items = items[:-1]
        if not items:
            return None

        NUMS = bytes_from_hex('50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0')

        if len(items) == 1:
            # key-path spend: pubkey dallo scriptPubKey
            return lift_x_even_y(bytes_from_hex(scriptPubKey[4:]))
        else:
            # script-path spend: internal key dal control block
            control_block = items[-1]
            internal_key  = control_block[1:33]
            if internal_key == NUMS:
                return None
            return lift_x_even_y(internal_key)

    else:
        return None

    # P2PKH, P2WPKH, P2SH-P2WPKH: verifica compressed key e ricostruisce il punto
    if len(raw) != 33 or raw[0] not in (0x02, 0x03):
        return None
    point = lift_x_even_y(raw[1:])
    if point is None:
        return None
    if raw[0] == 0x03:
        # odd-y: neghiamo
        return point_mul(point, n - 1)
    return point
# ── address generation ────────────────────────────────────────────────────────

def generate_sp_address(
    key_material: Optional[dict] = None,
    labels: Optional[List[int]] = None,
    network: str = 'mainnet',
    version: int = 0
) -> Tuple[List[str], dict]:

    if not key_material:
        key_material = generate_hardened_keys()
        b_scan  = key_material['scan_priv_key']
        b_spend = key_material['spend_priv_key']
    else:
        b_scan  = bytes_from_hex(key_material['scan_priv_key'])
        b_spend = bytes_from_hex(key_material['spend_priv_key'])

    B_scan  = pubkey_point_gen_from_int(int_from_bytes(b_scan))
    B_spend = pubkey_point_gen_from_int(int_from_bytes(b_spend))
    hrp = 'sp' if network == 'mainnet' else 'tsp'
    sp_addresses = [encode_silent_payment_address(B_scan, B_spend, hrp, version)]
    if labels:
        for m in labels:
            sp_addresses.append(
                create_labeled_silent_payment_address(b_scan, B_spend, m, hrp, version)
            )

    return sp_addresses, key_material

def scan(
    vin: List[dict],
    outputs: List[str],
    key_material: dict,
    labels: Optional[List[int]] = None
) -> List[Dict]:
    inputs = select_inputs(vin)
    
    print(f'DEBUG inputs count: {len(inputs)}')
    for tx in inputs:
        print(f'  vout={tx["vout"]} type={get_transaction_type(tx.get("txinwitness",""), tx["prevout"]["scriptPubKey"]["hex"], tx.get("scriptSig",""))}')    
    if not inputs:
        return []
    valid_inputs = []
    pubkeys = []
    for tx in inputs:
        pt = _pubkey_point_from_input(tx)
        if pt is not None:
            valid_inputs.append(tx)
            pubkeys.append(pt)
    if not valid_inputs:
        return []

    A = None
    for pt in pubkeys:
        A = point_add(A, pt)
    if A is None or is_infinity(A):
        return []  
    # ── 2. input_hash = hash_BIP0352/Inputs(outpointL || serP(A)) ────────────
    input_hash = get_input_hash(inputs, A)
    # ── 3. ecdh_shared_secret = input_hash · bscan · A ───────────────────────
    b_scan_int        = int_from_hex(key_material['scan_priv_key'])
    b_scan_bytes      = bytes_from_int(b_scan_int)
    s                 = int_from_bytes(input_hash) * b_scan_int % n
    ecdh_shared_secret = point_mul(A, s)
    
    print(f'valid_inputs count: {len(valid_inputs)}')
    for vi in valid_inputs:
        print(f'  vout={vi["vout"]} type={get_transaction_type(vi.get("txinwitness",""), vi["prevout"]["scriptPubKey"]["hex"], vi.get("scriptSig",""))}')
    print(f'A: {serP(A).hex() if A else None}')
    print(f'outpointL (inputs): {get_outpointL(inputs).hex()}')
    print(f'input_hash: {input_hash.hex()}')
    print(f't_k[0]: {create_tweak(ecdh_shared_secret, 0).hex()}')
    
    for i, (tx, pt) in enumerate(zip(valid_inputs, pubkeys)):
        print(f'  input {i} pubkey: {serP(pt).hex()}')
    
    A_check = None
    for i, pt in enumerate(pubkeys):
        A_check = point_add(A_check, pt)
        print(f'  after adding input {i}: {serP(A_check).hex()}')
        
    if not ecdh_shared_secret:
        raise ValueError('ERROR: ecdh_shared_secret is None.')
    labels_dict = compute_labels(b_scan_bytes, labels)

    B_spend = pubkey_point_gen_from_int(int_from_hex(key_material['spend_priv_key']))
    
    
    t_k0 = create_tweak(ecdh_shared_secret, 0)
    Pk0 = point_add(B_spend, point_mul(G, int_from_bytes(t_k0)))
    print(f'Pk0 computed: {bytes_from_point(Pk0).hex()}')
    print(f'Pk0 expected: 4612cdbf845c66c7511d70aab4d9aed11e49e48cdb8d799d787101cdd0d53e4f')
    print(f'outputs: {outputs}')
    
    wallet  = []
    k       = 0
    while True:
        t_k = create_tweak(ecdh_shared_secret, k)
        Pk = point_add(B_spend, point_mul(G, int_from_bytes(t_k)))
        if Pk is None:
            break
        Pk_hex = bytes_from_point(Pk).hex()
        matched = False
        for out in list(outputs):           
            if out == Pk_hex:
                wallet.append({
                    'pub_key':        Pk_hex,
                    'priv_key_tweak': t_k.hex()
                })
                outputs.remove(out)
                k      += 1
                matched = True
                break
            elif labels_dict:
                out_point = lift_x_even_y(bytes_from_hex(out))
                label_candidate = point_add(out_point, point_mul(Pk, n - 1))

                neg_out_point   = point_mul(out_point, n - 1)
                label_candidate_neg = point_add(neg_out_point, point_mul(Pk, n - 1))

                found_label  = None
                found_Pkm_pt = None

                if label_candidate in labels_dict:
                    found_label  = label_candidate
                    found_Pkm_pt = point_add(Pk, label_candidate)
                elif label_candidate_neg in labels_dict:
                    found_label  = label_candidate_neg
                    found_Pkm_pt = point_add(Pk, label_candidate_neg)

                if found_label is not None and found_Pkm_pt is not None:
                    m            = labels_dict[found_label]
                    label_scalar = int_from_bytes(generate_label(b_scan_bytes, m))
                    tweak_int    = (int_from_bytes(t_k) + label_scalar) % n

                    wallet.append({
                        'pub_key':        bytes_from_point(found_Pkm_pt).hex(),
                        'priv_key_tweak': bytes_from_int(tweak_int).hex()
                    })
                    outputs.remove(out)
                    k      += 1
                    matched = True
                    break

        if not matched:
            break

    return wallet

def get_spending_key(bspend: int, tk: int, bscan: int, m: int, labels: bool = False) -> str:
    d = (bspend + tk) % n
    if labels:
        label_hash = generate_label(bytes_from_int(bscan), m)
        d = (d + int_from_bytes(label_hash)) % n
    return hex(d)

def receiving_run(
    vin: Optional[List[dict]] = None,
    outputs: Optional[List[str]] = None,
    key_material: Optional[dict] = None,
    labels: Optional[List] = None
) -> Tuple[List[str], List[Dict]]:
    if vin is None or outputs is None:
        raise ValueError('vin and outputs are required and cannot be None')

    address, key_material = generate_sp_address(key_material, labels)
    wallet = scan(vin, list(outputs), key_material, labels) 

    b_spend = int_from_hex(key_material['spend_priv_key'])
    msg     = random_message()

    for output in wallet:
        pub_key   = bytes_from_hex(output['pub_key'])
        tweak_int = int_from_bytes(bytes_from_hex(output['priv_key_tweak']))
        d   = (b_spend + tweak_int) % n
        sig = schnorr_sign(msg, bytes_from_int(d).hex())
        if not schnorr_verify(msg, pub_key, sig):
            raise ValueError(f'ERROR: Invalid signature for pubkey {pub_key.hex()}.')
        output['signature'] = sig.hex()

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
    parser.add_argument('--vin',          required=False, help='List of input dicts (JSON string or path to JSON file)')
    parser.add_argument('--outputs',      required=False, help='List of output strings (JSON string or path to JSON file)')
    parser.add_argument('--key_material', required=False, help='Key material (JSON string or path to JSON file)')
    parser.add_argument('--labels',       required=False, help='List of integer labels (JSON string or path to JSON file)')
    parser.add_argument('--network',      required=False, default='mainnet', help='Network (default: mainnet)')
    parser.add_argument('--version',      required=False, type=int, default=0, help='Version (default: 0)')
    parser.add_argument('--bspend',       required=False, type=int)
    parser.add_argument('--tk',           required=False, type=int)
    parser.add_argument('--bscan',        required=False, type=int)
    parser.add_argument('--m',            required=False, type=int)
    parser.add_argument('--label',        required=False, action='store_true')
    parser.add_argument('--function',
        choices=['run', 'scan', 'generate_sp_address', 'get_spending_key'],
        required=True
    )
    args = parser.parse_args()

    def load_json_arg(arg):
        if arg is None:
            return None
        try:
            with open(arg, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, OSError):
            return json.loads(arg)

    vin          = load_json_arg(args.vin)
    outputs      = load_json_arg(args.outputs)
    key_material = load_json_arg(args.key_material)
    labels       = load_json_arg(args.labels)

    if args.function == 'run':
        if vin is None or outputs is None:
            raise ValueError('vin and outputs are required for run')
        print(receiving_run(vin, outputs, key_material, labels))

    elif args.function == 'scan':
        if vin is None or outputs is None or key_material is None:
            raise ValueError('vin, outputs, and key_material are required for scan')
        print(scan(vin, outputs, key_material, labels))

    elif args.function == 'generate_sp_address':
        print(generate_sp_address(key_material, labels, args.network, args.version))

    elif args.function == 'get_spending_key':
        if any(v is None for v in [args.bspend, args.tk, args.bscan, args.m]):
            raise ValueError('bspend, tk, bscan, and m are required for get_spending_key')
        print(get_spending_key(args.bspend, args.tk, args.bscan, args.m, args.label))