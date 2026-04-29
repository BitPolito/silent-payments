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


# ── helpers ──────────────────────────────────────────────────────────────────
def _pubkey_point_from_input(tx: dict):
    """
    Estrae il punto EC corretto dall'input rispettando la parità.

    - P2PKH                : pubkey compressa (33 byte) dallo scriptSig
    - P2WPKH / P2SH-P2WPKH: pubkey compressa (33 byte) dall'ultimo elemento del witness
    - P2TR                 : x-only pubkey (32 byte) dalla scriptPubKey; y sempre pari
    
    Ritorna None se l'input deve essere skippato (chiave non compressa, ambigua, NUMS point).
    """
    scriptPubKey = tx['prevout']['scriptPubKey']['hex']
    txinwitness  = tx.get('txinwitness', '')
    tx_type      = get_transaction_type(txinwitness, scriptPubKey, tx.get('scriptSig', ''))

    if tx_type == 'P2PKH':
        _, _, pubkey_hex = decode_scriptSig(tx['scriptSig'])
        if pubkey_hex is None:
            return None
        raw = bytes_from_hex(pubkey_hex)

    elif tx_type in ('P2WPKH', 'P2SH-P2WPKH'):
        # pubkey è nell'ultimo elemento del witness
        if isinstance(txinwitness, list):
            items = [bytes_from_hex(x) for x in txinwitness if x]
        else:
            wit_bytes = bytes_from_hex(txinwitness)
            pos = 0
            n_items = wit_bytes[pos]; pos += 1
            items = []
            for _ in range(n_items):
                item_len = wit_bytes[pos]; pos += 1
                items.append(wit_bytes[pos:pos + item_len])
                pos += item_len
        raw = items[-1]

    elif tx_type == 'P2TR':
        if isinstance(txinwitness, list):
            items = [bytes_from_hex(x) for x in txinwitness if x]
        else:
            wit_bytes = bytes_from_hex(txinwitness)
            pos = 0
            n_items = wit_bytes[pos]; pos += 1
            items = []
            for _ in range(n_items):
                item_len = wit_bytes[pos]; pos += 1
                items.append(wit_bytes[pos:pos + item_len])
                pos += item_len

        # rimuovi annex se presente (ultimo elemento che inizia con 0x50)
        if items and items[-1][0:1] == b'\x50':
            items = items[:-1]

        NUMS = bytes_from_hex('50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0')

        if len(items) == 1:
            # key path spend: usa x-only pubkey dalla scriptPubKey
            return lift_x_even_y(bytes_from_hex(scriptPubKey[4:]))
        else:
            # script path spend: internal key = byte 1-32 del control block
            control_block = items[-1]
            internal_key  = control_block[1:33]
            if internal_key == NUMS:
                return None  # NUMS point → skip
            return lift_x_even_y(internal_key)

    else:
        return None  # tipo non supportato → skip

    # ── comune a P2PKH, P2WPKH, P2SH-P2WPKH ─────────────────────────────────
    # chiave non compressa → skip
    if len(raw) != 33 or raw[0] not in (0x02, 0x03):
        return None

    point = lift_x_even_y(raw[1:])
    if raw[0] == 0x03 and has_even_y(point):
        return point_mul(point, n - 1)
    if raw[0] == 0x02 and not has_even_y(point):
        return point_mul(point, n - 1)
    return point
# ── address generation ────────────────────────────────────────────────────────

def generate_sp_address(
    key_material: Optional[dict] = None,
    labels: Optional[List[int]] = None,
    network: str = 'mainnet',
    version: int = 0
) -> Tuple[List[str], dict]:
    """Genera uno o più indirizzi Silent Payment."""

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


# ── scanning ──────────────────────────────────────────────────────────────────

def scan(
    vin: List[dict],
    outputs: List[str],
    key_material: dict,
    labels: Optional[List[int]] = None
) -> List[Dict]:
    """
    Scansiona gli output di una transazione e restituisce quelli spendibili
    dal wallet identificato da key_material.

    Ogni voce del wallet contiene:
      - pub_key        : x-only pubkey hex (32 byte) dell'output trovato
      - priv_key_tweak : scalare hex (32 byte) tale che d = (bspend + tweak) mod n
    """

    inputs = select_inputs(vin)
    
    print(f'DEBUG inputs count: {len(inputs)}')
    for tx in inputs:
        print(f'  vout={tx["vout"]} type={get_transaction_type(tx.get("txinwitness",""), tx["prevout"]["scriptPubKey"]["hex"], tx.get("scriptSig",""))}')

    if not inputs:
        return []
    

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
    
    
    # ── 1. Somma delle chiavi pubbliche degli input ───────────────────────────
    A = None
    for pt in pubkeys:
        A = point_add(A, pt)

    if A is None or is_infinity(A):
        return []  # somma dei punti è il punto all'infinito → skip tx

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

    if not ecdh_shared_secret:
        raise ValueError('ERROR: ecdh_shared_secret is None.')

    # ── 4. Mappa label: point → m ─────────────────────────────────────────────
    # Include sempre m=0 (change label); compute_labels ritorna {point: m}
    labels_dict = compute_labels(b_scan_bytes, labels)

    # ── 5. Scansione degli output ─────────────────────────────────────────────
    B_spend = pubkey_point_gen_from_int(int_from_hex(key_material['spend_priv_key']))
    wallet  = []
    k       = 0

    while True:
        t_k = create_tweak(ecdh_shared_secret, k)

        # Pk = Bspend + tk·G
        Pk = point_add(B_spend, point_mul(G, int_from_bytes(t_k)))
        if Pk is None:
            break
        Pk_hex = bytes_from_point(Pk).hex()

        matched = False
        for out in list(outputs):           # list() per evitare modifica durante iterazione

            # ── caso A: match diretto ────────────────────────────────────────
            if out == Pk_hex:
                wallet.append({
                    'pub_key':        Pk_hex,
                    'priv_key_tweak': t_k.hex()
                })
                outputs.remove(out)
                k      += 1
                matched = True
                break

            # ── caso B: output con label ─────────────────────────────────────
            elif labels_dict:
                out_point = lift_x_even_y(bytes_from_hex(out))

                # Prova label = out_point - Pk  (y positiva)
                label_candidate = point_add(out_point, point_mul(Pk, n - 1))

                # Prova anche con la y negata dell'output (parità opposta)
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


# ── spending key ──────────────────────────────────────────────────────────────

def get_spending_key(bspend: int, tk: int, bscan: int, m: int, labels: bool = False) -> str:
    """
    Calcola la chiave privata completa per spendere un output Silent Payment.

    d = (bspend + tk [+ label_hash]) mod n
    """
    d = (bspend + tk) % n
    if labels:
        label_hash = generate_label(bytes_from_int(bscan), m)
        d = (d + int_from_bytes(label_hash)) % n
    return hex(d)


# ── main receiving flow ───────────────────────────────────────────────────────

def receiving_run(
    vin: Optional[List[dict]] = None,
    outputs: Optional[List[str]] = None,
    key_material: Optional[dict] = None,
    labels: Optional[List] = None
) -> Tuple[List[str], List[Dict]]:
    """
    Flusso completo di ricezione:
      1. Genera (o usa) le chiavi e l'indirizzo SP
      2. Scansiona gli output
      3. Verifica la firma Schnorr per ogni output trovato
    """
    if vin is None or outputs is None:
        raise ValueError('vin and outputs are required and cannot be None')

    address, key_material = generate_sp_address(key_material, labels)
    wallet = scan(vin, list(outputs), key_material, labels)   # copia: scan modifica in-place

    b_spend = int_from_hex(key_material['spend_priv_key'])
    msg     = random_message()

    for output in wallet:
        pub_key   = bytes_from_hex(output['pub_key'])
        tweak_int = int_from_bytes(bytes_from_hex(output['priv_key_tweak']))

        # chiave privata completa: d = (bspend + tweak) mod n
        d   = (b_spend + tweak_int) % n
        sig = schnorr_sign(msg, bytes_from_int(d).hex())

        if not schnorr_verify(msg, pub_key, sig):
            raise ValueError(f'ERROR: Invalid signature for pubkey {pub_key.hex()}.')

        output['signature'] = sig.hex()

    return address, wallet


# ── CLI ───────────────────────────────────────────────────────────────────────

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