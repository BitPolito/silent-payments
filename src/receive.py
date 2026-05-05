import argparse
import json
import logging
from utils.utils import (
    encode_silent_payment_address,
    create_labeled_silent_payment_address,
    generate_label,
    compute_labels,
    get_input_hash,
    select_inputs,
    random_message,
    create_tweak,
    get_transaction_type,
    get_outpointL,
    serP,
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
)
from utils.hardened_keys import generate_hardened_keys
from typing import Tuple, List, Optional, Dict

logger = logging.getLogger(__name__)

NUMS_HEX = '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0'
NUMS_BYTES = bytes_from_hex(NUMS_HEX)


def _parse_witness(txinwitness) -> List[bytes]:
    """
    Decode a transaction witness field into a list of raw byte items.

    Accepts two formats:
    - A list of hex strings, as returned by most JSON RPC responses.
    - A single hex string containing the witness in Bitcoin's serialized format
      (compact-size item count followed by compact-size-prefixed items).

    Args:
        txinwitness: Either a list of hex strings or a single hex-encoded
                     serialized witness blob.

    Returns:
        A list of byte strings, one per witness stack item.
    """
    if isinstance(txinwitness, list):
        return [bytes_from_hex(x) for x in txinwitness if x]
    wit_bytes = bytes_from_hex(txinwitness)
    pos = 0
    num_items = wit_bytes[pos]; pos += 1
    items = []
    for _ in range(num_items):
        item_len = wit_bytes[pos]; pos += 1
        items.append(wit_bytes[pos:pos + item_len])
        pos += item_len
    return items


def _pubkey_point_from_input(tx: dict):
    """
    Extract and validate the elliptic-curve public key point from a transaction input.

    Supports P2PKH, P2WPKH, P2SH-P2WPKH, and P2TR input types. For each type the
    function reads the appropriate field (scriptSig, witness, or scriptPubKey), locates
    the public key, and reconstructs the corresponding curve point.

    Validation rules applied (mirroring validate_inputs logic):
    - P2PKH: only 33-byte compressed keys (prefix 0x02 or 0x03) are accepted; inputs
      carrying an uncompressed key are silently rejected.
    - P2WPKH / P2SH-P2WPKH: the last witness stack item must be a compressed key;
      65-byte uncompressed keys (prefix 0x04) are rejected.
    - P2TR key-path spend: the x-only public key is lifted directly from scriptPubKey.
    - P2TR script-path spend: the internal key is extracted from the control block;
      inputs using the NUMS point as internal key are rejected because they have no
      real spending authority.

    For keys with an odd y-coordinate (prefix 0x03) the point is negated so that the
    caller always receives the even-y representative, consistent with BIP-340 conventions.

    Args:
        tx: A dictionary representing one transaction input, expected to contain at
            minimum ``prevout.scriptPubKey.hex``, and optionally ``txinwitness``
            and ``scriptSig``.

    Returns:
        The elliptic-curve point corresponding to the input's public key, or ``None``
        if the input type is unsupported, the key is invalid, or the input must be
        excluded from Silent Payment scanning.
    """
    scriptPubKey = tx['prevout']['scriptPubKey']['hex']
    txinwitness  = tx.get('txinwitness', '')
    tx_type      = get_transaction_type(txinwitness, scriptPubKey, tx.get('scriptSig', ''))

    if tx_type == 'P2PKH':
        script_bytes = bytes_from_hex(tx['scriptSig'])
        items = []
        pos = 0
        while pos < len(script_bytes):
            opcode = script_bytes[pos]; pos += 1
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
                push_len = int.from_bytes(script_bytes[pos:pos + 2], 'little'); pos += 2
                items.append(script_bytes[pos:pos + push_len])
                pos += push_len

        raw = None
        for item in items:
            if len(item) == 33 and item[0] in (0x02, 0x03):
                raw = item
                break
        if raw is None:
            logger.debug('P2PKH input rejected: no valid compressed pubkey found')
            return None

    elif tx_type in ('P2WPKH', 'P2SH-P2WPKH'):
        items = _parse_witness(txinwitness)
        if not items:
            return None
        raw = items[-1]
        if len(raw) >= 65 and raw[0] == 0x04:
            logger.debug('%s input rejected: uncompressed pubkey', tx_type)
            return None

    elif tx_type == 'P2TR':
        items = _parse_witness(txinwitness)
        if not items:
            return None
        if items[-1][0:1] == b'\x50':
            items = items[:-1]
        if not items:
            return None

        if len(items) == 1:
            return lift_x_even_y(bytes_from_hex(scriptPubKey[4:]))
        else:
            control_block = items[-1]
            internal_key  = control_block[1:33]
            if internal_key == NUMS_BYTES:
                logger.debug('P2TR input rejected: NUMS internal key')
                return None
            return lift_x_even_y(internal_key)

    else:
        return None

    if len(raw) != 33 or raw[0] not in (0x02, 0x03):
        return None
    point = lift_x_even_y(raw[1:])
    if point is None:
        return None
    if raw[0] == 0x03:
        return point_mul(point, n - 1)
    return point


def generate_sp_address(
    key_material: Optional[dict] = None,
    labels: Optional[List[int]] = None,
    network: str = 'mainnet',
    version: int = 0,
) -> Tuple[List[str], dict]:
    """
    Derive one or more Silent Payment addresses from a set of key material.

    If no key material is provided, a fresh pair of hardened BIP-32 keys is
    generated automatically. The first address in the returned list is always
    the base (unlabeled) address. If ``labels`` is supplied, one additional
    labeled address is appended for each label integer.

    Args:
        key_material: Optional dictionary with ``scan_priv_key`` and
                      ``spend_priv_key`` as hex strings. When omitted, new keys
                      are generated and returned alongside the addresses.
        labels: Optional list of integer label indices. Each value ``m`` produces
                a labeled address via ``create_labeled_silent_payment_address``.
        network: Either ``'mainnet'`` (HRP ``sp``) or any other value for testnet
                 (HRP ``tsp``).
        version: Silent Payment protocol version encoded in the address (default 0).

    Returns:
        A tuple of ``(sp_addresses, key_material)`` where ``sp_addresses`` is a
        list of bech32m-encoded Silent Payment address strings and ``key_material``
        is the dictionary of keys used (generated or passed in).
    """
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
    labels: Optional[List[int]] = None,
) -> List[Dict]:
    """
    Scan a transaction's outputs and return those belonging to the Silent Payment wallet.

    Implements the BIP-352 recipient scanning algorithm:
    1. Filter ``vin`` down to eligible input types via ``select_inputs``, then extract
       a curve point from each input using ``_pubkey_point_from_input``.
    2. Sum the per-input points into the aggregate public key ``A``.
    3. Compute ``input_hash = hash_BIP0352/Inputs(outpointL || serP(A))``.
    4. Derive the ECDH shared secret as ``input_hash * b_scan * A``.
    5. For each counter ``k`` starting at 0, compute the candidate key
       ``Pk = B_spend + t_k * G`` and check whether any unmatched output matches
       ``Pk`` directly or via a known label tweak. Iteration stops at the first ``k``
       that produces no match.

    Args:
        vin: List of transaction input dictionaries, each containing at minimum
             ``vout``, ``prevout.scriptPubKey.hex``, and optionally ``txinwitness``
             and ``scriptSig``.
        outputs: List of hex-encoded x-only public keys from the transaction's
                 taproot outputs (32-byte, no prefix).
        key_material: Dictionary with ``scan_priv_key`` and ``spend_priv_key`` as
                      hex strings.
        labels: Optional list of integer label indices previously used to derive
                labeled addresses. When provided, label-tweaked outputs are also
                recognized.

    Returns:
        A list of dictionaries, one per matched output, each containing:
        - ``pub_key``: hex-encoded x-only public key of the matched output.
        - ``priv_key_tweak``: hex-encoded scalar tweak (``t_k`` or ``t_k + label``)
          to be added to ``b_spend`` to obtain the spending key.
    """
    inputs = select_inputs(vin)

    logger.debug('inputs count: %d', len(inputs))
    for tx in inputs:
        logger.debug(
            '  vout=%s type=%s',
            tx['vout'],
            get_transaction_type(
                tx.get('txinwitness', ''),
                tx['prevout']['scriptPubKey']['hex'],
                tx.get('scriptSig', ''),
            ),
        )

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

    logger.debug('valid_inputs count: %d', len(valid_inputs))
    for i, (vi, pt) in enumerate(zip(valid_inputs, pubkeys)):
        logger.debug(
            '  input %d  vout=%s  type=%s  pubkey=%s',
            i,
            vi['vout'],
            get_transaction_type(
                vi.get('txinwitness', ''),
                vi['prevout']['scriptPubKey']['hex'],
                vi.get('scriptSig', ''),
            ),
            serP(pt).hex(),
        )

    input_hash = get_input_hash(inputs, A)

    logger.debug('A:           %s', serP(A).hex())
    logger.debug('outpointL:   %s', get_outpointL(inputs).hex())
    logger.debug('input_hash:  %s', input_hash.hex())

    b_scan_int         = int_from_hex(key_material['scan_priv_key'])
    b_scan_bytes       = bytes_from_int(b_scan_int)
    s                  = int_from_bytes(input_hash) * b_scan_int % n
    ecdh_shared_secret = point_mul(A, s)

    logger.debug('t_k[0]: %s', create_tweak(ecdh_shared_secret, 0).hex())

    if not ecdh_shared_secret:
        raise ValueError('ERROR: ecdh_shared_secret is None.')

    labels_dict = compute_labels(b_scan_bytes, labels)
    B_spend     = pubkey_point_gen_from_int(int_from_hex(key_material['spend_priv_key']))

    wallet  = []
    k       = 0
    outputs = list(outputs)

    while True:
        t_k = create_tweak(ecdh_shared_secret, k)
        Pk  = point_add(B_spend, point_mul(G, int_from_bytes(t_k)))
        if Pk is None:
            break
        Pk_hex  = bytes_from_point(Pk).hex()
        matched = False

        for out in list(outputs):
            if out == Pk_hex:
                wallet.append({'pub_key': Pk_hex, 'priv_key_tweak': t_k.hex()})
                outputs.remove(out)
                k      += 1
                matched = True
                break

            elif labels_dict:
                out_point = lift_x_even_y(bytes_from_hex(out))

                label_candidate     = point_add(out_point, point_mul(Pk, n - 1))
                label_candidate_neg = point_add(point_mul(out_point, n - 1), point_mul(Pk, n - 1))

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
                        'priv_key_tweak': bytes_from_int(tweak_int).hex(),
                    })
                    outputs.remove(out)
                    k      += 1
                    matched = True
                    break

        if not matched:
            break

    return wallet


def get_spending_key(bspend: int, tk: int, bscan: int, m: int, labels: bool = False) -> str:
    """
    Compute the final spending private key for a received Silent Payment output.

    Combines the base spend key with the per-output tweak derived during scanning,
    and optionally adds a label scalar when the output was sent to a labeled address.

    Args:
        bspend: The spend private key as an integer (``b_spend``).
        tk:     The per-output tweak scalar ``t_k`` as an integer, as returned in
                ``priv_key_tweak`` by ``scan``.
        bscan:  The scan private key as an integer (``b_scan``), required only when
                ``labels`` is ``True`` to recompute the label hash.
        m:      The label index integer, required only when ``labels`` is ``True``.
        labels: When ``True``, the label scalar ``hash_BIP0352/Label(b_scan, m)`` is
                added to the result so the key matches a labeled output.

    Returns:
        The spending private key as a hex string (e.g. ``'0x1a2b...'``).
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
    labels: Optional[List] = None,
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


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=(
            'Run the Silent Payments receiving process or utility functions.\n'
            'All arguments must be provided via command line.\n'
            'vin, outputs, key_material, and labels can be JSON strings or paths to JSON files.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--vin',          required=False, help='List of input dicts (JSON string or path to JSON file)')
    parser.add_argument('--outputs',      required=False, help='List of output strings (JSON string or path to JSON file)')
    parser.add_argument('--key_material', required=False, help='Key material (JSON string or path to JSON file)')
    parser.add_argument('--labels',       required=False, help='List of integer labels (JSON string or path to JSON file)')
    parser.add_argument('--network',      required=False, default='mainnet', help='Network (default: mainnet)')
    parser.add_argument('--version',      required=False, type=int, default=0,  help='Version (default: 0)')
    parser.add_argument('--bspend',       required=False, type=int)
    parser.add_argument('--tk',           required=False, type=int)
    parser.add_argument('--bscan',        required=False, type=int)
    parser.add_argument('--m',            required=False, type=int)
    parser.add_argument('--label',        required=False, action='store_true')
    parser.add_argument('--debug',        required=False, action='store_true', help='Enable debug logging')
    parser.add_argument(
        '--function',
        choices=['run', 'scan', 'generate_sp_address', 'get_spending_key'],
        required=True,
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format='%(levelname)s %(name)s: %(message)s',
    )

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