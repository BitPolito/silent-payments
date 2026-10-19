"""Bounded educational experiments using public, pinned fixture material."""
from collections import Counter
from copy import deepcopy
from functools import lru_cache
from pathlib import Path
import hashlib
import json
from coincurve import PublicKeyXOnly
from core.receive import generate_sp_address, scan
from core.send import sending_run
from core.utils.schnorr_lib import n, schnorr_sign
from core.utils.utils import decode_silent_payment_address
from core.utils.segwit_addr import bech32_decode, convertbits, Encoding

ROOT = Path(__file__).parent / 'test'
class ExperimentInputError(ValueError):
    pass

TOOLS = ('payment', 'address')
PRESETS = {'payment': ['default', 'mutation'], 'address': ['default']}

@lru_cache(maxsize=1)
def fixtures():
    return json.loads((ROOT / 'test_vectors.json').read_text())

@lru_cache(maxsize=1)
def provenance():
    source = json.loads((ROOT / 'provenance.json').read_text())
    return {k: source[k] for k in ('spec_version', 'commit', 'url', 'upstream_sha256')}

def keys():
    return deepcopy(fixtures()[0]['receiving'][0]['given']['key_material'])

def input_cards():
    base = deepcopy(fixtures()[0]['sending'][0]['given']['vin'])
    for index in range(2):
        item = deepcopy(base[index])
        item['txid'] = f'{index + 1:02x}' * 32
        base.append(item)
    return base

def public_vin(vin):
    return [{k: deepcopy(v) for k, v in item.items() if k != 'private_key'} for item in vin]

def addresses(network='testnet', labels=None):
    return generate_sp_address(keys(), labels or [], network=network)[0]

def metadata():
    return {'tools': list(TOOLS), 'presets': PRESETS, 'inputs': [{'id': i, 'type': 'P2PKH', 'outpoint': f"{item['txid']}:{item['vout']}"} for i, item in enumerate(input_cards())],
            'samples': {network: addresses(network)[0] for network in ('testnet', 'mainnet')}, 'provenance': provenance()}

def integer(value, minimum, maximum, name):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ExperimentInputError(f'Invalid {name}')
    return value

def validate(body, fields, tool):
    if not isinstance(body, dict) or set(body) - fields:
        raise ExperimentInputError('Unknown experiment controls')
    if body.get('preset', 'default') not in PRESETS[tool]:
        raise ExperimentInputError('Unknown experiment preset')
    if body.get('network', 'testnet') not in ('testnet', 'mainnet'):
        raise ExperimentInputError('Invalid network')

def inspect_address(address):
    if not isinstance(address, str) or not 1 <= len(address) <= 1023:
        raise ExperimentInputError('A public address of at most 1023 characters is required')
    address = address.strip()
    hrp, data, encoding = bech32_decode(address)
    result = {'status': 'invalid_encoding', 'checksum_valid': False}
    if hrp is None or encoding != Encoding.BECH32M:
        return result
    result.update(checksum_valid=True, network={'sp': 'mainnet', 'tsp': 'testnet'}.get(hrp), version=data[0] if data else None)
    if hrp not in ('sp', 'tsp') or not data:
        return {**result, 'status': 'invalid_payload'}
    if data[0] == 31:
        return {**result, 'status': 'unsupported'}
    payload = convertbits(data[1:], 5, 8, False)
    if payload is None or len(payload) < 66 or (data[0] == 0 and len(payload) != 66):
        return {**result, 'status': 'invalid_payload'}
    try:
        scan_key, spend_key = decode_silent_payment_address(address, hrp)
    except ValueError:
        return {**result, 'status': 'invalid_payload'}
    return {**result, 'status': 'supported' if data[0] == 0 else 'forward_compatible', 'scan_pub_key': scan_key.hex(), 'spend_pub_key': spend_key.hex(), 'ignored_extension_bytes': len(payload) - 66}

def sign_evidence(wallet):
    msg = hashlib.sha256(b'BitPolito studio: synthetic proof of control, not a transaction').digest()
    spend = int(keys()['spend_priv_key'], 16)
    evidence = []
    for output in wallet:
        private = ((spend + int(output['priv_key_tweak'], 16)) % n).to_bytes(32, 'big').hex()
        signature = schnorr_sign(msg, private)
        valid = PublicKeyXOnly(bytes.fromhex(output['pub_key'])).verify(signature, msg)
        if not valid:
            raise RuntimeError('Independent signature verification failed')
        evidence.append({'pub_key': output['pub_key'], 'message': msg.hex(), 'signature': signature.hex(), 'verified': valid})
    return evidence

def payment(body):
    validate(body, {'preset', 'network', 'inputs', 'recipients', 'amount', 'comparison', 'action'}, 'payment')
    selected = body.get('inputs', [0, 1])
    if not isinstance(selected, list) or not 1 <= len(selected) <= 4 or any(type(i) is not int or i not in range(4) for i in selected) or len(set(selected)) != len(selected):
        raise ExperimentInputError('Select one to four unique input cards')
    comparison = body.get('comparison', 'mutation' if body.get('preset') == 'mutation' else 'changed')
    if comparison not in ('changed', 'reorder', 'amountOnly', 'mutation'):
        raise ExperimentInputError('Unknown comparison')
    action = body.get('action', 'derive')
    if action not in ('derive', 'scan', 'verify'):
        raise ExperimentInputError('Unknown payment action')
    count = integer(body.get('recipients', 1), 1, 2, 'recipient count')
    amount = integer(body.get('amount', 12000), 1, 2100000000000000, 'display amount')
    network = body.get('network', 'testnet')
    vin = [deepcopy(input_cards()[i]) for i in selected]
    changed = deepcopy(vin)
    if comparison == 'reorder':
        changed.reverse()
    elif comparison in ('changed', 'mutation'):
        # Changing the outpoint changes the input hash even with all four cards selected.
        changed[0]['txid'] = '00' * 32
    recipient = addresses(network)[0]
    recipients = [{'address': recipient, 'count': count}]
    outputs = sending_run(vin, recipients)
    after = outputs if comparison == 'amountOnly' else sending_run(changed, recipients)
    result = {'action': action, 'address': recipient, 'inputs': public_vin(vin), 'comparison_inputs': public_vin(changed), 'outputs': outputs, 'comparison_outputs': after,
              'same_outputs': Counter(outputs) == Counter(after), 'amount': amount, 'comparison_amount': amount + 1 if comparison == 'amountOnly' else amount,
              'network': network, 'comparison': comparison, 'recipient_count': count}
    if action in ('scan', 'verify'):
        wallet = scan(public_vin(vin), list(outputs), keys(), [])
        after_wallet = scan(public_vin(changed), list(outputs if comparison == 'mutation' else after), keys(), [])
        result.update(wallet=wallet, comparison_wallet=after_wallet)
        if action == 'verify':
            result['evidence'] = sign_evidence(wallet)
    return result

def execute(tool, body):
    if tool == 'payment':
        result = payment(body)
    elif tool == 'address':
        validate(body, {'preset', 'network', 'address'}, 'address')
        result = inspect_address(body.get('address', addresses(body.get('network', 'testnet'))[0]))
    else:
        raise ExperimentInputError('Unknown experiment')
    return {'computed': True, 'tool': tool, 'result': result, 'provenance': provenance()}
