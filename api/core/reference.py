"""Exact, noninteractive execution of the pinned BIP-352 reference cases."""
from collections import Counter
from copy import deepcopy
from core.errors import ZeroKeySum, RecipientLimitExceeded
from core.send import sending_run
from core.receive import receiving_run
from core.utils.schnorr_lib import n, tagged_hash
from core.utils.utils import generate_label, ser32

EXPECTED_FAILURES = {25: (ZeroKeySum, 'zero key sum'), 27: (RecipientLimitExceeded, 'recipient limit')}


def run_case(entry, direction, case_index=0, test_id=None):
    case = deepcopy(entry[direction][case_index])
    given, expected = case['given'], case['expected']
    result = {'test_id': test_id, 'case_index': case_index, 'expected_failure': False}
    if direction == 'sending':
        failure = EXPECTED_FAILURES.get(test_id)
        try:
            outputs = sending_run(given['vin'], given['recipients'])
        except (ZeroKeySum, RecipientLimitExceeded) as exc:
            if failure is None or type(exc) is not failure[0] or expected['outputs'] != [[]]:
                raise
            return {**result, 'outputs': [], 'expected_outputs': [], 'test_passed': True,
                    'expected_failure': True, 'note': failure[1]}
        allowed = expected['outputs']
        match = next((e for e in allowed if Counter(e) == Counter(outputs)), None)
        return {**result, 'outputs': outputs, 'expected_outputs': match if match is not None else allowed,
                'test_passed': failure is None and match is not None}
    addresses, wallet = receiving_run(given['vin'], given['outputs'], given['key_material'], given.get('labels'))
    expected_outputs = expected.get('outputs')
    if expected_outputs is None:
        # Upstream compact vector: the first K_max outputs all use change label 0.
        label = int.from_bytes(generate_label(bytes.fromhex(given['key_material']['scan_priv_key']), 0), 'big')
        secret = bytes.fromhex(expected['shared_secret'])
        expected_outputs = [
            {'pub_key': output, 'priv_key_tweak': ((int.from_bytes(tagged_hash('BIP0352/SharedSecret', secret + ser32(k)), 'big') + label) % n).to_bytes(32, 'big').hex()}
            for k, output in enumerate(given['outputs'][:expected['n_outputs']])
        ]
    project = lambda items: Counter((o['pub_key'], o['priv_key_tweak']) for o in items)
    return {**result, 'addresses': addresses, 'outputs': wallet,
            'expected_addresses': expected['addresses'], 'expected_outputs': expected_outputs,
            'test_passed': addresses == expected['addresses'] and project(wallet) == project(expected_outputs)}
