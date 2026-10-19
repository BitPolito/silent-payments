import copy
import json
from pathlib import Path
from collections import Counter
import pytest
from core.reference import run_case
from core.receive import generate_sp_address, receiving_run, _parse_witness
from core.send import sending_run
from core.utils.hardened_keys import validate_private_key, generate_private_key
from core.utils.schnorr_lib import n, G, point_mul
from core.utils.utils import decode_silent_payment_address, serP

VECTORS = json.loads((Path(__file__).parents[1] / 'core/test/test_vectors.json').read_text())
CASES = [pytest.param(i, direction, subcase, marks=pytest.mark.slow if i == 27 else (), id=f'{i}-{direction}-{subcase}')
         for i, entry in enumerate(VECTORS) for direction in ('sending', 'receiving')
         for subcase in range(len(entry.get(direction, [])))]

@pytest.mark.parametrize('index,direction,subcase', CASES)
def test_reference(index, direction, subcase, monkeypatch):
    import core.receive as receiver
    from coincurve import PublicKeyXOnly
    message = bytes(range(32))
    monkeypatch.setattr(receiver, 'random_message', lambda: message)
    result = run_case(VECTORS[index], direction, subcase, index)
    assert result['test_passed']
    if direction == 'receiving':
        assert all(PublicKeyXOnly(bytes.fromhex(o['pub_key'])).verify(bytes.fromhex(o['signature']), message) for o in result['outputs'])

@pytest.mark.parametrize('bad', ['00'*32, '01'*64, n.to_bytes(32,'big').hex(), 'xy'*32, b'\x01'*31, -1, None])
def test_reject_invalid_keys(bad):
    with pytest.raises(ValueError):
        validate_private_key(bad)

@pytest.mark.parametrize('network', ['mainnet', 'testnet'])
def test_generated_payment_round_trip(network, monkeypatch):
    import core.receive as receiver
    from coincurve import PublicKeyXOnly
    message = bytes(range(32))
    monkeypatch.setattr(receiver, 'random_message', lambda: message)
    addresses, keys = generate_sp_address(network=network)
    exported = {k: v.hex() for k,v in keys.items()}
    assert generate_sp_address(exported, network=network)[0] == addresses
    scan, spend = decode_silent_payment_address(addresses[0])
    assert scan == serP(point_mul(G, int.from_bytes(keys['scan_priv_key'], 'big')))
    assert spend == serP(point_mul(G, int.from_bytes(keys['spend_priv_key'], 'big')))
    vin = copy.deepcopy(VECTORS[0]['sending'][0]['given']['vin'])
    outputs = sending_run(vin, addresses)
    found_addresses, wallet = receiving_run(vin, outputs, exported, [], network=network)
    assert found_addresses == addresses
    assert Counter(o['pub_key'] for o in wallet) == Counter(outputs)
    assert all(PublicKeyXOnly(bytes.fromhex(o['pub_key'])).verify(bytes.fromhex(o['signature']), message) for o in wallet)

def test_key_rejection_sampling(monkeypatch):
    import core.utils.hardened_keys as keys
    samples = iter([b'\0'*32, n.to_bytes(32,'big'), (1).to_bytes(32,'big')])
    monkeypatch.setattr(keys.secrets, 'token_bytes', lambda size: next(samples))
    assert generate_private_key() == (1).to_bytes(32,'big')

def test_scalar_not_truncated():
    with pytest.raises(ValueError): point_mul(G, 1 << 256)

@pytest.mark.parametrize('data', ['01fd010001', '0102ff', '0000', ''])
def test_malformed_witness(data):
    with pytest.raises(ValueError): _parse_witness(data)

def test_compact_size_witness():
    item = b'\x42'*253
    assert _parse_witness((b'\x01\xfd\xfd\x00'+item).hex()) == [item]

def test_wrong_checksum_encoding():
    from core.utils.segwit_addr import bech32_decode, bech32_encode, Encoding
    address = VECTORS[0]['receiving'][0]['expected']['addresses'][0]
    hrp,data,_ = bech32_decode(address)
    with pytest.raises(ValueError): decode_silent_payment_address(bech32_encode(hrp,data,Encoding.BECH32))

def test_exact_outputs_detect_extra(monkeypatch):
    import core.reference as reference
    original = reference.receiving_run
    def extra(*args, **kwargs):
        addresses, wallet = original(*args, **kwargs)
        return addresses, wallet + wallet
    monkeypatch.setattr(reference, 'receiving_run', extra)
    assert not run_case(VECTORS[0], 'receiving', test_id=0)['test_passed']

def test_unrelated_failure_never_passes(monkeypatch):
    import core.reference as reference
    monkeypatch.setattr(reference, 'sending_run', lambda *a: (_ for _ in ()).throw(ValueError('wrong failure')))
    with pytest.raises(ValueError, match='wrong failure'):
        run_case(VECTORS[25], 'sending', test_id=25)

@pytest.mark.parametrize('scalar', [0, n, n+1])
@pytest.mark.parametrize('module_name', ['core.send','core.receive'])
def test_invalid_input_hash(monkeypatch, scalar, module_name):
    import importlib
    module=importlib.import_module(module_name)
    monkeypatch.setattr(module,'get_input_hash', lambda *args: scalar.to_bytes(32,'big'))
    given=copy.deepcopy(VECTORS[0]['sending' if module_name=='core.send' else 'receiving'][0]['given'])
    with pytest.raises(ValueError, match='Invalid input hash scalar'):
        if module_name=='core.send': module.sending_run(given['vin'],given['recipients'])
        else: module.receiving_run(given['vin'],given['outputs'],given['key_material'],given['labels'])

@pytest.mark.parametrize('scalar',[0,n,n+1])
def test_invalid_shared_secret_tweak(monkeypatch,scalar):
    import core.utils.utils as utils
    import core.send as sender
    monkeypatch.setattr(utils,'tagged_hash',lambda *args:scalar.to_bytes(32,'big'))
    with pytest.raises(ValueError,match='tweak not valid'): utils.create_tweak(G,0)
    monkeypatch.undo()
    original=sender.tagged_hash
    monkeypatch.setattr(sender,'tagged_hash',lambda tag,msg:scalar.to_bytes(32,'big') if tag=='BIP0352/SharedSecret' else original(tag,msg))
    given=copy.deepcopy(VECTORS[0]['sending'][0]['given'])
    with pytest.raises(ValueError,match='wrong tweak'): sender.sending_run(given['vin'],given['recipients'])

def test_group_limit_applies_to_sum_of_counts():
    from core.errors import RecipientLimitExceeded
    from core.send import create_sp_groups
    recipient=VECTORS[0]['sending'][0]['given']['recipients'][0]
    with pytest.raises(RecipientLimitExceeded): create_sp_groups([{**recipient,'count':2323},recipient])
    assert len(next(iter(create_sp_groups([{**recipient,'count':2323}]).values())))==2323

def test_taproot_script_path_uses_output_key_and_skips_nums():
    from core.receive import _pubkey_point_from_input, NUMS_BYTES
    from core.utils.schnorr_lib import lift_x_even_y
    tx=copy.deepcopy(VECTORS[6]['receiving'][0]['given']['vin'][0])
    internal=serP(point_mul(G,7))[1:]
    tx['txinwitness']=['51',(b'\xc0'+internal).hex()]
    expected=lift_x_even_y(bytes.fromhex(tx['prevout']['scriptPubKey']['hex'][4:]))
    assert _pubkey_point_from_input(tx)==expected
    tx['txinwitness']=['51',(b'\xc0'+NUMS_BYTES).hex()]
    assert _pubkey_point_from_input(tx) is None

def test_future_witness_input_skips_whole_transaction():
    given=copy.deepcopy(VECTORS[0]['receiving'][0]['given'])
    vin=given['vin']+[{'prevout':{'scriptPubKey':{'hex':'5220'+'00'*32}}}]
    assert receiving_run(vin,given['outputs'],given['key_material'],given['labels'])[1]==[]
    with pytest.raises(ValueError,match='Unsupported witness'):
        sending_run(vin,[])

@pytest.mark.parametrize('version',[1,16,30])
def test_forward_compatible_address(version):
    from core.utils.segwit_addr import bech32_decode,bech32_encode,convertbits,Encoding
    base=VECTORS[0]['receiving'][0]['expected']['addresses'][0]
    scan,spend=decode_silent_payment_address(base)
    address=bech32_encode('sp',[version]+convertbits(scan+spend+b'extension',8,5),Encoding.BECH32M)
    assert decode_silent_payment_address(address)==(scan,spend)

def test_reserved_version_rejected():
    from core.utils.segwit_addr import bech32_decode,bech32_encode,Encoding
    base=VECTORS[0]['receiving'][0]['expected']['addresses'][0]
    hrp,data,_=bech32_decode(base)
    with pytest.raises(ValueError): decode_silent_payment_address(bech32_encode(hrp,[31]+data[1:],Encoding.BECH32M))


@pytest.mark.parametrize('fixture', json.loads((Path(__file__).parents[1] / 'core/test/key_vectors.json').read_text()))
def test_shared_encoding_fixture(fixture):
    keys={key:fixture[key] for key in ('scan_priv_key','spend_priv_key')}
    assert generate_sp_address(keys,network=fixture['network'])[0]==[fixture['address']]

@pytest.mark.parametrize('opcode,width',[(0x4c,1),(0x4d,2),(0x4e,4)])
def test_p2pkh_public_key_push_encodings(opcode,width):
    from core.receive import _pubkey_point_from_input
    from core.utils.schnorr_lib import point_from_bytes
    tx=copy.deepcopy(next(v for v in VECTORS[0]['receiving'][0]['given']['vin'] if v['prevout']['scriptPubKey']['hex'].startswith('76a914')))
    expected=_pubkey_point_from_input(tx)
    key=serP(expected)
    unrelated=serP(point_mul(G,7))
    # A preceding unrelated compressed key must not shadow the key whose hash is spent.
    tx['scriptSig']=(bytes([33])+unrelated+bytes([0x75,opcode])+len(key).to_bytes(width,'little')+key).hex()
    assert _pubkey_point_from_input(tx)==expected


def test_list_witness_preserves_empty_stack_items():
    assert _parse_witness(['','51']) == [b'',b'\x51']
    assert _parse_witness('02000151') == [b'',b'\x51']
