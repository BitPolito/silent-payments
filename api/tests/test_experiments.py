from collections import Counter
import pytest
import index
from core import experiments as exp
from core.utils.segwit_addr import bech32_decode, bech32_encode, convertbits, Encoding

@pytest.fixture
def client():
    return index.app.test_client()

def test_metadata(client):
    response = client.get('/api/experiments')
    assert response.status_code == 200
    assert len(response.json['inputs']) == 4
    assert response.json['provenance']['commit'] == 'c2ac36f48f71615984087fd151f410457edfed72'
    assert 'private_key' not in response.get_data(as_text=True)

@pytest.mark.parametrize('network', ['testnet', 'mainnet'])
@pytest.mark.parametrize('comparison,same', [('changed', False), ('reorder', True), ('amountOnly', True), ('mutation', False)])
def test_payment_roundtrip(client, network, comparison, same):
    response = client.post('/api/experiments/payment', json={'network': network, 'comparison': comparison, 'recipients': 2, 'action': 'verify'})
    assert response.status_code == 200
    result = response.json['result']
    assert result['same_outputs'] == same
    assert len(result['outputs']) == len(result['wallet']) == 2
    assert Counter(row['pub_key'] for row in result['wallet']) == Counter(result['outputs'])
    assert all(row['verified'] for row in result['evidence'])
    assert len(result['comparison_wallet']) == (0 if comparison == 'mutation' else 2)
    assert exp.inspect_address(result['address'])['network'] == network
    assert response.headers['Cache-Control'] == 'no-store'

@pytest.mark.parametrize('payload', [None, [], {'inputs': []}, {'inputs': [0,0]}, {'inputs': [True]}, {'inputs':[0,1,2,3,4]}, {'recipients':3}, {'recipients':True}, {'amount':0}, {'network':'signet'}, {'action':'broadcast'}, {'comparison':'bad'}, {'preset':'bad'}, {'private_key':'secret'}, {'vin':[]}])
def test_invalid_payment_controls(client, payload):
    response = client.post('/api/experiments/payment', json=payload)
    assert response.status_code == 400
    assert set(response.json) == {'error', 'code'}

@pytest.mark.parametrize('selected', [[0],[1],[2],[3],[0,1,2,3]])
def test_input_choices(selected):
    result = exp.payment({'inputs':selected, 'action':'scan'})
    assert len(result['wallet']) == 1
    assert result['same_outputs'] is False

def test_sanitized_error(client, monkeypatch):
    monkeypatch.setattr(exp, 'payment', lambda body: (_ for _ in ()).throw(RuntimeError('secret')))
    response = client.post('/api/experiments/payment', json={})
    assert response.status_code == 500
    assert response.json == {'error':'Internal server error','code':'INTERNAL_ERROR'}

@pytest.mark.parametrize('network',['testnet','mainnet'])
def test_inspector_networks_and_versions(client, network):
    sample = exp.addresses(network)[0]
    result = client.post('/api/experiments/address', json={'address':sample}).json['result']
    assert result['network'] == network
    assert result['status'] == 'supported'
    assert len(result['scan_pub_key']) == len(result['spend_pub_key']) == 66
    hrp, data, _ = bech32_decode(sample)
    for version in [1,30,31]:
        modified = bech32_encode(hrp, [version]+data[1:], Encoding.BECH32M)
        assert exp.inspect_address(modified)['status'] == ('unsupported' if version == 31 else 'forward_compatible')
    assert exp.inspect_address(sample[:-1]+('q' if sample[-1]!='q' else 'p'))['status'] == 'invalid_encoding'
    payload = convertbits(data[1:],5,8,False)
    bad = bech32_encode(hrp,[0]+convertbits(payload+[0],8,5),Encoding.BECH32M)
    assert exp.inspect_address(bad)['status'] == 'invalid_payload'
    future = bech32_encode(hrp,[1]+convertbits(payload+[0],8,5),Encoding.BECH32M)
    assert exp.inspect_address(future)['ignored_extension_bytes'] == 1
    invalid_key = [0]*33+payload[33:]
    assert exp.inspect_address(bech32_encode(hrp,[0]+convertbits(invalid_key,8,5),Encoding.BECH32M))['status'] == 'invalid_payload'

@pytest.mark.parametrize('payload',[{'address':123},{'address':'a'*1024},{'private_key':'secret'}])
def test_address_request_bounds(client,payload):
    assert client.post('/api/experiments/address',json=payload).status_code == 400

def test_oversized_body_and_unknown_tool(client):
    response = client.post('/api/experiments/address', data='x'*9000, content_type='application/json')
    assert response.status_code == 413
    assert set(response.json) == {'error','code'}
    assert client.post('/api/experiments/unknown',json={}).status_code == 400

def test_unexpected_value_error_is_sanitized(client, monkeypatch):
    monkeypatch.setattr(exp, 'payment', lambda body: (_ for _ in ()).throw(ValueError('unexpected secret')))
    response=client.post('/api/experiments/payment',json={})
    assert response.status_code == 500
    assert response.json == {'error':'Internal server error','code':'INTERNAL_ERROR'}

def test_default_outputs_match_pinned_reference():
    result=exp.payment({'network':'mainnet'})
    assert Counter(result['outputs'])==Counter(exp.fixtures()[0]['sending'][0]['expected']['outputs'][0])

def test_invalid_signature_never_reports_success(client,monkeypatch):
    class Reject:
        def __init__(self,*args): pass
        def verify(self,*args): return False
    monkeypatch.setattr(exp,'PublicKeyXOnly',Reject)
    response=client.post('/api/experiments/payment',json={'action':'verify'})
    assert response.status_code==500
    assert response.json['code']=='INTERNAL_ERROR'

@pytest.mark.parametrize('network',['testnet','mainnet'])
@pytest.mark.parametrize('label',[1,2,3])
def test_label_derivation_and_known_labels(client, network, label):
    payload={'network':network,'label':label,'known_labels':[label]}
    result=client.post('/api/experiments/labels',json=payload).json['result']
    assert len(result['addresses'])==4
    assert len({row['scan_pub_key'] for row in result['addresses']})==1
    assert len({row['spend_pub_key'] for row in result['addresses']})==4
    assert len(result['wallet'])==1
    payload['known_labels']=[]
    unknown=client.post('/api/experiments/labels',json=payload).json['result']
    assert unknown['wallet']==[]
    assert unknown['outputs']==result['outputs']

@pytest.mark.parametrize('network',['testnet','mainnet'])
def test_scanning_all_outcomes_and_no_ownership_input(client,network,monkeypatch):
    original=exp.scan
    def scanner(vin,outputs,material,labels):
        assert all('owner' not in item and 'private_key' not in item for item in vin)
        return original(vin,outputs,material,labels)
    monkeypatch.setattr(exp,'scan',scanner)
    result=client.post('/api/experiments/scan',json={'network':network}).json['result']
    assert len(result['transactions'])==6
    assert result['found']==2
    assert [tx['status'] for tx in result['transactions']]==['found','found','no_match','skipped','skipped','rejected']
    unknown=client.post('/api/experiments/scan',json={'network':network,'known_labels':[]}).json['result']
    assert unknown['found']==1
    assert unknown['transactions'][1]['status']=='no_match'

@pytest.mark.parametrize('tool,payload', [('labels',{'label':0}),('labels',{'label':4}),('labels',{'label':True}),('labels',{'known_labels':[1,1]}),('scan',{'known_labels':[1,2,3,4]}),('scan',{'known_labels':[True]}),('scan',{'transactions':[]}),('scan',{'known_labels':'1'}),('labels',{'key_material':{}})])
def test_bounded_label_scan_controls(client,tool,payload):
    response=client.post('/api/experiments/'+tool,json=payload)
    assert response.status_code==400
    assert response.json['code']=='INVALID_INPUT'

def test_unrelated_scanner_failure_never_becomes_educational_rejection(client,monkeypatch):
    original=exp.scan
    def unrelated(vin,outputs,material,labels):
        if vin[0].get('txinwitness')=='0102ff':
            raise ValueError('unrelated secret')
        return original(vin,outputs,material,labels)
    monkeypatch.setattr(exp,'scan',unrelated)
    response=client.post('/api/experiments/scan',json={})
    assert response.status_code==500
    assert response.json['code']=='INTERNAL_ERROR'
    assert 'secret' not in response.get_data(as_text=True)
