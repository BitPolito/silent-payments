"""Check a preview without printing generated private keys."""
import argparse
import json
import os
import urllib.request


def smoke(base, revision=None):
    base=base.rstrip('/')
    headers={}
    if os.environ.get('VERCEL_AUTOMATION_BYPASS_SECRET'):
        headers['x-vercel-protection-bypass']=os.environ['VERCEL_AUTOMATION_BYPASS_SECRET']
    def call(path, body=None):
        request=urllib.request.Request(base+path,headers={**headers,'Content-Type':'application/json'},data=None if body is None else json.dumps(body).encode())
        with urllib.request.urlopen(request,timeout=60) as response:
            return json.load(response)
    with urllib.request.urlopen(urllib.request.Request(base,headers=headers),timeout=30) as response:
        assert response.status==200
        assert 'text/html' in response.headers.get('Content-Type', '')
        assert b'id="root"' in response.read()
    health=call('/api/health')
    assert health['ok'] and health['vanity_binary']
    assert health['protocol_version']=='1.1.1'
    if revision: assert health['revision']==revision,health['revision']
    for testnet in (False,True):
        for endpoint,body in [('/api/get_sp_address',{'testnet':testnet}),('/api/vanity_address',{'pattern':'q','testnet':testnet})]:
            result=call(endpoint,body)
            assert result['addresses'][0].startswith('tsp1qq' if testnet else 'sp1qq')
            assert all(len(key)==64 for key in result['key_material'].values())
            assert result['qr_png_base64']
    assert len(call('/api/reference_cases'))==28
    assert call('/api/single_test/send/25')['expected_failure']
    assert call('/api/single_test/receive/18?case_index=1')['test_passed']
    metadata=call('/api/experiments')
    assert set(metadata['tools'])=={'payment','address','labels','scan'}
    for network in ('testnet','mainnet'):
        inspected=call('/api/experiments/address',{'address':metadata['samples'][network]})['result']
        assert inspected['status']=='supported' and inspected['network']==network
        payment=call('/api/experiments/payment',{'network':network,'action':'verify','comparison':'mutation'})['result']
        assert len(payment['wallet'])==1 and payment['comparison_wallet']==[]
        assert all(item['verified'] for item in payment['evidence'])
        labels=call('/api/experiments/labels',{'network':network,'label':1,'known_labels':[]})['result']
        assert labels['wallet']==[]
        batch=call('/api/experiments/scan',{'network':network})['result']
        assert batch['found']==2 and len(batch['transactions'])==6
        assert {tx['status'] for tx in batch['transactions']}=={'found','no_match','skipped','rejected'}
    print('Preview smoke checks passed: frontend, revision, runnable generator, both networks, QR, references and all studio tools')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('url')
    parser.add_argument('--revision')
    args=parser.parse_args()
    smoke(args.url,args.revision)
