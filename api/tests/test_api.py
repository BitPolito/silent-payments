import pytest
import index
from core.utils import vanity_python as vanity

@pytest.fixture
def client():
    return index.app.test_client()

@pytest.mark.parametrize('payload', [None, [], ['q'], {'pattern':123}, {'pattern':'!'}, {'pattern':'q','mode':'bad'}, {'pattern':'q','threads':-1}])
def test_invalid_vanity(client, payload):
    response = client.post('/api/vanity_address', json=payload)
    assert response.status_code == 400
    assert response.json['code'] == 'INVALID_INPUT'
    assert response.headers['Cache-Control'] == 'no-store'

@pytest.mark.parametrize('testnet', [False, True])
def test_generation(client, testnet):
    response = client.post('/api/get_sp_address', json={'testnet':testnet})
    assert response.status_code == 200
    assert response.headers['Cache-Control'] == 'no-store'
    assert all(len(k)==64 for k in response.json['key_material'].values())
    assert response.json['addresses'][0].startswith('tsp1qq' if testnet else 'sp1qq')
    assert response.json['qr_png_base64']

@pytest.mark.parametrize('exc,status,code', [(TimeoutError(),504,'SEARCH_TIMEOUT'),(FileNotFoundError(),503,'GENERATOR_UNAVAILABLE'),(RuntimeError('secret'),500,'INTERNAL_ERROR')])
def test_generator_failures(client, monkeypatch, exc,status,code):
    def fail(*args, **kwargs): raise exc
    monkeypatch.setattr(index,'get_sp_vanity_address', fail)
    response=client.post('/api/vanity_address',json={'pattern':'q'})
    assert response.status_code==status
    assert response.json['code']==code
    assert 'secret' not in response.get_data(as_text=True)

def test_subcases(client):
    assert len(client.get('/api/reference_cases').json)==28
    assert client.get('/api/test_case/18?case_index=1').json['case_counts']['receiving']==2
    assert client.get('/api/single_test/receive/18?case_index=1').json['test_passed']
    for query in ['-1','bad','999']:
        assert client.get('/api/single_test/receive/0?case_index='+query).status_code==400

def test_runtime_limits(monkeypatch):
    monkeypatch.setenv('VERCEL','1')
    monkeypatch.setenv('VANITY_TIMEOUT_SEC','999')
    monkeypatch.setenv('VANITY_MAX_THREADS','999')
    assert vanity.vanity_runtime_limits()['timeout_sec']==50
    assert vanity.vanity_runtime_limits()['max_threads']==2
    monkeypatch.setenv('VANITY_TIMEOUT_SEC','bad')
    assert vanity.vanity_runtime_limits()['timeout_sec']==50

def test_vanity_integration(client):
    if vanity._find_bin() is None: pytest.skip('Rust executable not built')
    for mode,pattern in [('contains','q'),('prefix','g'),('suffix','q')]:
        response=client.post('/api/vanity_address',json={'pattern':pattern,'mode':mode,'testnet':True})
        assert response.status_code==200, response.json
        assert vanity.vanity_matches(response.json['addresses'][0],pattern,mode)

def test_python_fallback_validation_and_deadline():
    with pytest.raises(ValueError,match='Invalid vanity pattern'):
        vanity._python_vanity('!',timeout_sec=0)
    with pytest.raises(ValueError,match='Prefix must begin'):
        vanity._python_vanity('q',mode='prefix',timeout_sec=0)
    with pytest.raises(TimeoutError):
        vanity._python_vanity('q',timeout_sec=0)
    addresses,keys=vanity._python_vanity('q',testnet=True,timeout_sec=5)
    assert addresses[0].startswith('tsp1qq')
    assert all(len(value)==32 for value in keys.values())
