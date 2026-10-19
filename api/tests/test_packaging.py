"""Exercise the isolated runtime layout without a Vercel account."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import pytest

ROOT=Path(__file__).resolve().parents[2]

@pytest.mark.parametrize('relative_binary', ['api/vanity/target/debug/vanity', 'api/vanity/target/x86_64-unknown-linux-musl/release/vanity'])
def test_isolated_runtime(tmp_path, relative_binary):
    binary=ROOT/relative_binary
    if not binary.is_file(): pytest.skip('Build Rust before packaging tests')
    spec=importlib.util.spec_from_file_location('preview_packaging',ROOT/'scripts/prepare-preview.py')
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    stage=tmp_path/'preview'
    info=module.prepare(binary,stage,allow_dirty=True)
    assert not (stage/'api/vanity').exists()
    assert not (stage/'api/tests').exists()
    assert (stage/'api/bin/vanity').stat().st_mode & 0o111
    code='''import sys,os,json
sys.path.insert(0,sys.argv[1])
os.environ['VERCEL']='1'
from index import app
c=app.test_client()
h=c.get('/api/health').json
assert h['vanity_binary'],h
assert h['revision']==sys.argv[2]
r=c.post('/api/vanity_address',json={'pattern':'q','testnet':True})
assert r.status_code==200,r.json
assert r.json['addresses'][0].startswith('tsp1qq')
print(json.dumps({'ok':True}))
'''
    result=subprocess.run([sys.executable,'-c',code,str(stage/'api'),info['revision']],capture_output=True,text=True,timeout=20,cwd=stage)
    assert result.returncode==0,result.stderr
    assert json.loads(result.stdout)['ok']
