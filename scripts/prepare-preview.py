"""Package a reviewed source tree and freshly built Linux binary, never the local api/bin file."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def prepare(binary, output, allow_dirty=False):
    binary, output = Path(binary).resolve(), Path(output).resolve()
    if output.exists() or output == ROOT or ROOT in output.parents and output.name != '.preview-stage':
        raise ValueError('Use a new output directory (or .preview-stage)')
    dirty = bool(subprocess.check_output(['git','status','--porcelain'], cwd=ROOT).strip())
    if dirty and not allow_dirty:
        raise ValueError('Commit reviewed changes before packaging (use --allow-dirty for local verification only)')
    if subprocess.check_output([str(binary),'--self-test'], text=True, timeout=5).strip() != 'vanity: ok':
        raise ValueError('Generator self-test failed')
    revision = subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip() + ('-dirty' if dirty else '')
    output.mkdir(parents=True)
    files = ['package.json','package-lock.json','index.html','vite.config.js','tailwind.config.js','postcss.config.js','vercel.json','.python-version']
    for file in files:
        shutil.copy2(ROOT/file,output/file)
    for directory in ['src','public','api/core']:
        shutil.copytree(ROOT/directory,output/directory,ignore=shutil.ignore_patterns('__pycache__','*.ipynb','*.pyc'))
    for file in ['index.py','requirements.txt']:
        shutil.copy2(ROOT/'api'/file,output/'api'/file)
    target=output/'api/bin/vanity'
    target.parent.mkdir()
    shutil.copy2(binary,target)
    target.chmod(0o755)
    info={'revision':revision,'binary_sha256':hashlib.sha256(target.read_bytes()).hexdigest()}
    (output/'api/build-info.json').write_text(json.dumps(info,indent=2)+'\n')
    print(str(output))
    return info

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',required=True)
    parser.add_argument('--output',required=True)
    parser.add_argument('--allow-dirty',action='store_true')
    args=parser.parse_args()
    prepare(args.binary,args.output,args.allow_dirty)
