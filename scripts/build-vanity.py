"""Build the Vercel Linux generator from source, or validate an isolated prebuilt package."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tomllib
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
TARGET = 'x86_64-unknown-linux-gnu'


def self_test(binary):
    result = subprocess.check_output([str(binary), '--self-test'], text=True, timeout=5)
    if result.strip() != 'vanity: ok':
        raise ValueError('Generator self-test failed')


def build():
    binary = ROOT / 'api/bin/vanity'
    receipt = ROOT / 'api/build-info.json'
    manifest = ROOT / 'native/vanity/Cargo.toml'
    if not manifest.is_file():
        # The optional preview workflow packages a self-contained musl executable.
        if not binary.is_file() or not receipt.is_file():
            raise ValueError('Rust source or a verified prebuilt generator is required')
        info = json.loads(receipt.read_text())
        if hashlib.sha256(binary.read_bytes()).hexdigest() != info['binary_sha256']:
            raise ValueError('Prebuilt generator checksum mismatch')
        self_test(binary)
        print('Verified packaged vanity generator')
        return
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('Vercel source builds require Linux x86_64; use npm run build for the frontend locally')
    version = tomllib.loads((ROOT / 'rust-toolchain.toml').read_text())['toolchain']['channel']
    env = os.environ.copy()
    cargo = shutil.which('cargo')
    rustup = shutil.which('rustup')
    if not cargo or not rustup:
        # Keep build tools outside the function source tree and pin the Rust toolchain.
        tools = ROOT / '.cache' / 'rust-build'
        tools.mkdir(parents=True, exist_ok=True)
        env['CARGO_HOME'] = str(tools / 'cargo')
        env['RUSTUP_HOME'] = str(tools / 'rustup')
        cargo = str(tools / 'cargo/bin/cargo')
        if not Path(cargo).is_file():
            url = 'https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init'
            installer = tools / 'rustup-init'
            with urllib.request.urlopen(url, timeout=60) as response:
                content = response.read()
            with urllib.request.urlopen(url + '.sha256', timeout=30) as response:
                expected = response.read().decode().split()[0]
            if hashlib.sha256(content).hexdigest() != expected:
                raise ValueError('Rustup installer checksum mismatch')
            installer.write_bytes(content)
            installer.chmod(0o755)
            subprocess.run([str(installer), '-y', '--no-modify-path', '--profile', 'minimal',
                            '--default-toolchain', version], env=env, check=True, cwd=ROOT)
    env['PATH'] = str(Path(cargo).parent) + os.pathsep + env.get('PATH', '')
    subprocess.run([cargo, '+' + version, 'build', '--locked', '--release', '--bin', 'vanity',
                    '--target', TARGET, '--manifest-path', str(manifest)], env=env, check=True, cwd=ROOT)
    output_root = Path(env.get('CARGO_TARGET_DIR', ROOT / 'native/vanity/target'))
    if not output_root.is_absolute():
        output_root = ROOT / output_root
    compiled = output_root / TARGET / 'release/vanity'
    self_test(compiled)
    binary.parent.mkdir(parents=True, exist_ok=True)
    temporary = binary.with_suffix('.building')
    shutil.copy2(compiled, temporary)
    temporary.chmod(0o755)
    temporary.replace(binary)
    revision = env.get('VERCEL_GIT_COMMIT_SHA') or env.get('APP_REVISION')
    if not revision:
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        if subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT).strip():
            revision += '-dirty'
    receipt.write_text(json.dumps({'revision': revision, 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}, indent=2) + '\n')
    print('Built and verified Linux vanity generator for revision ' + revision)


if __name__ == '__main__':
    build()
