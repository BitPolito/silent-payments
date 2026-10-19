import os
import sys

# 1. Aggiungi la cartella 'api' ai percorsi dove Python cerca i moduli
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)


from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
import json
from core.http_helpers import cors_allowed_origins
from core.receive import generate_sp_address
from core.utils.vanity_python import (
	_find_bin,
	get_sp_vanity_address,
	normalize_vanity_mode,
	qr_png_base64,
	vanity_pattern_error,
	vanity_runtime_limits,
)
from core.reference import run_case
from werkzeug.exceptions import HTTPException
import subprocess
import time

app = Flask(__name__)
_cors_origins = cors_allowed_origins()
if os.environ.get('VERCEL'):
	CORS(app, origins=_cors_origins, supports_credentials=False)
else:
	CORS(app)

@app.after_request
def private_responses(response):
    if request.path.startswith(('/api/get_sp_address', '/api/vanity_address', '/api/test_case', '/api/single_test')):
        response.headers['Cache-Control'] = 'no-store'
    return response


@app.errorhandler(Exception)
def api_error(exc):
    if isinstance(exc, HTTPException):
        status, code, message = exc.code, 'HTTP_ERROR', exc.description
    elif isinstance(exc, (TimeoutError, subprocess.TimeoutExpired)):
        status, code, message = 504, 'SEARCH_TIMEOUT', 'Vanity search timed out'
    elif isinstance(exc, (FileNotFoundError, PermissionError)):
        status, code, message = 503, 'GENERATOR_UNAVAILABLE', 'Vanity generator is unavailable'
    elif isinstance(exc, ValueError):
        status, code, message = 400, 'INVALID_INPUT', str(exc)
    else:
        status, code, message = 500, 'INTERNAL_ERROR', 'Internal server error'
    return jsonify({'error': message, 'code': code}), status


def json_body():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise ValueError('A JSON object is required')
    return body


def case_index():
    try:
        index = int(request.args.get('case_index', '0'))
    except ValueError:
        raise ValueError('Invalid case_index')
    if index < 0:
        raise ValueError('Invalid case_index')
    return index


TEST_FILE = "test_vectors.json"
TEST_LIST = "test_list.json"

def load_json_arg(arg):
	if arg is None:
		return None
	try:
		with open(arg, 'r', encoding='utf-8') as f:
			return json.load(f)
	except (FileNotFoundError, OSError):
		return json.loads(arg)

@app.route('/', methods=['GET'])
def index():
	return jsonify({"message": "Hello, World!"})


@app.route('/api/health', methods=['GET'])
def api_health():
	build_info_path = os.path.join(current_dir, 'build-info.json')
	build_info = load_json_arg(build_info_path) if os.path.exists(build_info_path) else {}
	limits = vanity_runtime_limits()
	return jsonify({
		"ok": True,
		"service": "silent-payments",
		"vanity_max_pattern": limits['max_pattern_len'],
		"vanity_timeout_sec": limits['timeout_sec'],
		"vanity_max_threads": limits['max_threads'],
		"vanity_environment": limits['environment'],
		"vanity_binary": _find_bin() is not None,
        "revision": build_info.get("revision", os.environ.get("VERCEL_GIT_COMMIT_SHA", os.environ.get("APP_REVISION", "local"))),
        "protocol_version": "1.1.1",
	})


@app.route('/api/vanity_limits', methods=['GET'])
def vanity_limits_route():
	limits = vanity_runtime_limits()
	return jsonify(limits)

def _load_test_vectors():
	base_dir = os.path.dirname(os.path.abspath(__file__))
	json_path = os.path.join(base_dir, 'core', 'test', TEST_FILE)
	return load_json_arg(json_path)

def _load_test_list_labels():
	base_dir = os.path.dirname(os.path.abspath(__file__))
	json_path = os.path.join(base_dir, 'core', 'test', TEST_LIST)
	with open(json_path, 'r', encoding='utf-8') as f:
		data = json.load(f)
	return data.get('TEST LIST', [])

def _vin_summary(vin_list):
	items = []
	for v in vin_list or []:
		prevout = v.get('prevout') or {}
		spk = prevout.get('scriptPubKey') or {}
		items.append({
			'txid': v.get('txid', ''),
			'vout': v.get('vout', 0),
			'script_pubkey': spk.get('hex', ''),
			'has_sender_key': 'private_key' in v,
		})
	return items

def _flatten_send_expected(outputs_sets):
	if not outputs_sets:
		return []
	first = outputs_sets[0]
	if isinstance(first, list):
		return first
	return list(outputs_sets)

def _story_for_entry(entry, index=0):
	has_send = len(entry.get('sending', [])) > index
	has_recv = len(entry.get('receiving', [])) > index
	if not has_send and not has_recv:
		return {'kind': 'empty', 'send_outputs': [], 'receive_tx_outputs': []}

	send_outputs = []
	recv_outputs = []
	if has_send:
		expected = entry['sending'][index].get('expected') or {}
		send_outputs = _flatten_send_expected(expected.get('outputs') or [])
	if has_recv:
		given = entry['receiving'][index].get('given') or {}
		recv_outputs = list(given.get('outputs') or [])

	if not has_send:
		return {'kind': 'receive_only', 'send_outputs': [], 'receive_tx_outputs': recv_outputs}
	if not has_recv:
		return {'kind': 'send_only', 'send_outputs': send_outputs, 'receive_tx_outputs': []}

	# BIP-352 vectors: receive usually scans the tx that includes send-derived pubkeys.
	if send_outputs == []:
		kind = 'no_send_outputs'
	elif all(o in recv_outputs for o in send_outputs):
		extra = [o for o in recv_outputs if o not in send_outputs]
		kind = 'extra_tx_outputs' if extra else 'linked'
	else:
		kind = 'decoupled'

	zero_key = (
		kind == 'no_send_outputs'
		and recv_outputs == ['0000000000000000000000000000000000000000000000000000000000000000']
	)
	if zero_key:
		kind = 'zero_key_sum'

	return {
		'kind': kind,
		'send_outputs': send_outputs,
		'receive_tx_outputs': recv_outputs,
		'shared_transaction': True,
	}

@app.route('/api/test_case/<int:test_id>', methods=['GET'])
def get_test_case(test_id: int):
	try:
		vectors = _load_test_vectors()
		labels = _load_test_list_labels()
		if vectors is None or test_id < 0 or test_id >= len(vectors):
			return jsonify({'error': 'Invalid test id', 'code': 'NOT_FOUND'}), 404

		entry = vectors[test_id]
		if case_index() >= max(len(entry.get('sending', [])), len(entry.get('receiving', []))):
			raise ValueError('Invalid case_index')
		title = labels[test_id] if test_id < len(labels) else entry.get('comment', f'Test {test_id}')

		payload = {
			'id': test_id,
			'title': title,
			'comment': entry.get('comment', ''),
            'case_counts': {direction: len(entry.get(direction, [])) for direction in ('sending', 'receiving')},
			'story': _story_for_entry(entry, case_index()),
		}

		if len(entry.get('sending', [])) > case_index():
			sending = entry['sending'][case_index()]
			given = sending.get('given') or {}
			expected = sending.get('expected') or {}
			payload['sending'] = {
				'vin': _vin_summary(given.get('vin')),
				'recipients': [r['address'] if isinstance(r, dict) else r for r in given.get('recipients', [])],
				'expected_output_sets': expected.get('outputs') or [],
			}

		if len(entry.get('receiving', [])) > case_index():
			receiving = entry['receiving'][case_index()]
			given = receiving.get('given') or {}
			expected = receiving.get('expected') or {}
			km = given.get('key_material') or {}
			payload['receiving'] = {
				'vin': _vin_summary(given.get('vin')),
				'outputs': given.get('outputs') or [],
				'labels': given.get('labels') or [],
				'scan_priv_key': km.get('scan_priv_key', ''),
				'spend_priv_key': km.get('spend_priv_key', ''),
				'expected_addresses': expected.get('addresses') or [],
				'expected_outputs': expected.get('outputs') or [],
			}

		return jsonify(payload)
	except Exception as e:
		return api_error(e)

@app.route('/api/get_all_tests', methods=['GET'])
def get_all_tests():
	try:
		base_dir = os.path.dirname(os.path.abspath(__file__))
		json_path = os.path.join(base_dir, 'core', 'test', TEST_LIST)
		with open(json_path, 'r', encoding='utf-8') as f:
			test_list_data = json.load(f)
		return jsonify(test_list_data)
	except Exception as e:
		return api_error(e)

@app.route('/api/reference_cases', methods=['GET'])
def reference_cases():
    return jsonify([{'id': i, 'comment': e['comment'],
                     'case_counts': {d: len(e.get(d, [])) for d in ('sending', 'receiving')}}
                    for i, e in enumerate(_load_test_vectors())])


@app.route('/api/single_test/<direction>/<int:test_id>', methods=['GET'])
def single_test(direction, test_id):
    kind = {'send': 'sending', 'receive': 'receiving'}.get(direction)
    vectors = _load_test_vectors()
    if kind is None or test_id >= len(vectors):
        return jsonify({'error': 'Invalid test id or direction', 'code': 'NOT_FOUND'}), 404
    entry = vectors[test_id]
    index = case_index()
    if index >= len(entry.get(kind, [])):
        raise ValueError('Invalid case_index')
    return jsonify(run_case(entry, kind, index, test_id))


def _parse_testnet_flag(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ('1', 'true', 'yes'):
            return True
        if normalized in ('', '0', 'false', 'no'):
            return False
    raise ValueError('testnet must be a boolean')


def _serialize_key_material(key_material):
	if not key_material:
		return key_material
	out = {}
	for key, value in key_material.items():
		if isinstance(value, bytes):
			out[key] = value.hex()
		else:
			out[key] = value
	return out

def _run_vanity_response(pattern, mode, testnet, threads=0):
    if not isinstance(pattern, str):
        raise ValueError('Pattern must be a string')
    pattern = pattern.strip().lower()
    error = vanity_pattern_error(pattern)
    if error:
        raise ValueError(error)
    mode = normalize_vanity_mode(mode)
    if isinstance(threads, bool) or not isinstance(threads, int) or threads < 0:
        raise ValueError('Threads must be a nonnegative integer')
    start = time.perf_counter()
    addresses, keys = get_sp_vanity_address(pattern, mode, threads, testnet)
    if not addresses:
        raise RuntimeError('Invalid generator result')
    return jsonify({'message': 'Vanity address generated successfully', 'addresses': addresses,
                    'key_material': _serialize_key_material(keys), 'elapsed': time.perf_counter() - start,
                    'network': 'testnet' if testnet else 'mainnet', 'qr_png_base64': qr_png_base64(addresses[0])})


@app.route('/api/vanity_address', methods=['POST'])
def vanity_address_post():
    body = json_body()
    return _run_vanity_response(body.get('pattern'), body.get('mode', 'contains'),
                               _parse_testnet_flag(body.get('testnet', False)), body.get('threads', 0))


@app.route('/api/vanity_address/<string:pattern>/<string:mode>/<int:threads>/<int:testnet>/<int:force_python>', methods=['GET'])
def vanity_address(pattern, mode, threads, testnet, force_python):
    return _run_vanity_response(pattern, mode, bool(testnet), threads)


@app.route('/api/get_sp_address', methods=['GET', 'POST'])
def get_sp_address():
    body = json_body() if request.method == 'POST' else request.args
    testnet = _parse_testnet_flag(body.get('testnet', False))
    network = 'testnet' if testnet else 'mainnet'
    start = time.perf_counter()
    addresses, keys = generate_sp_address(network=network, qr_code=False)
    return jsonify({'message': 'SP address generated successfully', 'addresses': addresses,
                    'key_material': _serialize_key_material(keys), 'elapsed': time.perf_counter() - start,
                    'network': network, 'qr_png_base64': qr_png_base64(addresses[0])})


@app.route('/api/qr_code', methods=['GET'])
def qr_code():
	"""Legacy: prefer qr_png_base64 from generate endpoints. Optional ?address=sp1..."""
	try:
		addr = request.args.get('address', '').strip()
		if addr:
			from core.utils.utils import decode_silent_payment_address
			decode_silent_payment_address(addr)
			from io import BytesIO
			from core.utils.vanity_python import _qr_image
			buf = BytesIO()
			_qr_image(addr).save(buf, format='PNG')
			buf.seek(0)
			return send_file(
				buf,
				mimetype='image/png',
				as_attachment=True,
				download_name='silent_payment_qr.png',
			)
		raise ValueError('address query parameter is required')
	except Exception as e:
		return api_error(e)