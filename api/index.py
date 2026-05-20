import os
import sys

# 1. Aggiungi la cartella 'api' ai percorsi dove Python cerca i moduli
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)


from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
import json
from core.http_helpers import cors_allowed_origins, public_error_message
from core.send import sending_run
from core.receive import receiving_run, generate_sp_address
from core.utils.vanity_python import (
	_find_bin,
	get_sp_vanity_address,
	is_vercel_runtime,
	normalize_vanity_mode,
	qr_png_base64,
	vanity_pattern_error,
	vanity_runtime_limits,
)
from collections import Counter
import time

app = Flask(__name__)
_cors_origins = cors_allowed_origins()
if os.environ.get('VERCEL'):
	CORS(app, origins=_cors_origins if _cors_origins else None, supports_credentials=False)
else:
	CORS(app)

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
	limits = vanity_runtime_limits()
	return jsonify({
		"ok": True,
		"service": "silent-payments",
		"vanity_max_pattern": limits['max_pattern_len'],
		"vanity_timeout_sec": limits['timeout_sec'],
		"vanity_max_threads": limits['max_threads'],
		"vanity_environment": limits['environment'],
		"vanity_binary": _find_bin() is not None,
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

def _story_for_entry(entry):
	has_send = bool(entry.get('sending'))
	has_recv = bool(entry.get('receiving'))
	if not has_send and not has_recv:
		return {'kind': 'empty', 'send_outputs': [], 'receive_tx_outputs': []}

	send_outputs = []
	recv_outputs = []
	if has_send:
		expected = entry['sending'][0].get('expected') or {}
		send_outputs = _flatten_send_expected(expected.get('outputs') or [])
	if has_recv:
		given = entry['receiving'][0].get('given') or {}
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
			return jsonify({'error': 'Invalid test id'}), 404

		entry = vectors[test_id]
		title = labels[test_id] if test_id < len(labels) else entry.get('comment', f'Test {test_id}')

		payload = {
			'id': test_id,
			'title': title,
			'comment': entry.get('comment', ''),
			'story': _story_for_entry(entry),
		}

		if entry.get('sending'):
			sending = entry['sending'][0]
			given = sending.get('given') or {}
			expected = sending.get('expected') or {}
			payload['sending'] = {
				'vin': _vin_summary(given.get('vin')),
				'recipients': given.get('recipients') or [],
				'expected_output_sets': expected.get('outputs') or [],
			}

		if entry.get('receiving'):
			receiving = entry['receiving'][0]
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
		return jsonify({'error': public_error_message(e)}), 500

@app.route('/api/get_all_tests', methods=['GET'])
def get_all_tests():
	try:
		base_dir = os.path.dirname(os.path.abspath(__file__))
		json_path = os.path.join(base_dir, 'core', 'test', TEST_LIST)
		with open(json_path, 'r', encoding='utf-8') as f:
			test_list_data = json.load(f)
		return jsonify(test_list_data)
	except Exception as e:
		return jsonify({"error": public_error_message(e)}), 500

@app.route('/api/single_test/send/<int:test_id>', methods=['GET'])
def single_test_send(test_id: int):
	try:
		data = _load_test_vectors()
		if data is None or test_id < 0 or test_id >= len(data):
			return jsonify({'error': 'Invalid test id', 'test_passed': False, 'test_id': test_id}), 404

		entry = data[test_id]
		if not entry.get('sending'):
			return jsonify({'error': 'No sending scenario for this test', 'test_passed': False, 'test_id': test_id}), 400

		sending = entry['sending'][0]
		sending_details = sending['given']
		expected_sending = sending['expected']

		vin = sending_details['vin']
		recipients = sending_details['recipients']
		expected_outputs_sets = expected_sending['outputs']

		try:
			outputs = sending_run(vin, recipients)
		except Exception as e:
			if isinstance(e, ValueError) and 'zero key sum' in str(e):
				return jsonify({
					'expected_outputs': expected_outputs_sets,
					'outputs': [],
					'test_passed': True,
					'test_id': test_id,
					'note': 'zero key sum',
				})
			return jsonify({
				'error': public_error_message(e),
				'expected_outputs': expected_outputs_sets,
				'outputs': [],
				'test_passed': False,
				'test_id': test_id,
			})

		right_expected_outputs = None
		for expected_set in expected_outputs_sets:
			if Counter(outputs) == Counter(expected_set):
				right_expected_outputs = expected_set
				break

		if right_expected_outputs is None:
			return jsonify({
				'error': 'Outputs do not match any expected set.',
				'expected_outputs': expected_outputs_sets,
				'outputs': outputs,
				'test_passed': False,
				'test_id': test_id,
			})

		aligned_outputs = []
		for expected_output in right_expected_outputs:
			for output in outputs:
				if output == expected_output:
					aligned_outputs.append(output)
					break

		return jsonify({
			'expected_outputs': right_expected_outputs,
			'outputs': aligned_outputs,
			'test_passed': True,
			'test_id': test_id,
		})
	except Exception as e:
		return jsonify({'error': public_error_message(e), 'test_passed': False, 'test_id': test_id}), 500

@app.route('/api/single_test/receive/<int:test_id>', methods=['GET'])
def single_test_receive(test_id: int):
	try:
		data = _load_test_vectors()
		if data is None or test_id < 0 or test_id >= len(data):
			return jsonify({'error': 'Invalid test id', 'test_passed': False, 'test_id': test_id}), 404

		entry = data[test_id]
		if not entry.get('receiving'):
			return jsonify({'error': 'No receiving scenario for this test', 'test_passed': False, 'test_id': test_id}), 400

		receiving = entry['receiving'][0]
		receiving_details = receiving['given']
		expected_receiving = receiving['expected']

		vin = receiving_details['vin']
		outputs = receiving_details['outputs']
		key_material = receiving_details['key_material']
		labels = receiving_details['labels']

		addresses, wallet = receiving_run(vin, outputs, key_material, labels)

		expected_addresses = expected_receiving['addresses']
		expected_outputs = expected_receiving['outputs']

		addresses_ok = addresses == expected_addresses
		outputs_ok = all(
			any(
				w['pub_key'] == e['pub_key'] and w['priv_key_tweak'] == e['priv_key_tweak']
				for w in wallet
			)
			for e in expected_outputs
		)

		aligned_wallet = []
		for expected_output in expected_outputs:
			for output in wallet:
				if (
					output['pub_key'] == expected_output['pub_key']
					and output['priv_key_tweak'] == expected_output['priv_key_tweak']
				):
					aligned_wallet.append(output)
					break

		return jsonify({
			'expected_addresses': expected_addresses,
			'addresses': addresses,
			'expected_outputs': expected_outputs,
			'outputs': aligned_wallet,
			'test_passed': addresses_ok and outputs_ok,
			'test_id': test_id,
		})
	except Exception as e:
		return jsonify({'error': public_error_message(e), 'test_passed': False, 'test_id': test_id}), 500

def _parse_testnet_flag(value) -> bool:
	if value is True:
		return True
	if isinstance(value, int):
		return value != 0
	if isinstance(value, str):
		return value.strip().lower() in ('1', 'true', 'yes')
	return False


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

def _run_vanity(pattern: str, mode: str, testnet: int, threads: int = 0):
	pattern = pattern.strip().lower()
	err = vanity_pattern_error(pattern)
	if err:
		return None, None, err
	mode = normalize_vanity_mode(mode)
	if is_vercel_runtime():
		threads = 0
	try:
		threads = int(threads)
	except (TypeError, ValueError):
		threads = 0
	t0 = time.perf_counter()
	addresses, key_material = get_sp_vanity_address(
		vanity_string=pattern,
		mode=mode,
		testnet=bool(testnet),
		num_threads=threads,
	)
	if not addresses:
		limits = vanity_runtime_limits()
		return None, None, (
			f'Vanity search failed or timed out (max {limits["max_pattern_len"]} chars on {limits["environment"]})'
		)
	elapsed = time.perf_counter() - t0
	return addresses, key_material, elapsed


@app.route('/api/vanity_address', methods=['POST'])
def vanity_address_post():
	body = request.get_json(silent=True) or {}
	pattern = (body.get('pattern') or '').strip()
	mode = normalize_vanity_mode(body.get('mode') or 'contains')
	testnet = 1 if _parse_testnet_flag(body.get('testnet')) else 0
	try:
		threads = int(body.get('threads', 0))
	except (TypeError, ValueError):
		threads = 0
	if not pattern:
		return jsonify({'error': 'Pattern is required'}), 400
	try:
		addresses, key_material, elapsed_or_err = _run_vanity(pattern, mode, testnet, threads)
		if addresses is None:
			return jsonify({'error': elapsed_or_err}), 400
		addr = addresses[0]
		network = 'testnet' if testnet else 'mainnet'
		return jsonify({
			'message': 'Vanity address generated successfully',
			'addresses': addresses,
			'key_material': _serialize_key_material(key_material),
			'elapsed': elapsed_or_err,
			'network': network,
			'qr_png_base64': qr_png_base64(addr),
		})
	except Exception as e:
		return jsonify({'error': public_error_message(e)}), 500


# Legacy GET vanity endpoint (kept for compatibility)
@app.route('/api/vanity_address/<string:pattern>/<string:mode>/<int:threads>/<int:testnet>/<int:force_python>', methods=['GET'])
def vanity_address(
	pattern: str,
	mode: str = 'contains',
	threads: int = 0,
	testnet: int = 0,
	force_python: int = 0,
):
	try:
		addresses, key_material, elapsed_or_err = _run_vanity(pattern, mode, testnet, threads)
		if addresses is None:
			return jsonify({'error': elapsed_or_err}), 400
		addr = addresses[0]
		network = 'testnet' if testnet else 'mainnet'
		return jsonify({
			'message': 'Vanity address generated successfully',
			'addresses': addresses,
			'key_material': _serialize_key_material(key_material),
			'elapsed': elapsed_or_err,
			'network': network,
			'qr_png_base64': qr_png_base64(addr),
		})
	except Exception as e:
		return jsonify({'error': public_error_message(e)}), 500


@app.route('/api/get_sp_address', methods=['GET', 'POST'])
def get_sp_address():
	if request.method == 'POST':
		body = request.get_json(silent=True) or {}
		testnet = _parse_testnet_flag(body.get('testnet'))
	else:
		testnet = _parse_testnet_flag(request.args.get('testnet', ''))
	network = 'testnet' if testnet else 'mainnet'

	try:
		t0 = time.perf_counter()
		addresses, key_material = generate_sp_address(
			network=network,
			qr_code=False,
		)
		key_material["scan_priv_key"]= key_material["scan_priv_key"].hex()
		key_material["spend_priv_key"]= key_material["spend_priv_key"].hex()

		elapsed = time.perf_counter() - t0
		addr = addresses[0]
		return jsonify({
			"message": "SP address generated successfully",
			"addresses": addresses,
			"key_material": key_material,
			"elapsed": elapsed,
			"network": network,
			"qr_png_base64": qr_png_base64(addr),
		})
	except Exception as e:
		return jsonify({"error": public_error_message(e)}), 500

# Qr endpoint
@app.route('/api/qr_code', methods=['GET'])
def qr_code():
	"""Legacy: prefer qr_png_base64 from generate endpoints. Optional ?address=sp1..."""
	try:
		addr = request.args.get('address', '').strip()
		if addr:
			from io import BytesIO
			import base64 as b64
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
		return jsonify({"error": "address query parameter is required"}), 400
	except Exception as e:
		return jsonify({"error": public_error_message(e)}), 500