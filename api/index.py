import os
import sys

# 1. Aggiungi la cartella 'api' ai percorsi dove Python cerca i moduli
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)


from flask import Flask, jsonify, send_file
from flask_cors import CORS
import json
from core.send import sending_run
from core.receive import receiving_run, generate_sp_address
from core.utils.vanity_python import get_sp_vanity_address
from collections import Counter
import time

app = Flask(__name__)
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

@app.route('/api/get_all_tests', methods=['GET'])
def get_all_tests():
	try:
		base_dir = os.path.dirname(os.path.abspath(__file__))
		json_path = os.path.join(base_dir, 'core', 'test', TEST_LIST)
		with open(json_path, 'r', encoding='utf-8') as f:
			test_list_data = json.load(f)
		return jsonify(test_list_data)
	except Exception as e:
		return jsonify({"error": str(e)}), 500

@app.route('/api/single_test/send/<int:test_id>', methods=['GET'])
def single_test_send(test_id: int):
	base_dir = os.path.dirname(os.path.abspath(__file__))

	json_path = os.path.join(base_dir, 'core', 'test', TEST_FILE)
	data = load_json_arg(json_path)
	if data is None:
		raise ValueError('test_data problem')
	
	data = data[test_id]

	sending = data['sending'][0]
	sending_details = sending['given']
	expected_sending = sending['expected']

	vin = sending_details['vin']
	recipients = sending_details['recipients']

	expected_outputs_sets = expected_sending['outputs']

	try:
		outputs = sending_run(vin, recipients)
	except Exception as e:
		if (isinstance(e, ValueError) and 'zero key sum' in str(e)):
			test_passed = True
			return jsonify({
				"message": f"Single test send endpoint with ID {test_id}",
				"expected_outputs": expected_outputs_sets,
				"outputs": [],
				"test_passed": test_passed,
				"test_id": test_id
			})
		raise ValueError(f'Error occurred while running sending test: {str(e)}')

	test_passed = False

	for excpected_outputs in expected_outputs_sets:
		if Counter(outputs) == Counter(excpected_outputs):
			right_expected_outputs = excpected_outputs
			test_passed = True
			break
	else:
		raise ValueError('Test failed: outputs do not match any expected set.')

	aligned_outputs = []
	for expected_output in right_expected_outputs:
		for output in outputs:
			if output == expected_output:
				aligned_outputs.append(output)
				break

	return jsonify({
		"expected_outputs": right_expected_outputs,
		"outputs": aligned_outputs,
		"test_passed": test_passed,
		"test_id": test_id
	})

@app.route('/api/single_test/receive/<int:test_id>', methods=['GET'])
def single_test_receive(test_id: int):
	base_dir = os.path.dirname(os.path.abspath(__file__))
	
	json_path = os.path.join(base_dir, 'core', 'test', TEST_FILE)
	data = load_json_arg(json_path)
	if data is None:
		raise ValueError('test_data problem')
	
	data = data[test_id]
	receiving = data['receiving'][0]
	receiving_details = receiving['given']
	expected_receiving = receiving['expected']

	vin = receiving_details['vin']
	outputs = receiving_details['outputs']
	key_material = receiving_details['key_material']
	labels = receiving_details['labels']

	addresses, wallet = receiving_run(vin, outputs, key_material, labels)

	expected_addresses = expected_receiving['addresses']   # lista
	expected_outputs = expected_receiving['outputs']       # lista di dict

	addresses_ok = addresses == expected_addresses

	# confronta pub_key e priv_key_tweak (la signature è random, non confrontabile)
	outputs_ok = all(
		any(w['pub_key'] == e['pub_key'] and w['priv_key_tweak'] == e['priv_key_tweak']
			for w in wallet)
		for e in expected_outputs
	)

	aligned_wallet = []
	for expected_output in expected_outputs:
		for output in wallet:
			if output['pub_key'] == expected_output['pub_key'] and output['priv_key_tweak'] == expected_output['priv_key_tweak']:
				aligned_wallet.append(output)
				break

	if addresses_ok and outputs_ok:
		test_passed = True
	else:
		test_passed = False

	return jsonify({
		"message": f"Single test receive endpoint with ID {test_id}",
		"expected_addresses": expected_addresses,
		"addresses": addresses,
		"expected_outputs": expected_outputs,
		"outputs": aligned_wallet,
		"test_passed": test_passed,
		"test_id": test_id
	})

# Vanity address endpoint
@app.route('/api/vanity_address/<string:pattern>/<string:mode>/<int:threads>/<int:testnet>/<int:force_python>', methods=['GET'])
def vanity_address(
	pattern: 		str, 
	mode: 			str = "contains", 
	threads: 		int = 0, 
	testnet: 		int = 0, 
	force_python: 	int = 0
):
	print(f"Generating vanity address with pattern={pattern}, mode={mode}, threads_num={threads}, testnet={testnet}, force_python={force_python}", flush=True)
	try:
		t0 = time.perf_counter()
		addresses, key_material = get_sp_vanity_address(
			vanity_string=pattern,
			mode=mode,
			num_threads=threads,
			testnet=testnet,
			force_python=force_python
		)
		
		elapsed = time.perf_counter() - t0
		return jsonify({
			"message": "Vanity address generated successfully",
			"addresses": addresses,
			"key_material": key_material,
			"elapsed": elapsed	
		})
	except Exception as e:
		return jsonify({"error": str(e)}), 500
	

@app.route('/api/get_sp_address', methods=['GET'])
def get_sp_address():

	try:
		t0 = time.perf_counter()
		addresses, key_material = generate_sp_address(
			qr_code=True
		)
		key_material["scan_priv_key"]= key_material["scan_priv_key"].hex()
		key_material["spend_priv_key"]= key_material["spend_priv_key"].hex()

		# print(f"address: {addresses[0]}, keys: {key_material}", flush=True)

		elapsed = time.perf_counter() - t0
		return jsonify({
			"message": "SP address generated successfully",
			"addresses": addresses,
			"key_material": key_material,
			"elapsed": elapsed	
		})
	except Exception as e:
		return jsonify({"error": str(e)}), 500

# Qr endpoint
@app.route('/api/qr_code', methods=['GET'])
def qr_code():
	try :
		file_path = "/tmp/silent_payment_qr.png"
    
		return send_file(
			file_path,
			mimetype='image/png',
			as_attachment=True,
			download_name='silent_payment_qr.png'
		)
	except Exception as e:
		return jsonify({"error": str(e)}), 500