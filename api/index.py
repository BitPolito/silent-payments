from flask import Flask, jsonify, request
from flask_cors import CORS
import json
from core.send import sending_run
from core.receive import receiving_run
from collections import Counter

app = Flask(__name__)
CORS(app)

TEST_FILE = "./core/test/test_vectors.json"
TEST_LIST = "./core/test/test_list.json"

def load_json_arg(arg):
	if arg is None:
		return None
	try:
		with open(arg, 'r') as f:
			return json.load(f)
	except (FileNotFoundError, OSError):
		return json.loads(arg)

@app.route('/', methods=['GET'])
def index():
	return jsonify({"message": "Hello, World!"})

@app.route('/get_all_tests', methods=['GET'])
def get_all_tests():
	try:
		with open(TEST_LIST, 'r') as f:
			test_list_data = json.load(f)
		return jsonify(test_list_data)
	except Exception as e:
		return jsonify({"error": str(e)}), 500

@app.route('/single_test/send/<int:test_id>', methods=['GET'])
def single_test_send(test_id):
	data = load_json_arg(TEST_FILE)
	if data is None:
		raise ValueError('test_data problem')
	
	data = data[test_id]

	sending = data['sending'][0]
	sending_details = sending['given']
	expected_sending = sending['expected']

	vin = sending_details['vin']
	recipients = sending_details['recipients']

	expected_outputs_sets = expected_sending['outputs']
	outputs = sending_run(vin, recipients)
	test_passed = False

	for excpected_outputs in expected_outputs_sets:
		if Counter(outputs) == Counter(excpected_outputs):
			right_expected_outputs = excpected_outputs
			test_passed = True
			break
	else:
		raise ValueError('Test failed: outputs do not match any expected set.')

	return jsonify({
		"expected_outputs": right_expected_outputs,
		"outputs": outputs,
		"test_passed": test_passed,
		"test_id": test_id
	})

@app.route('/single_test/receive/<int:test_id>', methods=['GET'])
def single_test_receive(test_id):
	data = load_json_arg(TEST_FILE)
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

	if addresses_ok and outputs_ok:
		test_passed = True
	else:
		test_passed = False

	return jsonify({
		"message": f"Single test receive endpoint with ID {test_id}",
		"expected_addresses": expected_addresses,
		"expected_outputs": expected_outputs,
		"addresses": addresses,
		"outputs": wallet,
		"test_passed": test_passed,
		"test_id": test_id
	})