''''
The sender performs coin selection as usual with the following restrictions: 
- At least one input MUST be from the Inputs For Shared Secret Derivation list 
- Exclude inputs with SegWit version > 1 (see Scanning silent payment eligible transactions)
- For each taproot output spent the sending wallet MUST have access to the private key corresponding to the taproot output key, unless H is used as the internal public key
''' 

import argparse
import logging
import json

from utils.schnorr_lib import (
    G, 
    n, 
    int_from_hex, 
    int_from_bytes, 
    bytes_from_point, 
    point_from_bytes, 
    point_mul, 
    point_add, 
    tagged_hash,
    pubkey_point_gen_from_int,
    has_even_y,
)
from utils.utils import (
    get_transaction_type, 
	get_input_hash, 
	select_inputs, 
	validate_inputs,
    decode_silent_payment_address,
    ser32,
    serP
)

logger = logging.getLogger(__name__)

def create_sp_groups(recipients: list[str]) -> dict[bytes, list[bytes]]:
    '''
    Group receiver silent payment addresses by B_scan (e.g. each group consists of one B_scan and one or more B_m).
    
    Args:
		recipients: list of silent payment addresses of the recipients.
	Returns:
		A dictionary where the keys are the B_scan values and the values are lists of B_m values corresponding to each B_scan.
    
    '''
    sp_groups: dict[bytes, list[bytes]] = {}
    logger.debug(f'recipients: {recipients}')
    for receip in recipients:
        B_scan, B_m = decode_silent_payment_address(receip)
        logger.debug(f'B_scan: {B_scan}')
        logger.debug(f'B_m: {B_m}')
        if B_scan in sp_groups:
            sp_groups[B_scan].append(B_m)
        else:
            sp_groups[B_scan] = [B_m]
    logger.debug(f'SP groups: {sp_groups}')
    return sp_groups

def generate_a_A_from_inputs(inputs: list[dict]) -> tuple[int, bytes]:
    '''
    
    Generate the scalar a and the point A = a·G from the private keys of the inputs.
    
    Args:
    	inputs: list of inputs selected for the transaction. Each input is a dictionary containing the private key and the previous output information.
	
    Returns:
		a: the scalar a generated from the private keys of the inputs.
		A: the point A = a·G generated from the private keys of the inputs.
    '''
    keys = []
    for tx in inputs:
        a_i = int_from_hex(tx['private_key'])
        P = pubkey_point_gen_from_int(a_i)
        
        txinwitness = tx.get('txinwitness', '')
        scriptPubKey = tx['prevout']['scriptPubKey']['hex']
        tx_type = get_transaction_type(txinwitness, scriptPubKey)
        
        if tx_type == 'P2TR':
            if not has_even_y(P):
                a_i = n - a_i
        keys.append(a_i)

    a = sum(keys) % n
    if a == 0:
        raise ValueError('ERROR: zero key sum.')
    A = point_mul(G, a)
    return a, A

def create_outputs(vin: list[dict], inputs: list[dict], recipients: list[str]) -> list:
    '''Create one output for each B_m in each group.
    
    For each group, the output is created as follows:
		- Let ecdh_shared_secret = input_hash·a·B_scan, where input_hash is the hash of the transaction inputs and B_scan is the internal public key of the group.
		
        - For each B_m in the group:
			
            - Let tk = hashBIP0352/SharedSecret(serP(ecdh_shared_secret) || ser32(k)), where k is a counter starting from 0.
			- If tk is not valid tweak, i.e., if tk = 0 or tk is larger or equal to the secp256k1 group order, fail.
			- Let P_mn = B_m + tk·G, where B_m is the external public key of the recipient and G is the generator point of the secp256k1 curve.
			- Encode P_mn as a BIP341 taproot output and add it to the list of outputs.
			- Optionally, repeat with k++ to create additional outputs for the current B_m.
			If no additional outputs are required, continue to the next B_m with k++.
    
    Args:
    	vin: list of all the inputs of the transaction. Each input is a dictionary containing the previous output information.
		inputs: list of inputs selected for the transaction. Each input is a dictionary containing the private key and the previous output information.
		recipients: list of silent payment addresses of the recipients.

    Returns:
		A list of outputs created for the transaction. Each output is a hexadecimal string representing the taproot output.
    '''
  
    a, A = generate_a_A_from_inputs(inputs)

    input_hash = get_input_hash(vin, A)
    logger.debug(f'input hash: {input_hash}')
    
    sp_groups = create_sp_groups(recipients)
    
    outputs = []
    # For each group:
    for B_scan, B_m_list_bytes in sp_groups.items(): 
        
        logger.debug(f'Processing group with B_scan: {B_scan} and B_m_list_bytes: {B_m_list_bytes}')
        # Let ecdh_shared_secret = input_hash·a·Bscan
        logger.debug(f'B_scan: {point_from_bytes(B_scan)}')
        logger.debug(f'input_hash: {input_hash}')
        logger.debug(f'a: {a}')
        scalar = (int_from_bytes(input_hash) * a) % n
        ecdh_shared_secret = point_mul(point_from_bytes(B_scan), scalar)
        logger.debug(f'ecdh_shared_secret: {ecdh_shared_secret}')

        B_m_points = []
        for b_m_bytes in B_m_list_bytes:
            B_m_points.append(point_from_bytes(b_m_bytes))
         
        B_m_points.sort()

        # Let k = 0
        k = int(0) 
        # For each B_m in the group: 
        for B_m in B_m_points:           
            # Let tk = hashBIP0352/SharedSecret(serP(ecdh_shared_secret) || ser32(k))
            t_k = int_from_bytes(tagged_hash('BIP0352/SharedSecret', serP(ecdh_shared_secret) + ser32(k)))
            # If tk is not valid tweak, i.e., if tk = 0 or tk is larger or equal to the secp256k1 group order, fail
            if t_k == 0 or t_k >= n: 
                raise ValueError('ERROR: wrong tweak value.') 
            
            # Let Pmn = Bm + tk·G
            P_mn = point_add(B_m, point_mul(G, t_k))
            # Encode Pmn as a BIP341 taproot output
            taproot_output = bytes_from_point(P_mn).hex()
            outputs.append(taproot_output)

            # Optionally, repeat with k++ to create additional outputs for the current Bm
            # If no additional outputs are required, continue to the next Bm with k++
            k += 1
    
    return outputs


def sending_run(vin: list[dict], recipients: list[str]) -> list[str]:
    '''Main function for the sending phase. It takes as input the list of inputs and the list of recipients and returns the list of outputs.'''
    inputs = select_inputs(vin)
    inputs = validate_inputs(inputs, vin)
    if not inputs:
        return []
    logger.debug(f'selected {len(inputs)} valid inputs: {inputs}')
    outputs = create_outputs(vin, inputs, recipients)
    return outputs


# CLI
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=(
            'Run the Silent Payments sending tests\n'
            'All arguments must be provided via command line.\n'
            'filename paths to JSON files.'
            'test number of the test to run can be provided via --test_id argument, otherwise it will be requested as input.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--filename',          required=False, help='filename of the JSON file containing the test data')
    parser.add_argument('--test_id',      required=False, help='Test number of the test to run (0-25)')
    parser.add_argument('--debug',        required=False, action='store_true', help='Enable debug logging')
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format='%(levelname)s %(name)s: %(message)s',
    )

    def load_json_arg(arg):
        if arg is None:
            return None
        try:
            with open(arg, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, OSError):
            return json.loads(arg)

    data = load_json_arg(args.filename)
    if data is None:
        raise ValueError('test_data problem')
    
    test_id  = int(args.test_id) if args.test_id is not None else None
    if test_id is None:
        test_id = int(input('Insert the test id to select the test to perform (0-25):'))
        if test_id < 0 or test_id >= len(data):
            raise ValueError('Invalid test ID selected.')
    data = data[test_id]

    sending = data['sending'][0]
    sending_details = sending['given']
    expected_sending = sending['expected']

    vin = sending_details['vin']
    recipients = sending_details['recipients']

    expected_outputs_sets = expected_sending['outputs']

    outputs = sending_run(vin, recipients)
    print(json.dumps(outputs, indent=4))
    print(f'Expected outputs sets: {expected_outputs_sets}')