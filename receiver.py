from utils import *
from schnorr_lib import pubkey_point_gen_from_int, tagged_hash, point_add, int_from_bytes, bytes_from_hex
from hardened_keys import generate_hardened_keys
from segwit_addr import encode as bech32m



# generating silent payments address
def generate_sp_address(key_material: dict = None, labels: list[int] = None, network: str = 'mainnet', version: int = 0) -> str:
    
    # if there are no keys in input create a key pair
    if key_material is None: 
        key_material = generate_hardened_keys()
        b_scan = key_material['scan_priv_key']
        b_spend = key_material['spend_priv_key']
    else: 
        b_scan = bytes_from_hex(key_material['scan_priv_key'])
        b_spend = bytes_from_hex(key_material['spend_priv_key'])
    
    # Let Bscan, bscan = Receiver's scan public key and corresponding private key
    B_scan = pubkey_point_gen_from_int(int_from_bytes(b_scan))

    # Let Bspend, bspend = Receiver's spend public key and corresponding private key
    B_spend = pubkey_point_gen_from_int(int_from_bytes(b_spend))

    # If a label is provided, apply the tweak
    # Assuming label is an integer 
    if len(labels) > 0: 
        # Let Bm = Bspend + hashBIP0352/Label(ser256(bscan) || ser32(m))·G 
        # where hashBIP0352/Label(ser256(bscan) || ser32(m))·G is an optional integer tweak for labeling
        h = tagged_hash('Label', ser256(int_from_bytes(b_scan)) + ser32(labels)) 
        label_hash = pubkey_point_gen_from_int(int_from_bytes(h))
        B_m = point_add(B_spend, label_hash)  # Tweak the spend public key 
    else: 
        B_m = B_spend # If no label is applied then Bm = Bspend

    
    # human-readable part based on the network
    hrp = 'sp' if network == 'mainnet' else 'tsp' 

    # Create the data part
    data_part = serP(B_scan) + serP(B_m)  # Concatenate the serialized public keys

    # Encode the address in Bech32m format
    # sp_address = encode_sp_address(hrp, data_part, version)
    
    sp_address = bech32m(hrp, data_part, version)

    return sp_address


'''
The final address is a Bech32m encoding of:
    The human-readable part "sp" for mainnet, "tsp" for testnets (e.g. signet, testnet)
    The data-part values:
        The character "q", to represent a silent payment address of version 0
        The 66-byte concatenation of the receiver's public keys, serP(Bscan) || serP(Bm)
'''
def encode_sp_address(hrp: str, data_part: bytes, version: int) -> str:

    return 



def scanning(transactions: list, bscan: int, Bspend: Point, labels: list) -> list:
    '''
    If each of the checks in Scanning silent payment eligible transactions passes, the receiving wallet must:

    Let A = A1 + A2 + ... + An, where each Ai is the public key of an input from the Inputs For Shared Secret Derivation list
        If A is the point at infinity, skip the transaction
    Let input_hash = hashBIP0352/Inputs(outpointL || A), where outpointL is the smallest outpoint lexicographically used in the transaction
    Let ecdh_shared_secret = input_hash·bscan·A
    Check for outputs:
        Let outputs_to_check be the taproot output keys from all taproot outputs in the transaction (spent and unspent).
        Starting with k = 0:
            Let tk = hashBIP0352/SharedSecret(serP(ecdh_shared_secret) || ser32(k))
                If tk is not valid tweak, i.e., if tk = 0 or tk is larger or equal to the secp256k1 group order, fail
            Compute Pk = Bspend + tk·G
            For each output in outputs_to_check:
                If Pk equals output:
                    Add Pk to the wallet
                    Remove output from outputs_to_check and rescan outputs_to_check with k++
                Else, check for labels (always check for the change label, i.e. hashBIP0352/Label(ser256(bscan) || ser32(m)) where m = 0):
                    Compute label = output - Pk
                    Check if label exists in the list of labels used by the wallet
                    If a match is found:
                        Add Pk + label to the wallet
                        Remove output from outputs_to_check and rescan outputs_to_check with k++
                    If a label is not found, negate output and check a second time
            If no matches are found, stop
    '''
    """
    Scans transactions for silent payment eligible outputs.
    
    Args:
        transactions: List of transaction dicts with at least:
            - 'inputs': list of dicts with public keys as Points and 'outpoint'
            - 'outputs': list of Points (taproot output keys)
        bscan: Private scan key (int)
        Bspend: Public spend key (Point)
        labels: List of Points (public keys used as labels)
    
    Returns:
        List of detected output Points that belong to the wallet.
    """
    detected_outputs = []

    for tx in transactions:
        inputs = tx["inputs"]
        outputs_to_check = tx["outputs"]

        # Step 1: Aggregate input public keys A = A1 + A2 + ... + An
        A = None
        for i in inputs:
            A = point_add(A, i["pubkey"])

        if is_infinity(A):
            continue

        # Step 2: Get the smallest outpoint lexicographically
        outpoints = [i["outpoint"] for i in inputs]
        outpointL = min(outpoints)

        # Step 3: Compute input_hash = hashBIP0352/Inputs(outpointL || A)
        input_hash = tagged_hash("BIP0352/Inputs", outpointL + bytes_from_point(A))

        # Step 4: ecdh_shared_secret = input_hash * bscan * A
        ecdh_scalar = (int_from_bytes(input_hash) * bscan) % n
        ecdh_shared_secret = point_mul(A, ecdh_scalar)
        if ecdh_shared_secret is None:
            continue

        # Step 5: Iterate over outputs and derive possible matches
        k = 0
        while outputs_to_check:
            # tk = hashBIP0352/SharedSecret(serP(ecdh_shared_secret) || ser32(k))
            ser_secret = bytes_from_point(ecdh_shared_secret)
            ser_k = k.to_bytes(4, byteorder='big')
            tk_bytes = tagged_hash("BIP0352/SharedSecret", ser_secret + ser_k)
            tk = int_from_bytes(tk_bytes)

            if tk == 0 or tk >= n:
                break

            # Pk = Bspend + tk * G
            Pk = point_add(Bspend, point_mul(G, tk))
            if Pk is None:
                break

            matched = False
            for out in outputs_to_check:
                if Pk == out:
                    detected_outputs.append(Pk)
                    outputs_to_check.remove(out)
                    matched = True
                    break

                # Check label
                label = point_add(out, point_mul(Pk, n - 1))  # label = out - Pk
                if label in labels:
                    derived = point_add(Pk, label)
                    detected_outputs.append(derived)
                    outputs_to_check.remove(out)
                    matched = True
                    break

                # Check negated output
                neg_out = point_mul(out, n - 1)
                label_neg = point_add(neg_out, point_mul(Pk, n - 1))
                if label_neg in labels:
                    derived = point_add(Pk, label_neg)
                    detected_outputs.append(derived)
                    outputs_to_check.remove(out)
                    matched = True
                    break

            if not matched:
                break

            k += 1

    return detected_outputs



def spending(bspend: int, tk: int, bscan: int, m: int, label: bool = False) -> int:
    '''
    Recall that a silent payment output is of the form Bspend + tk·G + hashBIP0352/Label(ser256(bscan) || ser32(m))·G, where hashBIP0352/Label(ser256(bscan) || ser32(m))·G is an optional label. 
    To spend a silent payment output:
    - Let d = (bspend + tk + hashBIP0352/Label(ser256(bscan) || ser32(m))) mod n, where hashBIP0352/Label(ser256(bscan) || ser32(m)) is the optional label
    - Spend the BIP341 output with the private key d
    '''
    d = (bspend + tk) % n
    if label:
        data = ser256(bscan) + ser32(m)
        label_hash = tagged_hash("BIP0352/Label", data)
        d = (d + int.from_bytes(label_hash, 'big')) % n
    return d



# running the receiving process
def receiving_run(key_material: dict = None, labels: list = []) -> str:

    print('receiver.py loading...')  
    address = generate_sp_address(key_material, labels)
    print(address)
    return address


if __name__ == '__main__':
    receiving_run()












