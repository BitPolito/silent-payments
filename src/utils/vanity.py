import argparse
from ..receive import generate_sp_address
from typing import Tuple, List

def get_sp_vanity_address(vanity_string: str) -> Tuple[List[str], dict]:
    while True:
        address, key_material = generate_sp_address()
        print(f"Address: {address}")
        if vanity_string in address:
            return address, key_material


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate a BIP352 Silent Payment address with a vanity string.')
    parser.add_argument('vanity_string', type=str, help='Vanity string to search for in the address')
    args = parser.parse_args()
    
    address, key_material = get_sp_vanity_address(args.vanity_string)
    print(f"Address found: {address}")
    print(f"Key material: {key_material}")