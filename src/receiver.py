from receive import generate_sp_address, scan, get_spending_key, run
from typing import Optional, List, Dict

class Receiver:
    def __init__(self, vin: List[Dict], outputs: List[str], key_material: Optional[Dict] = None, labels: Optional[List[int]] = None):
        self.vin = vin
        self.outputs = outputs
        self.key_material = key_material
        self.labels = labels

    def generate_sp_address(self, network='mainnet', version=0):
        return generate_sp_address(self.key_material, self.labels, network, version)

    def scan(self):
        if self.key_material is None:
            raise ValueError('key_material is required for scan')
        return scan(self.vin, self.outputs, self.key_material, self.labels)

    def get_spending_key(self, bspend, tk, bscan, m, label: List[int] = []):
        return get_spending_key(bspend, tk, bscan, m, label)

    def run(self):
        return run(self.vin, self.outputs, self.key_material, self.labels)
