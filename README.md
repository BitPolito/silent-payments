# Silent-Payments

## Introduction
This project explores and implements key concepts from [BIP 352: Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki). Silent Payments introduce a novel method for privately receiving Bitcoin transactions without requiring the sender and receiver to directly communicate or share a unique address beforehand.
Unlike traditional Bitcoin addresses, which are typically used once to preserve privacy, Silent Payments enable address reuse without compromising privacy. The receiver publishes a static silent payment address, while senders use it to generate unique one-time destination addresses for each transaction. This mechanism allows recipients to remain passive, scanning the blockchain for relevant outputs derived from their silent address.
Our test suite includes various scenarios to evaluate the correctness and flexibility of Silent Payments, including different input types, taproot combinations, label handling, and more, as outlined in the test_list.json.


### Project Structure
```bash
silent-payments/
│
├── .gitignore               # Ignore file
├── README.md                # Project documentation
├── requirements.txt         # Dependencies file
└── src/                     # source code
    ├── hardened_keys.py     # hardkeys function gen
    ├── receive.py           # receiver's functions
    ├── schnorr_lib.py       # schnorr-ref-lib
    ├── segwit_addr.py       # bech32m enc/dec reference
    ├── send.py              # sender's functions
    ├── utils.py             # useful functions
    ├── test_legend.json     # .json file for test legend
    ├── test_list.json       # .json file for test list
    ├── test_vectors.json    # .json file for test vectors
    ├── test.ipynb           # Jupyter notebook to easly test
    └── test.py              # main test file
```

### How to install and run code
1. **Clone this repository** to your local machine:
   ```bash
   git clone https://www.github.com/BitPolito/silent-payments
   cd silent-payments
   ```
2. Create a virtual environment (optional but recommended):
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Running the tests
Execute tests running
```bash
python3 test.py
```
and follow the instructions selecting the test from test_list.json

Choose the test type:

0. Simple send: two inputs  
1. Simple send: two inputs order reversed  
2. Simple send: two inputs from the same transaction  
3. Simple send: two inputs from the same transaction order reversed  
4. Outpoint ordering byte-lexicographically vs. vout-integer  
5. Single recipient: multiple UTXOs from the same public key  
6. Single recipient: taproot only inputs with even y-values  
7. Single recipient: taproot only with mixed even/odd y-values  
8. Single recipient: taproot input with even y-value and non-taproot input  
9. Single recipient: taproot input with odd y-value and non-taproot input  
10. Multiple outputs: multiple outputs same recipient  
11. Multiple outputs: multiple outputs multiple recipients  
12. Receiving with labels: label with even parity  
13. Receiving with labels: label with odd parity  
14. Receiving with labels: large label integer  
15. Multiple outputs with labels: un-labeled and labeled address; same recipient  
16. Multiple outputs with labels: multiple outputs for labeled address; same recipient  
17. Multiple outputs with labels: un-labeled labeled and multiple outputs for labeled address; same recipients  
18. Single recipient: use silent payments for sender change  
19. Single recipient: taproot input with NUMS point  
20. Pubkey extraction from malleated p2pkh  
21. P2PKH and P2WPKH Uncompressed Keys are skipped  
22. Skip invalid P2SH inputs  
23. Recipient ignores unrelated outputs  
24. No valid inputs sender generates no outputs  
25. Input keys sum up to zero / point at infinity: sending fails receiver skips tx  

Note:
Tests must be launched directly from the Test.py script.
At the moment, the sender.py and receiver.py files do not support command-line arguments, so it's not possible to run individual tests via the command line.
This is something we plan to add in a future version.

### Generate a Silent-Payments vanity address
Perform a brute-force search for a vanity address:
```bash
python3 vanity.py your_vanity_string
```

### Future works

Silent Payments offer a powerful privacy feature for Bitcoin by allowing recipients to derive unique addresses per transaction without interacting with the sender or publishing any extra data on-chain. However, this design introduces a key technical challenge: scanning the blockchain to detect incoming payments.
In a real-world scenario, the recipient must scan every Taproot output to check if it's addressed to them. This process becomes resource-intensive, especially without the help of a full node. So far, our implementation does not connect to a Bitcoin node, but future work will likely require exploring how to integrate one.
Relying on a full node would let us maintain an index of Taproot outputs and scan them efficiently, but it also introduces practical concerns — such as node synchronization, bandwidth usage, and managing access to raw blockchain data. According to some estimates, under heavy usage, this could mean ~100 kB per block (up to 450 MB/month), while current conditions suggest a more modest 30–50 MB/month.
Understanding whether this scanning can be done independently — or needs lightweight alternatives or external infrastructure — will be crucial to making Silent Payments truly usable at scale.