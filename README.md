# Silent-Payments

## Introduction


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

### Generate a Silent-Payments vanity address
Perform a brute-force search for a vanity address:
```bash
python3 vanity.py your_vanity_string
```
