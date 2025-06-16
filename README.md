# Silent-Payments

## Introduction


## Initial Setup


### Project Structure
```bash
silent-payments/
│
├── .gitignore               # Ignore file
├── README.md                # Project documentation
├── requirements.txt         # Dependencies file
├── src/                     # source code
│   ├── dleq.py              # dleq proof functions
│   ├── hardened_keys.py     # hardkeys function gen
│   ├── receiver.py          # receiver's functions
│   ├── schnorr_lib.py       # schnorr-ref-lib
│   ├── segwit_addr.py       # bech32m enc/dec reference
│   ├── sender.py            # sender's functions
│   └── utils.py             # useful functions
│
└── test/                    # test code
    ├── test_legend.json     # .json file for test legend
    ├── test_list.json       # .json file for test list
    ├── test_vectors.json    # .json file for test vectors
    ├── test.ipynb           # Jupyter notebook to easly test
    └── test.py              # main test file
```

### How to install and run code
1. **Clone this repository** to your local machine:
   ```bash
   git clone 
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
Execute each test file with:
