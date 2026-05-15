# Silent-Payments

This project is a proof-of-concept of [BIP 352: Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki), a method for receiving Bitcoin privately via a static address, without having to communicate directly with the sender.

The repo includes various scenarios to evaluate the correctness and flexibility of Silent Payments, including different input types, taproot combinations, label handling, and more, as outlined in the [test_list.json](src/test_list.json).

### Project Structure
```bash
silent-payments/
│
├── .gitignore							# Ignore file for github
├── .vercelignore						# Ignore file for vercel
├──	vercel.json							# Settings file for vercel
├── package.json						# Depedencies file for vite
├── README.md							# Project documentation
├── public/								# Assets for the frontend
├──	src/								# React frontend
├── api/								# Python backend
	├── index.py						# main for flask api
	├── requirements.txt				# Dependencies file for python
	├── vanity/							# Rust functions to generate the vanity address
	├── core/							# source code for python
		├── send.py						# sender's functions
		├── receive.py					# receiver's functions
		├── utils/
			├── hardened_keys.py		# hardkeys function gen
			├── schnorr_lib.py			# schnorr-ref-lib
			├── segwit_addr.py			# bech32m enc/dec reference
			├── utils.py				# useful functions
			├── vanity_python.py		# functions in python for the vanity address 
		├── test/
			├── test_legend.json 		# .json file for test legend
			├── test_list.json   		# .json file for test list
			├── test_vectors.json		# .json file for test vectors
			├── test.ipynb       		# Jupyter notebook to easly test
			└── test.py          		# main test file
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
   source venv/bin/activate 
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Install Rust and Cargo (only for vanity address)
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

### Running the scripts

Execute tests running
```bash
cd api
python3 -m core.test.test
```
and follow the instructions.

Exectute sending tests with the debug option
```bash
cd api
python3 -m core.send --filename=core/test/test_vectors.json --test_id=the_id_of_the_test --debug
```

Exectute receiving tests with the debug option
```bash
cd api
python3 -m core.receive	--function {run,scan,generate_sp_address,get_spending_key} --debug
```

### Jupyter
Select the "test.ipynb" from you folders and execute all the send and receive tests


### Generate a Silent-Payments vanity address
Perform a brute-force search for a vanity address:
```bash
cd api
python3 -m core.utils.vanity your_vanity_string
```

Or directly from rust binary:
```bash
python3 ./vanity/target/release/vanity "your_vanity_string"


```

Command line option:

**--mode**: select mode from prefix, suffix and contains (default contains).

**--threads**: select threads number (0 is max threads) Only for rust implementation.

**--python-only**: execute the python version.

Rust implementation benchmark and test:
```bash
cd vanity
cargo bench
```
All results are also displyed in vanity/target/criterion
```bash
cd vanity
cargo test
```
You can find the tests in vanity/tests/integration_tests.rs 

### Webapp

The webapp has been deployad on Vercel at: https://silent-payments.vercel.app/

Install node 20
```bash

curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash

source ~/.bashrc
nvm install 20
nvm use 20
```

Resfresh node_modules

```bash
rm -rf node_modules package-lock.json
npm install
```

Launch the webapp locally at https://localhost:5173

```bash
npm run dev
```