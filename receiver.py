from create_keypair import create_keypair as ckp

# generating silent payments address
def generate_sp_address(keys = None):
    
    # if there are no keys in input create a key pair
    if keys is not None:
        keys = ckp()

    # ..........
    sp_address = keys 

    sp_address = encoding_sp_address(sp_address)

    return sp_address 

# encoding the address
def encoding_sp_address(sp_address):
    # .......
    return sp_address



# running the receiving process
def receiving_run(): 
    print('receiver.py loading...')    
