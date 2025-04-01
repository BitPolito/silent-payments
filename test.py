import json
from sender import sending_run
from receiver import receiving_run

def test_file_reading(): 
    # insert .json file
    test_vectors = './send_and_receive_test_vectors.json'
    # read test file
    try: 
        with open(test_vectors, 'r') as f:
            print('Reading file...')
            test_data = json.load(f)
    except FileNotFoundError:
        print(f'Error: file {test_vectors} not found.')
        return None
    except json.JSONDecodeError:
        print("Error: json file not valid.")
        return None
    return test_data


def test() -> bool:
    # read the test file
    data = test_file_reading()
    if data is None:
        return False
    
    # take as input the id of the test you want to perform
    test_id = int(input('Insert the test id to select the test to perform (0-25):'))
    
    if test_id < 0 or test_id >= len(data):
        raise ValueError('Invalid test ID selected.')
    
    test_data = data[test_id]
    print(f'Starting test #{test_id}...')  

    comment = test_data['comment']
    print(f'Test details: {comment}')

    # select the type of test
    flag = int(input('Insert test type (type 0 for sending or 1 for receiving or 2 for both): '))
    if flag == 0:
        test_type = 'sending'
    elif flag == 1:
        test_type = 'receiving'
    elif flag == 2: 
        test_type = 'both'
    else:
        raise ValueError('Invalid test type selected.')
    
    if test_type == 'sending': 
        return sending_test(data=test_data) 
    elif test_type == 'receiving':
        return receiving_test(data=test_data)
    elif test_type == 'both':
        send_res = sending_test(data=test_data) 
        rec_res = receiving_test(data=test_data)
        return send_res + rec_res


def sending_test(data) -> bool:
    success = False
    sending = data['sending'][0]
    sending_details = sending['given']
    expected_sending = sending['expected']
    print("Sending details:", sending_details)
    print("Sending expectation:", expected_sending)
    # store variables
    vin = sending_details['vin']


    recipients = sending_details['recipients']
    sp_address = recipients[0]
    
    # run sending test
    sending_run()
    return success


def receiving_test(data) -> bool:
    success = False
    receiving = data['receiving'][0]
    receiving_details = receiving['given']
    expected_receiving = receiving['expected']
    print("Receiving details:", receiving_details)
    print("Receiving expectation:", expected_receiving)
    # store variables

    # run receiving test
    receiving_run()
    return success


if __name__ == "__main__":
    b = test()
    if b: 
        print('Good job!')
    else:
        print('Try again!')

