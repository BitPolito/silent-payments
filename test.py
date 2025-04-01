import json
from sender import sending_run
from receiver import receiving_run


def test_file_reading(test_file = None): 
    # read test file
    try: 
        with open(test_file, 'r') as f:
            print('Reading file...')
            test_data = json.load(f)
    except FileNotFoundError:
        print(f'Error: file {test_file} not found.')
        return None
    except json.JSONDecodeError:
        print("Error: json file not valid.")
        return None
    return test_data


def test(test_file = 'send_and_receive_test_vectors.json', test_id = None, test_type = None) -> bool:
    # read the test file 
    test_data = test_file_reading(test_file)
    if test_data is None:
        return False
    
    # print the test list
    with open('test_list.json', 'r') as file:
        test_list = json.load(file)
    print(json.dumps(test_list['TEST LIST'], indent=4))

    if test_id is None:
        # take as input the id of the test you want to perform
        test_id = int(input('Insert the test id to select the test to perform (0-25):'))
        if test_id < 0 or test_id >= len(test_data):
            raise ValueError('Invalid test ID selected.')
    
    # extract data for the selected test
    test_data = test_data[test_id]
    comment = test_data['comment']

    if test_type is None:
        # select the type of test
        flag = int(input('Insert test type (type 0 for sending or 1 for receiving or 2 for both): '))
        match flag:
            case 0:
                test_type = 'sending'
            case 1:
                test_type = 'receiving'
            case 2: 
                test_type = 'sending and receiving'
            case _:
                raise ValueError('Invalid test type selected.')
            
    print(f'Starting the {test_type} test for test #{test_id}: {comment}')
    
    match test_type:
        case 'sending':
            return sending_test(data=test_data) 
        case 'receiving':
            return receiving_test(data=test_data)
        case 'sending and receiving':
            send_res = sending_test(data=test_data) 
            rec_res = receiving_test(data=test_data)
            return send_res + rec_res


def sending_test(data) -> bool:
    sending = data['sending'][0]
    sending_details = sending['given']
    expected_sending = sending['expected']
    print("Sending details:", sending_details)
    print("Sending expectation:", expected_sending)

    # store variables
    vin = sending_details['vin']
    recipients = sending_details['recipients'][0]

    # run sending test
    result = sending_run(vin, recipients)

    expected_output = expected_sending['outputs'][0][0]

    if result == expected_output:
        print('Sendig test passed.')
        return True 
    else:
        print('Sending test failed.')
        return False


def receiving_test(data) -> bool:
    receiving = data['receiving'][0]
    receiving_details = receiving['given']
    expected_receiving = receiving['expected']
    print("Receiving details:", receiving_details)
    print("Receiving expectation:", expected_receiving)

    # store variables
    vin = receiving_details['vin']
    outputs = receiving_details['outputs'] 
    key_material = receiving_details['key_material']
    labels = receiving_details['labels']

    # run receiving test
    address_result, outputs_result = receiving_run(vin, outputs, key_material, labels, )

    expected_addresses = expected_receiving['addresses'][0]
    expected_outputs = expected_receiving['outputs'][0]

    if address_result == expected_addresses and outputs_result == expected_outputs:
        print('Receiving test passed.')
        return True 
    else:
        print('Receiving test failed.')
        return False


if __name__ == "__main__":
    b = test()
    if b: 
        print('Good job!')
    else:
        print('Try again!')

