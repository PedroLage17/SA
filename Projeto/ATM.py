import socket
from cryptography.fernet import Fernet
import argparse
import sys
import re
import random
import math
import json

BUFFER_SIZE = 1024

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()
parser.add_argument("-s", help="authentication file", action="store", dest='authfile', default="bank.auth")
parser.add_argument("-i", help="bank's ip address", action="store", dest='ip', default="127.0.0.1")
parser.add_argument("-p", help="bank's port number", action="store", dest='port', type=int, default=4001)
parser.add_argument("-c", help="card-file", action="store", dest='cardfile')
parser.add_argument("-a", help="account", action="store", required=True, dest='account')
group.add_argument("-n", help="balance when create an account", action="store", dest='balance')
group.add_argument("-d", help="amount when deposit", action="store", dest='deposit')
group.add_argument("-w", help="amount when withdraw", action="store", dest='withdraw')
group.add_argument("-g", help="get the information about account", action="store_true", dest='getinfo')

args = parser.parse_args()

if args.cardfile == None:
    args.cardfile = args.account + ".card"

# Check if the amount is valid
def is_valid_amount(amount):
    if re.match("(0|[1-9][0-9]*).[0-9][0-9]", amount):
        amount_parts = amount.split(".")
        num1 = int(amount_parts[0])
        if args.balance != None and num1 < 10:
            sys.exit(255)
        if(num1 > 4294967295 or num1 <= 0):
            sys.exit(255)
    else:
        sys.exit(255)

if args.getinfo == False:
    if args.balance != None:
        is_valid_amount(args.balance)
    elif args.deposit != None:
        is_valid_amount(args.deposit)
    else:
        is_valid_amount(args.withdraw)

try:
    with open(args.authfile, 'rb') as f_auth:
        secret_key = f_auth.read().strip()
except IOError as e:
    sys.exit(255)

try:
    with open(args.cardfile, 'rb') as f_card:
        card_data = json.load(f_card)
        card_num = int(card_data.get('card_number', 0))
        user_balance = float(card_data.get('balance', 0))
        pin = int(card_data.get('pin', 0))
except IOError as e:
    if args.balance != None:
        card_num = random.randint(1000000, 9999999)
        user_balance = float(args.balance)
        pin = random.randint(1000, 9999)
        with open(args.cardfile, 'w') as f:
            f.write(json.dumps({'account': args.account, 'card_number': card_num, 'balance': args.balance, 'pin': pin}))
    else:
        sys.exit(255)

token = int(math.ceil(random.random()*10000000))

if args.balance != None:
    operation = 'create'
elif args.deposit != None:
    operation = 'deposit'
elif args.withdraw != None:
    operation = 'withdraw'
else:
    operation = 'getinfo'

fernet_obj = Fernet(secret_key)

try:
    with open(args.authfile, 'rb') as f_auth:
        secret_key = f_auth.read().strip()
except IOError as e:
    print("Error reading authentication file:", e)  # Add debug print
    sys.exit(255)

# Check if the encryption key is correct
print("Encryption key:", secret_key)  # Add debug print

# Initialize Fernet with the encryption key
try:
    fernet_obj = Fernet(secret_key)
except Exception as e:
    print("Error initializing Fernet with the encryption key:", e)
    sys.exit(255)

# Now you can proceed to establish a connection with the bank
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(10)
try:
    s.connect((args.ip, args.port))
except (socket.error, socket.timeout) as e:
    s.close()
    sys.exit(63)

# Rest of your code for sending requests to the bank and handling responses goes here

json_obj1 = {'counter': token}
json_string1 = json.dumps(json_obj1)
print("Sending authentication request:", json_string1)  # Add this line for debugging
try:
    s.send(fernet_obj.encrypt(json_string1.encode()))
except (socket.error, socket.timeout) as e:
    s.close()
    sys.exit(63)

# Add debug print to print the sent ciphertext
print("Sent ciphertext:", fernet_obj.encrypt(json_string1.encode()))  # Add this line to print the sent ciphertext

try:
    json_string2 = s.recv(1024)
except (socket.error, socket.timeout) as e:
    s.close()
    sys.exit(63)

# Add debug print to print the received ciphertext
print("Received ciphertext:", json_string2)  # Add this line to print the received ciphertext

try:
    json_obj2 = json.loads(fernet_obj.decrypt(json_string2).decode())
    print("Decrypted data from ATM:", json_obj2)  # Add this line to print the decrypted data
except Exception as e:
    print("Error decrypting data from ATM:", e)  # Add this line to print the error message
    s.close()
    sys.exit(255)

# Import statements and other initial setup omitted for brevity

json_obj3 = {'counter': token+2, 'card_number': card_num, 'operation': operation, 'amount': args.balance or args.deposit or args.withdraw, 'name': args.account, 'pin': pin}
json_string3 = json.dumps(json_obj3)

print("Sending request to bank:", json_obj3)

try:
    s.send(fernet_obj.encrypt(json_string3.encode()))
    print("Request sent successfully")
except Exception as e:
    print("Error sending request to bank:", e)
    s.close()
    sys.exit(255)

# Receiving response from the bank
try:
    json_string2 = s.recv(BUFFER_SIZE)
    print("Received ciphertext:", json_string2)
except (socket.error, socket.timeout) as e:
    print("Error receiving response from bank:", e)
    s.close()
    sys.exit(255)

# Decrypting the response from the bank
try:
    json_obj4 = json.loads(fernet_obj.decrypt(json_string2).decode())
    print("Decrypted data from ATM:", json_obj4)
except Exception as e:
    print("Error decrypting data from ATM:", e)
    s.close()
    sys.exit(255)

# Ensure the 'counter' key is present in the response
if 'counter' not in json_obj4:
    print("Counter key not found in response from bank")
    s.close()
    sys.exit(255)

# Check if the 'counter' value matches the expected value
if json_obj4['counter'] != token+1:
    print("Counter mismatch in response from bank")
    s.close()
    sys.exit(255)

if json_obj4['success'] == False:
    print("Transaction failed:", json_obj4.get('error_message', 'Unknown error'))
    s.close()
    sys.exit(255)

if args.withdraw != None:
    user_balance = json_obj4['balance']
    with open(args.cardfile, 'r+') as f:
        user_info = json.load(f)
        user_info['balance'] = user_balance
        f.seek(0)
        f.write(json.dumps(user_info))
        f.truncate()

print("Operation Successful!")
print("Transaction Summary:", json.dumps(json_obj4['summary']))
s.close()