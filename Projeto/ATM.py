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
parser.add_argument("-p", help="bank's port number", action="store", dest='port', type=int, default=3000)
parser.add_argument("-c", help="card-file", action="store", dest='cardfile')
parser.add_argument("-a", help="account", action="store", required=True, dest='account')
group.add_argument("-n", help="balance when create an account", action="store", dest='balance')
group.add_argument("-d", help="amount when deposit", action="store", dest='deposit')
group.add_argument("-w", help="amount when withdraw", action="store", dest='withdraw')
group.add_argument("-g", help="get the information about account", action="store_true", dest='getinfo')

args = parser.parse_args()

if args.cardfile == None:
    args.cardfile = args.account + "args.balance"

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

# Open authentication file to get the secret_key
try:
    with open(args.authfile, 'rb') as f_auth:
        secret_key = f_auth.read().strip()
except IOError as e:
    sys.exit(255)

# Open card file to get the card number
try:
    with open(args.cardfile, 'rb') as f_card:
        card_num = int(f_card.read().strip())
except IOError as e:
    if args.balance != None:
        card_num = 0
    else:
        sys.exit(255)

# Generate a random number for authentication with bank
token = int(math.ceil(random.random()*10000000))

# Determine operation
if args.balance != None:
    operation = 'create'
elif args.deposit != None:
    operation = 'deposit'
elif args.withdraw != None:
    operation = 'withdraw'
else:
    operation = 'getinfo'

# Encryption
fernet_obj = Fernet(secret_key)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.settimeout(10)
try:
    s.connect((args.ip, args.port))
except (socket.error, socket.timeout) as e:
    s.close()
    sys.exit(63)

json_obj1 = {'counter': token}
json_string1 = json.dumps(json_obj1)
try:
    s.send(fernet_obj.encrypt(json_string1.encode()))
except (socket.error, socket.timeout) as e:
    s.close()
    sys.exit(63)

try:
    json_string2 = s.recv(1024)
except (socket.error, socket.timeout) as e:
    s.close()
    sys.exit(63)
try:
    json_obj2 = json.loads(fernet_obj.decrypt(json_string2).decode())
except:
    s.close()
    sys.exit(255)
# Authenticate failure
if json_obj2['counter'] != token+1:
    s.close()
    sys.exit(255)

json_obj3 = {'counter': token+2, 'card_number': card_num, 'operation': operation, 'amount': args.balance or args.deposit or args.withdraw, 'name': args.account}
json_string3 = json.dumps(json_obj3)
try:
    s.send(fernet_obj.encrypt(json_string3.encode()))
except (socket.error, socket.timeout) as e:
    sys.exit(63)

try:
    json_string4 = s.recv(1024)
except (socket.error, socket.timeout) as e:
    s.close()
    sys.exit(63)

json_obj4 = json.loads(fernet_obj.decrypt(json_string4).decode())
if json_obj4['counter'] != token+3:
    s.close()
    sys.exit(255)
if json_obj4['success'] == False:
    s.close()
    sys.exit(255)
if args.balance != None:
    with open(args.cardfile, 'wb+') as f_card:
        f_card.write(str(json_obj4['card_number']))
print(json.dumps(json_obj4['summary']))
s.close()