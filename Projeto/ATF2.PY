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


        ## função responsavel por ler a chave no ATM
def lerChave():
    try:
        with open(args.authfile, 'rb') as f_auth:
            return f_auth.read().strip()
    except IOError as e:
        print("Error reading authentication file:", e)  # Add debug print
        sys.exit(255)

def leCartao():
    pass
##### coisas aqui



def send(json_):
    fernet_obj = Fernet(lerChave())
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    try:
        s.connect((args.ip, args.port))
    except (socket.error, socket.timeout) as e:
        s.close()
        sys.exit(63)
    ## ENVIAR
    json_string1 = json.dumps(json_)
    print("Sending authentication request:", json_string1)  # Add this line for debugging
    try:
        msg = fernet_obj.encrypt(json_string1.encode())
        s.send(msg)
    except (socket.error, socket.timeout) as e:
        s.close()
        sys.exit(63)


    ##RECEBER
    try:
        json_string2 = s.recv(1024)
    except (socket.error, socket.timeout) as e:
        s.close()
        sys.exit(63)

    print("Received ciphertext:", json_string2)  # Add this line to print the received ciphertext

    ##decifrar
    data = fernet_obj.decrypt(json_string2)
    print("Decrypted data:", data)



# ## verifica cartao
# if args.cardfile == None:
#     args.cardfile = args.account + ".card"


# ## verifica Argumentos
# if args.getinfo == False:
#     if args.balance != None:
#         is_valid_amount(args.balance)
#     elif args.deposit != None:
#         is_valid_amount(args.deposit)
#     else:
#         is_valid_amount(args.withdraw)

# try:
#     with open(args.authfile, 'rb') as f_auth:
#         secret_key = f_auth.read().strip()
# except IOError as e:
#     sys.exit(255)



# if args.balance != None:
#     operation = 'create'
# elif args.deposit != None:
#     operation = 'deposit'
# elif args.withdraw != None:
#     operation = 'withdraw'
# else:
#     operation = 'getinfo'


json_obj1 = {'type': "genChallange"}
send(json_obj1)