from cryptography.fernet import Fernet
import argparse
import json
import random
import re
import sys
import socket
import os
import signal

BUFFER_SIZE = 1024

def handler(signum, frame):
    sys.exit(0)

def parse_money(money_string):
    parts = money_string.split('.')
    amount = [0, 0]
    amount[0] = int(parts[0])
    amount[1] = int(parts[1])
    return amount

class Account:
    def __init__(self, name, balance):
        self.card_number = random.randint(1000000, 9999999)
        self.name = name
        amount = parse_money(balance)
        self.dollars = amount[0]
        self.cents = amount[1]

    def withdraw(self, amount_string):
        amount = parse_money(amount_string)
        if amount[0] < self.dollars or (amount[0] == self.dollars and amount[1] <= self.cents):
            self.dollars -= amount[0]
            self.cents -= amount[1]
            if self.cents < 0:
                self.dollars -= 1
                self.cents += 100
            return amount
        else:
            return 0

    def deposit(self, amount_string):
        amount = parse_money(amount_string)
        self.dollars += amount[0]
        self.cents += amount[1]
        if self.cents >= 100:
            self.dollars += 1
            self.cents -= 100

    def get_balance(self):
        balance_string = str(self.dollars) + '.' + str(self.cents)
        return balance_string

def authenticate(f, conn):
    ciphertext = conn.recv(BUFFER_SIZE)
    print("Received ciphertext:", ciphertext)  # Add this line to print the received ciphertext
    if not ciphertext:  # Check if ciphertext is empty
        print("Received empty ciphertext")
        return 0
    try:
        data = f.decrypt(ciphertext)
        print("Decrypted data:", data)  # Add this line for debugging
        request = json.loads(data)
        counter = request['counter']
        conn.send(f.encrypt(json.dumps({'counter': counter + 1}).encode()))
        print("Authentication successful for counter:", counter)  # Add debug print
        return counter
    except Exception as e:
        print("Authentication failed:", e)  # Add debug print
        return 0


def create(accounts, name, amount):
    response = {'success': True}
    for key in accounts:
        if accounts[key].name == name:
            response = {'success': False}
    if response['success']:
        account = Account(name, amount)
        accounts[account.card_number] = account
        response['summary'] = {'account': name, 'initial_balance': amount}
        response['card_number'] = account.card_number
        response['pin'] = random.randint(1000, 9999)  # Generate PIN
    return response

def deposit(account, amount):
    account.deposit(amount)
    response = {'success': True, 'summary': {'account': account.name, 'deposit': amount}}
    return response

def withdraw(account, amount):
    r = account.withdraw(amount)
    if r:
        response = {'success': True, 'summary': {'account': account.name, 'withdraw': amount}}
        return response
    else:
        response = {'success': False}
        return response

def getinfo(account):
    balance = account.get_balance()
    response = {'success': True, 'summary': {'account': account.name, 'balance': balance}}
    return response

def handle_request(f, conn, counter, accounts):
    try:
        ciphertext = conn.recv(BUFFER_SIZE)
        print("Received ciphertext:", ciphertext)
        if not ciphertext:
            print("Received empty ciphertext")
            return 0
        data = f.decrypt(ciphertext)
        print("Decrypted data:", data)
        request = json.loads(data)
        if request['counter'] != counter + 2:
            return 0
        account = None
        if request['operation'] == "create":
            response = create(accounts, request['name'], request['amount'])
            if response['success']:
                print("Account created. Name:", response['summary']['account'], "Balance:", response['summary']['initial_balance'], "PIN:", response['pin'])
        else:
            account = accounts[int(request['card_number'])]
            if account.name != request['name']:
                return 0
            if request['operation'] == "deposit":
                response = deposit(account, request['amount'])
                update_user_info(request['name'], account.get_balance())
            elif request['operation'] == "withdraw":
                response = withdraw(account, request['amount'])
                update_user_info(request['name'], account.get_balance())
            elif request['operation'] == "getinfo":
                response = getinfo(account)
            else:
                return 0
        response['counter'] = counter + 3
        return response
    except Exception as e:
        print("Error handling request:", e)
        return 0


def update_user_info(name, balance):
    filename = name + ".txt"
    with open(filename, 'w') as file:
        file.write(balance)

if __name__ == '__main__':
    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", help="port number", default=4001, type=int)
    parser.add_argument("-s", "--auth_file", help="auth file", nargs='?')

    args = parser.parse_args()

    if args.port < 1024 or args.port > 65535:
        parser.print_help()
        print("port must be between 1024 and 65535")
        sys.exit(255)

    pattern = re.compile(r'[_\-\.0-9a-z]{1,255}')
    auth_file_name = ""

    if args.auth_file:
        if os.path.isfile(args.auth_file):
            sys.exit(255)
        if not pattern.match(args.auth_file):
            parser.print_help()
            print(r"file name must match [_\-\.0-9a-z]{1,255}")
            sys.exit(255)
        else:
            auth_file_name = args.auth_file
    else:
        auth_file_name = "bank.auth"

    print("created")
    key = Fernet.generate_key()
    auth_file = open(auth_file_name, 'wb')
    auth_file.write(key)
    auth_file.close()

    f = Fernet(key)

    accounts = {}

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', args.port))
    s.listen(1)

    # Import statements and other initial setup omitted for brevity

while True:
    conn, addr = s.accept()
    conn.settimeout(10)
    print("Connection established with:", addr)  # Add this line to print connection establishment
    counter = authenticate(f, conn)
    if counter:
        print("Authentication successful for counter:", counter)  # Add this line to print successful authentication
        response = handle_request(f, conn, counter, accounts)
        if response:
            print("Response generated:", response)  # Add this line to print generated response
            ciphertext = f.encrypt(json.dumps(response).encode())
            try:
                conn.send(ciphertext)
                print("Response sent successfully")  # Add this line to print successful response transmission
            except:
                print("Error sending response")  # Add this line to print error in response transmission
            try:
                print(json.dumps(response['summary']))
            except KeyError:
                pass
        else:
            print("No response generated")  # Add this line to print when no response is generated
            print("protocol_error")
    else:
        print("Authentication failed")  # Add this line to print when authentication fails
        print("protocol_error")





