import argparse
import json
import random
import re
import sys
import socket
import os
import signal
from cryptography.fernet import Fernet
import hmac
import hashlib


BUFFER_SIZE = 1024
accounts = {}
auth_file_name = "bank.auth"
hmac_challange_server = None
travao = False

chave_secreta = "abak123123sjdnf.kjasd123123nf.kja123123sdfn"  ## validar HMAC Challange


def handler(signum, frame):
    print("Desligando")
    raise KeyboardInterrupt()


def handler_int(signum, frame):
    raise KeyboardInterrupt()
    print("Desligando")
    sys.exit(0)


def parse_money(money_string):
    money_string = money_string + 0.0
    parts = str(money_string).split('.')
    amount = [0, 0]
    amount[0] = int(parts[0])
    amount[1] = int(parts[1])
    return amount


def lerChave():
    global auth_file_name
    try:
        with open(auth_file_name, 'rb') as f_auth:
            return f_auth.read().strip()
    except IOError as e:
        print("Error reading authentication file:", e)  # Add debug print
        sys.exit(255)


class Account:
    ## Criar novo cartao
    ## id, nome, balance,
    def __init__(self, name, balance):
        self.card_number = random.randint(1000000, 9999999)
        self.pin = random.randint(1000, 9999)
        self.name = name
        amount = parse_money(balance)
        self.dollars = amount[0]
        self.cents = amount[1]
        self.salt = random.randint(1000000, 9999999)

    ####################### MEXER BEGIN

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
            return False

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

    ####################### MEXER END

    def validadeCard(self, resume):
        resumo_gen = self.calculateResume()
        return hmac.compare_digest(resumo_gen, resume)

    def calculateResume(self):
        return gerar_hmac("asdfadsfadsf" + str(self.pin) + self.name + str(self.card_number) + str(self.salt))


def tirarDaCripta(ciphertext):
    fernet_obj = Fernet(lerChave())
    return fernet_obj.decrypt(ciphertext)


def colocarNaCripta(plainText):
    fernet_obj = Fernet(lerChave())
    return fernet_obj.encrypt(plainText)


def gerar_hmac(mensagem):
    global chave_secreta
    chave_secreta_bytes = bytes(chave_secreta, 'utf-8')
    mensagem_bytes = bytes(mensagem, 'utf-8')
    hmac_objeto = hmac.new(chave_secreta_bytes, mensagem_bytes, hashlib.sha256)
    hmac_gerado = hmac_objeto.hexdigest()
    return hmac_gerado


def genNewChallange(conn):
    global chave_secreta

    desafio = random.randint(100000000, 999999999)
    json_ = json.dumps({'MatrixChallange': desafio})
    cypherText = colocarNaCripta(json_.encode("utf-8"))
    conn.send(cypherText)

    desafio = "Cifrar" + str(desafio + 23634562) + "Criptar"
    hmac_Server = gerar_hmac(desafio)

    return hmac_Server


def validateMatrixChallange(hmacClient, hmacServer):
    return hmac.compare_digest(hmacClient, hmacServer)


def validadeResumeRequest(request):
    request_dict = json.loads(request)
    resumoRequest = request_dict.pop('resumo')
    hmac_gerado = gerar_hmac("nadaFoiAlterado" + json.dumps(request_dict, sort_keys=True) + "nadaFoiAlterado")
    return hmac.compare_digest(hmac_gerado, resumoRequest)

## Cria cartão e verifica se já existe e se o user tbm já existe
def create(name, amount):
    global accounts
    response = {'success': True}

    # Verifica se o usuário já foi criado
    for card_number, conta in accounts.items():
        if conta.name == name:
            return {'success': False, 'message': 'User already exists'}

    # Verifica se o arquivo do cartão já existe
    card_file = f"{name}.card"
    if os.path.exists(card_file):
        return {'success': False, 'message': 'Card file already exists'}

    conta = Account(name, amount)
    accounts[conta.card_number] = conta

    response['summary'] = "{\"account\": \"", conta.name, "\", \"initial_balance\": ", conta.get_balance(), "}"
    response['cardResume'] = conta.calculateResume()

    # Salva temporariamente as informações do cartão em um arquivo
    with open(card_file, 'w') as f:
        json.dump({
            'card_number': conta.card_number,
            'pin': conta.pin,
            'balance': conta.get_balance()
        }, f)

    return response



if __name__ == '__main__':
    ## LOADUP START BANK

    signal.signal(signal.SIGINT, handler_int)
    signal.signal(signal.SIGTERM, handler)

    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", help="port number", default=4001, type=int)
    parser.add_argument("-s", "--auth_file", help="auth file", default="bank.auth", nargs='?')

    args = parser.parse_args()

    if args.port < 1024 or args.port > 65535:
        parser.print_help()
        print("port must be between 1024 and 65535")
        sys.exit(255)

    pattern = re.compile(r'[_\-\.0-9a-z]{1,255}')

    if args.auth_file:  ## REMOVER FALSE
        if os.path.isfile(args.auth_file):  ## se ficheiro existe
            sys.exit(255)
        if not pattern.match(args.auth_file):  ## se nome ficheiro for incorrecto
            parser.print_help()
            print(r"file name must match [_\-\.0-9a-z]{1,255}")
            sys.exit(255)
        ## se ficheiro Auth não existe, então o nome passa a ser este
        auth_file_name = args.auth_file
        print("created")
        key = Fernet.generate_key()
        auth_file = open(auth_file_name, 'wb')
        auth_file.write(key)
        auth_file.close()
    ## FIM LOADUP

    ## cria connection
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', args.port))
    s.listen(1)
    
    while True:
        print("Ready for connection")

        conn, addr = s.accept()
        conn.settimeout(10)
        print("Connection established with:", addr)

        ciphertext = conn.recv(BUFFER_SIZE)
        #print("Received ciphertext:", ciphertext)
        if not ciphertext:
            print("Received empty ciphertext") ############### VER O QUE FAZER AQUI
        
        data = tirarDaCripta(ciphertext)
        print("Decrypted data:", data)

        request = json.loads(data)
        type = request['type']
        if type == "genChallange":
            hmac_challange_server = genNewChallange(conn) ## gera e Envia

        ciphertext = conn.recv(BUFFER_SIZE)
        ##print("Received ciphertext:", ciphertext)
        if not ciphertext:
            print("Received empty ciphertext") ############### VER O QUE FAZER AQUI

        data = tirarDaCripta(ciphertext)
        print("Decrypted data:", data, end="\n\n")
        request_str = data.decode('utf-8')
        
        if (not validadeResumeRequest(request_str)):
            print("RESUMO INVALIDO")                ########### VER O QUE FAZER AQUI

        print ("Resumo Operação Valido")    

        dicionario  = json.loads(request_str)
        if not(validateMatrixChallange(dicionario['nounce'], hmac_challange_server)):
            print("NOUNCE INVALIDO")                 ########### VER O QUE FAZER AQUI
        print ("Nounce Valido")



        type = dicionario['type']

        if type == "createAcc":
            response = create(dicionario['nome'], dicionario['valor'])
            print(response)
            if response['success']:
                sumario = response['summary']
                print(sumario)
            else:
                print("erro criar Cartão")
            
        elif type == "deposit":
            ##Validar Cartão
            pass
        elif type == "levantar":
            ##Validar Cartão
            pass
        elif type == "consultar":
            ##Validar Cartão
            pass
        else:
            print("Esta é a opção padrão, caso nenhuma das anteriores se aplique.")
