import socket
from cryptography.fernet import Fernet
import argparse
import sys
import re
import random
import math
import json
import hmac
import hashlib
import os

BUFFER_SIZE = 1024
chave_secreta = "abak123123sjdnf.kjasd123123nf.kja123123sdfn" ## validar HMAC Challange


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

def solveChallange(puzzle):
    global chave_secreta
    try:
        desafio = "Cifrar"+str(puzzle+23634562)+"Criptar"
        print(desafio)
        hmac_Client = gerar_hmac(desafio)
        # print("puzzle resolvido")
        # print("\n\n\n" + hmac_Client+ "\n\n\n")
        return hmac_Client
    except Exception as e:
        print("Authentication failed:", e)
        return 0


def send(type, nomePessoa, valor = None, cartao = None ):
    getChallange = {'type': "genChallange"}
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    try:
        s.connect((args.ip, args.port))
        ## ENVIAR RequestChallange
        json_string1 = json.dumps(getChallange)
        print("Sending authentication request:", json_string1)  # Add this line for debugging
        msg = colocarNaCripta(json_string1.encode())
        s.send(msg)
        json_string2 = s.recv(1024)##RECEBER o challange
        print("Received ciphertext:", json_string2) 
            ##decifrar
        data = tirarDaCripta(json_string2)
        request = json.loads(data)
        MatrixChallange = request['MatrixChallange']
        print(MatrixChallange)
        MatrixChallangeSolved = solveChallange(MatrixChallange)
        # createAcc deposit levantar consultar # types possiveis
        novoNounce = random.randint(100000000, 999999999)
        pedido = {
            'type': type,
            'nome': nomePessoa,
            'cartao': cartao,
            'valor': valor,
            'nounce': MatrixChallangeSolved,
            'novoNounce': novoNounce
            }
        pedido['resumo'] = gerar_hmac("nadaFoiAlterado" + json.dumps(pedido, sort_keys=True) + "nadaFoiAlterado")
        R = json.dumps(pedido)
        msg = colocarNaCripta(R.encode())
        s.send(msg)
        print("Pedido SENT")


    except (socket.error, socket.timeout) as e:
        s.close()
        sys.exit(63)







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

###CRIAÇÂO DO CARTÃO
def verificar_existencia_arquivo(caminho_arquivo):
    return os.path.exists(caminho_arquivo)

def criar_cartao(args):
    card_num = random.randint(1000000, 9999999)
    user_balance = float(args.balance)
    pin = random.randint(1000, 9999)
    with open(args.cardfile, 'w') as f:
        f.write(json.dumps({'account': args.account, 'card_number': card_num, 'balance': args.balance, 'pin': pin}))
    print("Cartão criado com sucesso.")

def ler_cartao(args):
    try:
        with open(args.cardfile, 'rb') as f_card:
            card_data = json.load(f_card)
            card_num = int(card_data.get('card_number', 0))
            user_balance = float(card_data.get('balance', 0))
            pin = int(card_data.get('pin', 0))
            print("Cartão encontrado. Número do cartão:", card_num)
            # Faça o que precisa com as informações do cartão aqui
    except IOError as e:
        print("O arquivo do cartão não existe.")

def main():
    if verificar_existencia_arquivo(args.cardfile):
        print("O arquivo do cartão já existe.")
        ler_cartao(args)
    else:
        print("O arquivo do cartão não existe. Criando...")
        criar_cartao(args)

if __name__ == "__main__":
    main()


###send("createAcc","bob", 1010)