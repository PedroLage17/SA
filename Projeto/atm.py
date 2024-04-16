import socket
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
import argparse
import sys
import re
import random

import signal
import json
import hmac
import hashlib
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64


BUFFER_SIZE = 8192
chave_secreta = "abak123123sjdnf.kjasd123123nf.kja123123sdfn" ## validar HMAC Challange

chave_aes = None
chave_publica = None


parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()
parser.add_argument("-s", help="authentication file", action="store", dest='authfile', default="bank.auth")
parser.add_argument("-i", help="bank's ip address", action="store", dest='ip', default="127.0.0.1")
parser.add_argument("-p", help="bank's port number", action="store", dest='port', type=int, default=3000)
parser.add_argument("-c", help="card-file", action="store", dest='cardfile', default=None)
parser.add_argument("-a", help="account", action="store", required=True, dest='account')
group.add_argument("-n", help="balance when create an account", action="store", dest='balance')
group.add_argument("-d", help="amount when deposit", action="store", dest='deposit')
group.add_argument("-w", help="amount when withdraw", action="store", dest='withdraw')
group.add_argument("-g", help="get the information about account", action="store_true", dest='getinfo')

args = parser.parse_args()

def handler(signum, frame):
    print("Desligando")
    raise KeyboardInterrupt()


def handler_int(signum, frame):
    print("Desligando")
    sys.exit(0)


## BEGIN RSA

def cifrar_com_publica( mensagem):
    global chave_publica
    chave = RSA.import_key(chave_publica)
    cifrador = PKCS1_OAEP.new(chave)
    mensagem_cifrada = cifrador.encrypt(mensagem)
    return mensagem_cifrada


def verificar_assinatura(mensagem, assinatura_base64):
    global chave_publica
    chave = RSA.import_key(chave_publica)
    h = SHA256.new(mensagem.encode())
    assinatura = base64.b64decode(assinatura_base64)
    try:
        pkcs1_15.new(chave).verify(h, assinatura)
        return True  
    except (ValueError, TypeError):
        return False 


## END RSA



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


def lerChave(auth_file_name):
    global chave_aes
    global chave_publica
    try:
        with open(auth_file_name, 'r') as file:
            linhas = [linha.strip() for linha in file.readlines()]
            chave_aes = linhas[0]  # A chave AES é a primeira linha
            chave_publica = "\n".join(linhas[1:])
    except IOError as e:
        sys.exit(255)






def tirarDaCripta(ciphertext):
    global chave_aes
    fernet_obj = Fernet(chave_aes)
    return fernet_obj.decrypt(ciphertext)


def colocarNaCripta(plainText):
    global chave_aes
    fernet_obj = Fernet(chave_aes)
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
        desafio = "Cifrar"+str(int(puzzle)+23634562)+"Criptar"
        hmac_Client = gerar_hmac(desafio)
        return hmac_Client
    except Exception as e:
        sys.exit(63)

def validateMatrixChallange(hmacClient, hmacServer):
    return hmac.compare_digest(hmacClient, hmacServer)


def validadeResumeRequest(request):
    request_dict = json.loads(request)
    resumoRequest = request_dict.pop('resumo')
    hmac_gerado = gerar_hmac("nadaFoiAlterado" + json.dumps(request_dict, sort_keys=True) + "nadaFoiAlterado")
    return hmac.compare_digest(hmac_gerado, resumoRequest)

def genNewChallange():
    global chave_secreta
    desafio = random.randint(100000000, 999999999)
    desafioResolvido = "Cifrar" + str(desafio + 23634562) + "Criptar"
    hmac_ATM = gerar_hmac(desafioResolvido)

    return hmac_ATM, desafio


def send(type, nomePessoa, valor = None, cartao = None ):
    getChallange = {'type': "genChallange"}
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    try:
        s.connect((args.ip, args.port))
        # ENVIAR solicitação de desafio
        json_string1 = json.dumps(getChallange)
        msg = colocarNaCripta(json_string1.encode())
        msg_cifrada_RSA_public = cifrar_com_publica(msg)
        s.send(msg_cifrada_RSA_public)

        json_string2 = s.recv(BUFFER_SIZE)  # RECEBER o desafio + Assinatura
        data = tirarDaCripta(json_string2)
        request = json.loads(data)
        if "protocolError" in request and 'protocolErrorSigned' in request and verificar_assinatura(str(request['protocolError'])+"aaa", request['protocolErrorSigned']):
            print(request['protocolError'])
            sys.exit(request['protocolError'])

        if not 'MaChSigned' in request:
            sys.exit(63)

        if not 'MatrixChallange' in request:
            sys.exit(63)

        assinatura = request['MaChSigned']
        MatrixChallange = request['MatrixChallange']
        if not(verificar_assinatura(str(MatrixChallange), assinatura)):
            sys.exit(63)
        
        ## até aqui tá bom
        MatrixChallangeSolved = solveChallange(MatrixChallange)

        # Gerar um novo desafio para a resposta
        hmac_ATM, desafinovo = genNewChallange()
        
        # Construir o pedido para o banco
        pedido = {
            'type': type,
            'nome': nomePessoa,
            'valor': valor,
            'cartao': cartao,
            'nounce': MatrixChallangeSolved,
            'novoNounce': desafinovo
        }
        pedido['resumo'] = gerar_hmac("nadaFoiAlterado" + json.dumps(pedido, sort_keys=True) + "nadaFoiAlterado")

        pedido_json = json.dumps(pedido)
        pedido_bytes = pedido_json.encode('utf-8')


        ##GERAR a chave AES que o MiM nunca lhe Bai por a Bista Em Cima
        key_AntiMiM = Fernet.generate_key()
        ferAnti_MiM = Fernet(key_AntiMiM)
        pedidoEncapsulado = ferAnti_MiM.encrypt(pedido_bytes)

        chaveCifradaAntiMiM = cifrar_com_publica(key_AntiMiM)

        capsula = {
            'pedidoEncapsulado': base64.b64encode(pedidoEncapsulado).decode('utf-8'),
            'chaveCifradaAntiMiM': base64.b64encode(chaveCifradaAntiMiM).decode('utf-8'),
        }

        R = json.dumps(capsula)
        msg = colocarNaCripta(R.encode())
        s.send(msg)



        # RECEBER A RESPOSTA DO BANCO
        try:
            json_string2 = s.recv(BUFFER_SIZE)
            data = ferAnti_MiM.decrypt(json_string2)
            if (not validadeResumeRequest(data)):
                sys.exit(63)

            dicionario  = json.loads(data)
            if not(validateMatrixChallange(dicionario['nounce'], hmac_ATM)):
                sys.exit(63)
        except(InvalidToken):
            sys.exit(63)


        return dicionario  # retorna a resposta do banco

    except (socket.error, socket.timeout) as e:
        s.close()
        sys.exit(63)


###CRIAÇÂO DO CARTÃO
def verificar_existencia_arquivo(nomePessoa, caminho_arquivo=None, temDeExistirMesmoOCartao = False):
    check_path_traversal(caminho_arquivo)
    if temDeExistirMesmoOCartao and caminho_arquivo == None:
        return False
    if ((caminho_arquivo) == None and (not (temDeExistirMesmoOCartao))): ## só no caso de criar, é que não existe e vem  a False
        caminho_arquivo = nomePessoa+".card" ## logo entraria AQUI
    return os.path.exists(caminho_arquivo)


def criar_cartao(args):

    ## verificar nomes, todas as ceninnhas a verificar
    if args.balance is not None:  # Check if balance is provided
        user_balance = float(args.balance)
    else:
        user_balance = 0  # Default balance if not provided

    resposta = send("createAcc", args.account ,user_balance)
    if not resposta['param1'] == str(255):
        if args.cardfile == None:
            nomeCard = args.account+".card"
        else:
            nomeCard = args.cardfile
        with open(nomeCard, 'w') as f:
            f.write(resposta['param1']) ## vem o primeiro parametro, neste caso o resumo do cartão 

        print(resposta['param2']) ## vem o segundo parametro, neste caso o sumario 
    else:
        sys.exit(255)
    

def ler_cartao(nome):
    
    try:
        with open(nome, 'r') as f_card:
            return f_card.readline()
    except IOError as e:
        print("O arquivo do cartão não existe.")



def withdraw_from_card(args):
    resumoCartao = ler_cartao(args.cardfile)
    data = send("levantar", args.account, args.withdraw, resumoCartao)
    if data['param1'] == str(255) or data['param1'] == 255:
        sys.exit(255)
    print(data['param1'])



def deposit_to_card(args):
    resumoCartao = ler_cartao(args.cardfile)
    data = send("deposit", args.account, args.deposit, resumoCartao)
    if data['param1'] == str(255) or data['param1'] == 255:
        sys.exit(255)
    print(data['param1'])

   

def get_account_info(args):
    resumoCartao = ler_cartao(args.cardfile)
    data = send("consultar", args.account, 0, resumoCartao)
    if data['param1'] == str(255) or data['param1'] == 255:
        sys.exit(255)
    print(data['param1'])


def is_money(value):
    # Regex ajustada para considerar a parte inteira opcional quando o ponto está presente
    if re.match(r'^(\d{1,10})?(\.\d{2})?$', value):
        parts = value.split('.')
        # Verifica se a parte inteira está presente e não excede o limite
        if len(parts) == 2 and parts[0] == '':  # Caso de ".99"
            return True
        elif len(parts) == 2 and int(parts[0]) <= 4294967295:
            return True
        elif len(parts) == 1 and int(parts[0]) <= 4294967295:  # Caso apenas inteiro
            return True
    return False


def check_path_traversal(user_input):
    # Regex para detectar padrões comuns de path traversal
    patterns = [
        r'\.\./',  # Unix-like path traversal
        r'\.\.\\',  # Windows path traversal
        r'/\.\./',  # Encoded Unix-like path traversal
        r'\\\.\.\\'  # Encoded Windows path traversal
    ]
    
    # Verifica cada padrão usando expressões regulares
    if user_input != None:
        for pattern in patterns:
            if re.search(pattern, user_input):
                sys.exit(255)
    
    
def validate_command_line_arguments(args):
    # Serializa os argumentos para uma string como se fossem fornecidos na linha de comando
    combined_args = ' '.join(f"{key} {value}" for key, value in vars(args).items() if value is not None)
    # Checa se o comprimento total excede 4096 caracteres
    if len(combined_args) > 4096:
        sys.exit(255)  # Encerra o programa se exceder o comprimento máximo


def validate_exclusive_arguments(args):
    arguments = [args.balance, args.getinfo, args.deposit, args.withdraw]
    # Conta apenas argumentos que são True ou não-None (para argumentos não-flag).
    provided_args = sum(arg is not None and arg is not False for arg in arguments)
    if provided_args > 1:
        sys.exit(255)


def main():
    signal.signal(signal.SIGINT, handler_int)
    signal.signal(signal.SIGTERM, handler)
    check_path_traversal(args.authfile)
    validate_command_line_arguments(args)

    validate_exclusive_arguments(args)
    lerChave(args.authfile)

    if args.balance: ## QUERO criar conta
        ## ver se cartão com o nome já existe
        if not(verificar_existencia_arquivo(args.account, args.cardfile))  and (is_money(args.balance)): ## se cartão não existe
            if (float(args.balance)>=0.0):
                criar_cartao(args)
        else:
            sys.exit(255)
    elif args.getinfo:
        if (verificar_existencia_arquivo(args.account, args.cardfile, True )): ## se cartão não existe
            get_account_info(args)
        else:
            sys.exit(255)
    elif args.deposit is not None:
        if (verificar_existencia_arquivo(args.account, args.cardfile, True )) and (is_money(args.deposit)): ## se cartão não existe
            if (float(args.deposit)>0.0):
                deposit_to_card(args)
        else:
            sys.exit(255)
    elif args.withdraw is not None:
        if (verificar_existencia_arquivo(args.account, args.cardfile, True )) and (is_money(args.withdraw) ): ## se cartão não existe
            if (float(args.withdraw)>0.0):
                withdraw_from_card(args)
        else:
            sys.exit(255)
    else:
        sys.exit(255)


if __name__ == "__main__":
    main()
