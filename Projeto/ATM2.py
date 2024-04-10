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
        desafio = "Cifrar"+str(int(puzzle)+23634562)+"Criptar"
        hmac_Client = gerar_hmac(desafio)
        return hmac_Client
    except Exception as e:
        print("Authentication failed:", e)
        return 0

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
        hmac_ATM, desafinovo = genNewChallange()
        pedido = {
            'type': type,
            'nome': nomePessoa,
            'cartao': cartao,
            'valor': valor,
            'nounce': MatrixChallangeSolved,
            'novoNounce': desafinovo
        }
        pedido['resumo'] = gerar_hmac("nadaFoiAlterado" + json.dumps(pedido, sort_keys=True) + "nadaFoiAlterado")
        R = json.dumps(pedido)
        msg = colocarNaCripta(R.encode())
        s.send(msg) ## envio do pedido
        print("Pedido SENT")



        ## RECEBER A RESPOSTA
        json_string2 = s.recv(1024)
        ##decifrar
        data = tirarDaCripta(json_string2)
   


        if (not validadeResumeRequest(data)):
            print("RESUMO INVALIDO")                ########### VER O QUE FAZER AQUI
        print ("Resumo Operação Valido")    
        dicionario  = json.loads(data)
        if not(validateMatrixChallange(dicionario['nounce'], hmac_ATM)):
            print("NOUNCE INVALIDO")                 ########### VER O QUE FAZER AQUI
        print ("Nounce Valido")

        return dicionario ## a função acaba aqui e retorna a resposta do banco





    except (socket.error, socket.timeout) as e:
        s.close()
        sys.exit(63)


###CRIAÇÂO DO CARTÃO
def verificar_existencia_arquivo(caminho_arquivo):
    return os.path.exists(caminho_arquivo)

def criar_cartao(args):

    ## verificar nomes, todas as ceninnhas a verificar
    if args.balance is not None:  # Check if balance is provided
        user_balance = float(args.balance)
    else:
        user_balance = 0  # Default balance if not provided

    resposta = send("createAcc", args.account ,user_balance)

    with open(args.cardfile, 'w') as f:
        f.write(resposta['param1']) ## vem o primeiro parametro, neste caso o resumo do cartão 

    print(resposta['param2']) ## vem o segundo parametro, neste caso o sumario 
    

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

def withdraw_from_card(args):
    try:
        with open(args.cardfile, 'r+') as f_card:
            card_data = json.load(f_card)
            card_num = int(card_data.get('card_number', 0))
            user_balance = float(card_data.get('balance', 0))
            pin = int(card_data.get('pin', 0))
            print("Cartão encontrado. Número do cartão:", card_num)
            # Verificar se há saldo suficiente para a retirada
            if args.withdraw is not None:
                withdraw_amount = float(args.withdraw)
                if withdraw_amount <= user_balance:
                    user_balance -= withdraw_amount
                    card_data['balance'] = user_balance  # Atualizar o saldo no dicionário
                    f_card.seek(0)  # Voltar ao início do arquivo
                    f_card.truncate()  # Limpar o conteúdo existente
                    json.dump(card_data, f_card)  # Escrever o novo conteúdo
                    print("Retirada de", args.withdraw, "realizada com sucesso.")
                else:
                    print("Saldo insuficiente para a retirada.")
            else:
                print("Nenhuma quantia especificada para retirada.")
    except IOError as e:
        print("O arquivo do cartão não existe.")


def deposit_to_card(args):
    try:
        with open(args.cardfile, 'r') as f_card:
            card_data = f_card.read()
            # card_num = int(card_data.get('card_number', 0))
            # user_balance = float(card_data.get('balance', 0))
            # pin = int(card_data.get('pin', 0))
            # print("Cartão encontrado. Número do cartão:", card_num)
            # # Verificar se há uma quantidade válida de depósito
            # if args.deposit is not None:
            #     deposit_amount = float(args.deposit)
            #     if deposit_amount > 0:
            #         user_balance += deposit_amount
            #         card_data['balance'] = user_balance  # Atualizar o saldo no dicionário
            #         f_card.seek(0)  # Voltar ao início do arquivo
            #         f_card.truncate()  # Limpar o conteúdo existente
            #         json.dump(card_data, f_card)  # Escrever o novo conteúdo
            #         print("Depósito de", args.deposit, "realizado com sucesso.")
            #     else:
            #         print("O valor do depósito deve ser maior que zero.")
            # else:
            #     print("Nenhuma quantia especificada para depósito.")


                    
        valor = 0 ## DEFINIR
        #SEND( OPERATION, NOME_PESSOA, VALUE, CONTEUDO_CARTÃO_PESSOA )
        resposta = send("deposit", args.account ,valor, card_data)

        print(resposta['param1'])
        print(resposta['param2'])
        print(resposta['param3'])


    except IOError as e:
        print("O arquivo do cartão não existe.")


def get_account_info(args):
    try:
        with open(args.cardfile, 'r') as f_card:
            card_data = json.load(f_card)
            print("Informações da Conta:")
            print("Nome do Cliente:", card_data.get('account'))
            print("Número do Cartão:", card_data.get('card_number'))
            print("Saldo:", card_data.get('balance'))
            print("PIN:", card_data.get('pin'))
            respsta = send("getinfo", args.nome , 1, card_data)


            valor = 0 ## DEFINIR
            #SEND( OPERATION, NOME_PESSOA, VALUE, CONTEUDO_CARTÃO_PESSOA )
            resposta = send("deposit", args.account ,valor, card_data)

            print(resposta['param1'])
            print(resposta['param2'])
            print(resposta['param3'])
    except FileNotFoundError:
        print("O arquivo do cartão não existe.")



def main():
    if args.getinfo:
        get_account_info( args)
    elif args.deposit is not None:
        deposit_to_card(args)
    elif args.withdraw is not None:
        withdraw_from_card(args)
    elif verificar_existencia_arquivo(args.cardfile):
        print("O arquivo do cartão já existe.")
        ler_cartao(args)
    elif args.balance is not None:
        print("O arquivo do cartão não existe. Criando...")
        criar_cartao(args)
    else:
        print("O arquivo do cartão não existe.")

if __name__ == "__main__":
    main()
