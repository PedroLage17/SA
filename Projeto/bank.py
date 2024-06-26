import argparse
import json
import random
import re
import sys
import socket
import os
import signal
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
import hmac
import hashlib
import base64


from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256





debug = False

BUFFER_SIZE = 8192

accounts = {}
auth_file_name = "bank.auth"
hmac_challange_server = None
travao = False
chave_RSA_privada= None
chave_secreta = "abak123123sjdnf.kjasd123123nf.kja123123sdfn"  ## validar HMAC Challange


def handler(signum, frame):
    print("Desligando")
    raise KeyboardInterrupt()


def handler_int(signum, frame):
    print("Desligando")
    sys.exit(0)


## BEGIN RSA
def gerar_chaves_rsa():
    global chave_RSA_privada
    chave = RSA.generate(2048)
    chave_privada = chave.export_key()
    chave_publica = chave.publickey().export_key()
    chave_RSA_privada=chave_privada
    return chave_publica

def decifrar_com_privada(mensagem_cifrada):
    global chave_RSA_privada
    chave = RSA.import_key(chave_RSA_privada)
    cifrador = PKCS1_OAEP.new(chave)
    mensagem_decifrada = cifrador.decrypt(mensagem_cifrada)
    return mensagem_decifrada


def assinar_com_privada(mensagem):
    global chave_RSA_privada
    chave = RSA.import_key(chave_RSA_privada)
    h = SHA256.new(mensagem.encode())
    assinatura = pkcs1_15.new(chave).sign(h)
    # Converte a assinatura para base64 para serialização JSON
    assinatura_base64 = base64.b64encode(assinatura).decode('utf-8')
    return assinatura_base64


## END RSA


def parse_money(money_string):
    parts = str(money_string).strip().split('.')
    amount = [0, 0]  # Inicializa a parte inteira e decimal como zero

    # Verifica e trata a parte inteira
    if len(parts) > 0 and parts[0]:
        amount[0] = int(parts[0])
    
    # Verifica e trata a parte decimal
    if len(parts) == 2 and parts[1]:
        amount[1] = int(parts[1])

    return amount


def lerChave():
    global auth_file_name
    try:
        with open(auth_file_name, 'r') as file:
            linhas = [linha.strip() for linha in file.readlines()]
            chave_aes = linhas[0]  # A chave AES é a primeira linha
            chave_publica = "\n".join(linhas[1:])
        return chave_aes, chave_publica
    except IOError as e:

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

    ######################################################################################################## MEXER BEGIN

    def withdraw(self, amount_string):
        amount = parse_money(amount_string)
        
        if amount[0] < self.dollars or (amount[0] == self.dollars and amount[1] <= self.cents):
            
            self.dollars -= amount[0]
            self.cents -= amount[1]
            if self.cents < 0:
                self.dollars -= 1
                self.cents += 100
            return True
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

    ######################################################################################################## MEXER END

    def validadeCard(self, resume):
        resumo_gen = self.calculateResume()
        return hmac.compare_digest(resumo_gen, resume)

    def calculateResume(self):
        return gerar_hmac("asdfadsfadsf" + str(self.pin) + self.name + str(self.card_number) + str(self.salt))


def tirarDaCripta(ciphertext):
    chaveAES, chaveRSA_Pub = lerChave()
    fernet_obj = Fernet(chaveAES)
    return fernet_obj.decrypt(ciphertext)


def colocarNaCripta(plainText):
    chaveAES, chaveRSA_Pub = lerChave()
    fernet_obj = Fernet(chaveAES)
    return fernet_obj.encrypt(plainText)

## não mexer
def gerar_hmac(mensagem):
    global chave_secreta
    chave_secreta_bytes = bytes(chave_secreta, 'utf-8')
    mensagem_bytes = bytes(mensagem, 'utf-8')
    hmac_objeto = hmac.new(chave_secreta_bytes, mensagem_bytes, hashlib.sha256)
    hmac_gerado = hmac_objeto.hexdigest()
    return hmac_gerado

## nao mexer
def genNewChallange(conn):
    global chave_secreta

    desafio = random.randint(100000000, 999999999)
    json_ = json.dumps({'MatrixChallange': desafio, 'MaChSigned': assinar_com_privada(str(desafio))})
    cypherText = colocarNaCripta(json_.encode("utf-8"))
    conn.send(cypherText)

    desafio = "Cifrar" + str(desafio + 23634562) + "Criptar"
    hmac_Server = gerar_hmac(desafio)

    return hmac_Server

def sendProtocolError(conn):
    global chave_secreta

    json_ = json.dumps({'protocolError': 63, 'protocolErrorSigned': assinar_com_privada( str(63) +"aaa" )})
    cypherText = colocarNaCripta(json_.encode("utf-8"))
    conn.send(cypherText)


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

    for card_number, conta in accounts.items():
        if conta.name == name:
            return {'success': False, 'message': 'User already exists'}

    conta = Account(name, amount)
    accounts[conta.card_number] = conta

    response['summary'] = "{\"account\": \""+ conta.name+ "\", \"initial_balance\": "+ str(conta.get_balance())+ "}"
    response['cardResume'] = conta.calculateResume()

    return response

##não mexer
def solveChallange(puzzle):
    global chave_secreta
    try:
        desafio = "Cifrar"+str(int(puzzle)+23634562)+"Criptar"
        hmac_Client = gerar_hmac(desafio)
        return hmac_Client
    except Exception as e:
        print("Authentication failed:", e)
        return 0
    
def deposit_to_card(nome, resumoCartao, valor):
    global accounts; 
    response = {'success': False}
    if float(valor)<=0.0:
        return response

    for a, conta in accounts.items():

        if conta.name == nome:
            
            if conta.calculateResume() == resumoCartao: ## epá se os 2 são iguais, 
                response = {'success': True}                                      ##então yá o nome da pessoa foi validado e o cartão tambem
                conta.deposit(str(valor))                                       
                response['summary'] = "{\"account\": \""+ conta.name+ "\", \"deposit\": "+ str(valor)+"}"
                break

    return response
def withdraw_from_card(nome, resumoCartao, valor):
    global accounts; 
    response = {'success': False}
    
    if float(valor)<=0.0:
        return response

    for a, conta in accounts.items():

        if conta.name == nome:
            if conta.calculateResume() == resumoCartao: ## epá se os 2 são iguais, 
                                                        ##então yá o nome da pessoa foi validado e o cartão tambem
                if conta.withdraw(str(valor)):
                    response = {'success': True}                                  
                    response['summary'] = "{\"account\": \""+ conta.name+ "\", \"withdraw\": "+ str(valor)+"}"
                    break
    
    return response





def get_account_balance(nome, resumoCartao):
    global accounts
    response = {'success': False}
    for a, conta in accounts.items():

        if conta.name == nome:
            
            if conta.calculateResume() == resumoCartao: ## epá se os 2 são iguais, 
                response = {'success': True} ##então yá o nome da pessoa foi validado e o cartão tambem
                balance = conta.get_balance()
                response['summary'] = "{\"account\": \""+ conta.name+ "\", \"balance\": "+ str(balance)+"}"
                break
    return response

    
       

###################################################################################################################################################################

## não precisa mudar
def respostaParaATM(f , nouncePorResolver, param1 = None, param2 = None, param3= None):
    nounceResolvido =  solveChallange(nouncePorResolver)

    resposta = {
        'param1': param1,
        'param2': param2,
        'param3': param3,
        'nounce': nounceResolvido,
    }

    resposta['resumo'] = gerar_hmac("nadaFoiAlterado" + json.dumps(resposta, sort_keys=True) + "nadaFoiAlterado")
    R = json.dumps(resposta)
    msg = f.encrypt(R.encode()) ## fernet encript já com a chave ANTI MIM
    conn.send(msg) ## envio da Resposta
    return 0

###################################################################################################################################################################

def check_path_traversal(user_input):
    # Regex para detectar padrões comuns de path traversal
    patterns = [
        r'\.\./',  # Unix-like path traversal
        r'\.\.\\',  # Windows path traversal
        r'/\.\./',  # Encoded Unix-like path traversal
        r'\\\.\.\\'  # Encoded Windows path traversal
    ]
    
    # Verifica cada padrão usando expressões regulares
    for pattern in patterns:
        if re.search(pattern, user_input):
            sys.exit(255)







if __name__ == '__main__':
    ## LOADUP START BANK


    # if debug:
    #     nome_arquivo = "bank.auth"

    #     try:
    #         # Remove o arquivo
    #         os.remove(nome_arquivo)
    #         print(f"O arquivo {nome_arquivo} foi removido com sucesso.")
    #     except FileNotFoundError:
    #         print(f"O arquivo {nome_arquivo} não foi encontrado.")
    #     except PermissionError:
    #         print(f"Permissão negada para remover o arquivo {nome_arquivo}.")
    #     except Exception as e:
    #         print(f"Erro ao remover o arquivo {nome_arquivo}: {e}")




    signal.signal(signal.SIGINT, handler_int)
    signal.signal(signal.SIGTERM, handler)

    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", help="port number", dest = "port", default=3000, type=int)
    parser.add_argument("-s", "--auth_file", help="auth file", dest = "auth_file", default="bank.auth", nargs='?')
    parser.add_argument("-i", "--ip_address", help="ip address", default="127.0.0.1", dest = "ip", nargs='?')

    args = parser.parse_args()

    if args.port < 1024 or args.port > 65535:
        parser.print_help()
        print("port must be between 1024 and 65535")

        sys.exit(255)

    pattern = re.compile(r'[_\-\.0-9a-z]{1,255}')

    check_path_traversal(args.auth_file)

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
        chave_RSA_publica = gerar_chaves_rsa()
        auth_file = open(auth_file_name, 'wb')
        auth_file.write(key)
        auth_file.write(b'\n')
        auth_file.write(chave_RSA_publica)
        auth_file.close()
    ## FIM LOADUP

    ## cria connection
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((args.ip, args.port))
    s.listen(1)
    s.settimeout(1)
    print("Ready for connection")
    try:
        while True:
            
            do = False
            try:
                conn, addr = s.accept()
                do = True
            except socket.timeout:
                do = False
                continue

            try:
                if do:
                    conn.settimeout(10)
                    ##print("Connection established with:", addr)

                    ciphertext = conn.recv(BUFFER_SIZE)
                    ciphertext = decifrar_com_privada(ciphertext)
                    
                    if not ciphertext:
                        print("protocol_error") 
                        sendProtocolError(conn)
                        continue
                    
                    

                    data = tirarDaCripta(ciphertext)
                    

                    request = json.loads(data)
                    type = request['type']
                    if type == "genChallange":
                        hmac_challange_server = genNewChallange(conn) ## gera e Envia

                    ciphertext = conn.recv(BUFFER_SIZE) ## aqui recebemos a capsula / envelope seguro,
                    if not ciphertext:
                        print("protocol_error") 
                        sendProtocolError(conn)
                        continue

                    ## ABrir a ENVELOPE SEGURO que veio do ATM
                    data = tirarDaCripta(ciphertext)  
                    capsula = json.loads(data)
                    pedido_encapsulado_base64 = capsula['pedidoEncapsulado']
                    chave_cifrada_anti_mim_base64 = capsula['chaveCifradaAntiMiM']
                    key_AntiMiM = decifrar_com_privada(base64.b64decode(chave_cifrada_anti_mim_base64))
                    ferAnti_MiM = Fernet(key_AntiMiM)
                    request_str = ferAnti_MiM.decrypt(base64.b64decode(pedido_encapsulado_base64))
                    ## ENVELOPE SEGURO ABERTO

                    if (not validadeResumeRequest(request_str)):
                        print("protocol_error") 
                        sendProtocolError(conn)       
                        
                    

                    dicionario  = json.loads(request_str)
                    if not(validateMatrixChallange(dicionario['nounce'], hmac_challange_server)):
                        print("protocol_error") 
                        sendProtocolError(conn)               
                

                    type = dicionario['type']




                    if type == "createAcc":
                        response = create(dicionario['nome'], dicionario['valor'])
                        if response['success']:
                            sumario = response['summary']
                            resumoCartAo = response['cardResume']
                            respostaParaATM(ferAnti_MiM ,dicionario['novoNounce'], resumoCartAo, sumario)
                            print(sumario)
                        else:
                     
                            respostaParaATM(ferAnti_MiM, dicionario['novoNounce'], "255")




                    elif type == "deposit":
                        response = deposit_to_card(dicionario['nome'], dicionario['cartao'],dicionario['valor'])
                        if response['success']:
                            sumario = response['summary']
                            respostaParaATM(ferAnti_MiM,dicionario['novoNounce'], sumario)
                            print(sumario)
                        else:
                           
                            respostaParaATM(ferAnti_MiM, dicionario['novoNounce'], "255")




                    elif type == "levantar":
                        response = withdraw_from_card(dicionario['nome'], dicionario['cartao'],dicionario['valor'])
                        if response['success']:
                            sumario = response['summary']
                            respostaParaATM(ferAnti_MiM,dicionario['novoNounce'], sumario)
                            print(sumario)
                        else:
                            respostaParaATM(ferAnti_MiM, dicionario['novoNounce'], "255")

                        respostaParaATM(ferAnti_MiM, dicionario['novoNounce'], "Levantou o que quis")




                    elif type == "consultar":

                        response = get_account_balance(dicionario['nome'], dicionario['cartao'])
                        if response['success']:
                            sumario = response['summary']
                            respostaParaATM(ferAnti_MiM ,dicionario['novoNounce'], sumario,)
                            print(sumario)
                        else:

                            respostaParaATM(ferAnti_MiM, dicionario['novoNounce'], "255")
                    else:

                        print("protocol_error")  
            except(InvalidToken):
                print("protocol_error")  
    
    except KeyboardInterrupt:
        
        s.close()
        sys.exit(0)  
    
            
         

