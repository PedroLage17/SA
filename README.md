Projeto de SA

1. Fazer dowload do codigo.
   
2. Instalar as dependências necessárias
   - pip install cryptography
   - pip install pycryptodome
     
  (*)Em caso de no passo 3.3 ou 3.4 dar erro, executar os seguintes comandos por ordem:
  - pip3 uninstall crypto
  - pip3 uninstall pycrypto
  - pip3 install pycryptodome

3. Após a instalação das dependências, para correr o projeto:
   
  3.1. Abra o terminal do editor de código ou o powershell
     
  3.2. Vá ate a pasta Projeto
     
  3.3. Inicie primeiro o banco com o comando " python bank.py ", este
       irá inicaiar o banco e criar um novo ficheiro bank.auth,
       que comtem a chave publica e a chave AES
  
  3.4. Em seguida noutro terminal corra o ATM com o comando
       " python atm.py -s bank.auth -c bob.card -a bob -n 1000.00 ",
       com este comando, irá ser criado um ficheiro <username>.card, 
       que contem, resumo da conta do user. O resumo é um HMAC 
       SHA-256 que tem o nome do user, o número do cartão, o pin e o 
       salt.
       
4. A partir deste passo já esta tudo operacional para começarem a
   atacar a nossa aplicação.
   Boa sorte e um resto de um bom trabalho!
   

Alguma dúvida não exitem em contactar via mail: pedrolage1702@gmail.com ou via discord .hewkii


     
     

