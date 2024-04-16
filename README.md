Projeto de SA

1. Fazer download do código.
   
2. Instalar as dependências necessárias
   - pip install cryptography
   - pip install pycryptodome
     
   (*)Em caso de no passo 3.3 ou 3.4 dar erro, executar os seguintes comandos por ordem:
   - pip3 uninstall crypto
   - pip3 uninstall pycrypto
   - pip3 install pycryptodome

3. Após a instalação das dependências, para correr o projeto:
   
   3.1. Abra o terminal do editor de código ou o powershell
     
   3.2. Vá até à pasta Projeto

   3.3. Crie as pastas bank e atm

   3.4. Coloque o ficheiro bank.py dentro da pasta bank
   
      3.4.1. Inicie primeiro o banco com o comando " python bank.py ", este
             irá iniciar o banco e criar um novo ficheiro bank.auth
   
   3.5 Copie o ficheiro bank.auth dentro da pasta bank e coloque na pasta atm,
       coloque o ficheiro atm.py dentro da pasta atm

      3.5.1. Em seguida noutro terminal corra o ATM com o comando
             " python atm.py -s bank.auth -c bob.card -a bob -n 1000.00 ",
             com este comando, irá ser criado um ficheiro <username>.card
       
5. A partir deste passo já está tudo operacional para começarem a
   atacar a nossa aplicação.
   Boa sorte e um resto de um bom trabalho!
   

Alguma dúvida não exitem em contactar via mail: pedrolage1702@gmail.com ou via discord .hewkii


     
     

