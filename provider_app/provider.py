import socket, ssl, _thread, os

CERT_PROVIDER = '../certificates/provider.pem'
CERT_BROKER = '../certificates/broker.pem'
CERT_ADMIN = '../certificates/admin.pem'
CERT_USER1 = '../certificates/user1.pem'
CERT_USER2 = '../certificates/user2.pem'
CERTS = '../certificates/'
KEY = '1234567890123456'
FILE_PATH = '../files/'
#CERT_BROKER = "d8d30cb266b0d14f25e83dad06846b12"
IP_PROVIDER = ''
PORT_BROKER = 9999 # conexão com o broker (porta de escuta) (provider é server)
PORT_CLIENT = 8888 # conexão com cliente (porta de escuta)

def conectado(connUser, cliente, soc_broker):
    print('Conectado por', cliente)
    # msg = connection.read()
    msg = connUser.recv(1024).decode()
    if msg == 'send':
        send_file(connUser, cliente, soc_broker)
    else:
        get_file(connUser, cliente, msg, soc_broker)
    _thread.exit()

def get_file(connUser, cliente, fileName, soc_broker):
    fileName = FILE_PATH + fileName
    fileSize = os.path.getsize(fileName)
    connUser.send(str(fileSize).encode())
    file = open(fileName,'rb') # b - binario
    while (fileSize > 0):
        print ('Sending...')
        content = file.read(1024)
        connUser.send(content)
        fileSize -= len(content)
    file.close()
    print('Finalizando conexao do cliente', cliente)
    connUser.close()

    # passo 3
    # passo 4
    new_socBroker, broker = soc_broker.accept()
    connBroker = ssl.wrap_socket(new_socBroker, server_side=True, ca_certs=CERT_BROKER, cert_reqs=ssl.CERT_REQUIRED, certfile=CERT_PROVIDER, keyfile=CERT_PROVIDER)
    end_transaction(connBroker, broker)
    print('Finalizando conexao', broker)
    connBroker.close()

def send_file(connUser, cliente, soc_broker):
    fileName = FILE_PATH + connUser.recv(1024).decode() # tenho que tirar o caminho
    fileSize = int(connUser.recv(1024).decode())
    file = open(fileName,'wb') # b - binario
    while (fileSize > 0):
        print ('Receiving...')
        content = connUser.recv(1024)
        file.write(content)
        fileSize -= len(content)
    file.close()
    print('Finalizando conexao do cliente', cliente)
    connUser.close()

    # passo 3
    # passo 4
    new_socBroker, broker = soc_broker.accept()
    connBroker = ssl.wrap_socket(new_socBroker, server_side=True, ca_certs=CERT_BROKER, cert_reqs=ssl.CERT_REQUIRED, certfile=CERT_PROVIDER, keyfile=CERT_PROVIDER)
    end_transaction(connBroker, broker)
    print('Finalizando conexao', broker)
    connBroker.close()

def end_transaction(connBroker, broker):
    print('Conectado por', broker)
    end = connBroker.recv(1024).decode()
    if end=='end':
        connBroker.send('end'.encode())
    print('Done')


soc_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
orig_client = (IP_PROVIDER, PORT_CLIENT)
soc_client.bind(orig_client)
soc_client.listen(5)
soc_broker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
orig_broker = (IP_PROVIDER, PORT_BROKER)
soc_broker.bind(orig_broker)
soc_broker.listen(5)

# sair do loop???
while True:

    # passo 1
    # passo 2
    new_socClient, cliente = soc_client.accept()
    connUser = ssl.wrap_socket(new_socClient, server_side=True, ca_certs=CERT_ADMIN, cert_reqs=ssl.CERT_REQUIRED, certfile=CERT_PROVIDER, keyfile=CERT_PROVIDER)
    _thread.start_new_thread(conectado, tuple([connUser, cliente, soc_broker]))
    # sem thread
    # conectado(connection,cliente)

soc_client.close()
soc_broker.close()
