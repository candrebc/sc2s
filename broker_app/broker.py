import socket, ssl

import os, pickle
import sys
import _thread

CERT_PROVIDER = '../certificates/provider.pem'
CERT_BROKER = '../certificates/broker.pem'
CERT_ADMIN = '../certificates/admin.pem'
CERT_USER1 = '../certificates/user1.pem'
CERT_USER2 = '../certificates/user2.pem'
CERTS = '../certificates/'
FILE_PATH = '../files/'
IP_BROKER = ''
PORT_BROKER = 8080
IP_PROVIDER = '172.16.7.16'
PORT_PROVIDER = 9999

def connectProvider():
    soc_provider = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connProvider = ssl.wrap_socket(soc_provider, server_side=False, ca_certs=CERT_PROVIDER, cert_reqs=ssl.CERT_REQUIRED,
                                 certfile=CERT_BROKER, keyfile=CERT_BROKER)
    connProvider.connect((IP_PROVIDER, PORT_PROVIDER))
    return connProvider

def files():
    list = []
    for _, _, file in os.walk(FILE_PATH):
        list.append(file)
    return list

def list_files(connection):
    list = files()
    print(list)
    connection.send(pickle.dumps(list))

def send_file(connUser):

    # passo 1
    # passo 2 - PoR (Provider)
    # passo 3 - upload (Provider)

    # passo 4 - hash (att_meta) e fim
    fileName = FILE_PATH + connUser.recv(1024).decode() # tenho que tirar o caminho
    signature = connUser.recv(1024)
    fileSign = open(fileName+'.sha256','wb')
    fileSign.write(signature)
    fileSign.close()
    connProvider = connectProvider()
    connProvider.send('end'.encode())
    endSend = connProvider.recv(1024).decode()
    if endSend == 'end':
        connUser.send('end'.encode())
    connProvider.close()
    print('Done')

def get_file(connUser):
    # passo 1
    fileName = FILE_PATH + connUser.recv(1024).decode()
    fileSign = open(fileName+'.sha256','rb')
    connUser.send(fileSign.read(1024))
    fileSign.close()

    # passo 2 - provider
    # passo 3

    # passo 4
    endGet = connUser.recv(1024).decode()
    if endGet=='end':
        connProvider = connectProvider()
        connProvider.send('end'.encode())
        endGet = connProvider.recv(1024).decode()
        if endGet=='end':
            connUser.send('end'.encode())
        connProvider.close()
    print('Done')

def conectado(connUser, cliente):
    print('Conectado por', cliente)
    while True:
        #msg = connection.read()
        msg = connUser.recv(1024).decode()
        print(cliente, msg)
        if msg == 'list': list_files(connUser)
        elif msg == 'send': send_file(connUser)
        elif msg == 'get': get_file(connUser)
        elif (msg == 'exit'): break
        else: continue
    print('Finalizando conexao do cliente', cliente)
    connUser.close()
    _thread.exit()


# context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH,capath=CERTS)
# context = ssl.SSLContext(ssl.PROTOCOL_TLS)
# context.verify_mode = ssl.CERT_REQUIRED
# context.check_hostname = False #True
# context.load_verify_locations(capath=CERTS)
# context.load_default_certs(capath=CERTS)
# context.load_cert_chain(certfile=CERT_ADMIN, keyfile=CERT_ADMIN)

soc_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
orig_client = (IP_BROKER, PORT_BROKER)
soc_client.bind(orig_client)
soc_client.listen(5)

while True:
    new_socClient, client = soc_client.accept()
    connUser = ssl.wrap_socket(new_socClient, server_side=True, ca_certs=CERT_ADMIN, cert_reqs=ssl.CERT_REQUIRED, certfile=CERT_BROKER, keyfile=CERT_BROKER)
    # connection = context.wrap_socket(newsocket, server_side=True)
    _thread.start_new_thread(conectado, tuple([connUser, client]))
    # try:
    #     _thread.start_new_thread(conectado, tuple([connection, cliente]))
    # finally:
    #     connection.shutdown(socket.SHUT_RDWR)
    #     connection.close()

    # pid = os.fork()
    # if pid == 0:
    #     tcp.close()
    #     print('Conectado por', cliente)
    #     while True:
    #         msg = connection.recv(1024)
    #         if not msg: break
    #         print(cliente, msg.decode())
    #     print('Finalizando conexao do cliente', cliente)
    #     connection.close()
    #     sys.exit(0)
    # else:
    #     connection.close()

soc_client.close()

# sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# sock.bind(('', PORT_BROKER))
# sock.listen(1)
#
# newsocket, fromaddr = sock.accept()
# conn = ssl.wrap_socket(newsocket, server_side=True, certfile=CERT_BROKER, keyfile=CERT_BROKER)
# print(conn.cipher())
# conn.setblocking(0)
#
# while True:
#     try:
#         buf = conn.read(512)
#         if buf == '':
#             break
#         else:
#             print(buf)
#     except:
#         pass
#
