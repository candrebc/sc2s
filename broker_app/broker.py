import socket, ssl

import os, pickle
import sys
import _thread

CERT_BROKER = '../certificates/broker.pem'
CERT_ADMIN = '../certificates/admin.pem'
CERT_USER1 = '../certificates/user1.pem'
CERT_USER2 = '../certificates/user2.pem'
CERTS = '../certificates/'
FILE_PATH = '../files/'
IP_BROKER = ''
PORT_BROKER = 8080

def files():
    list = []
    for _, _, file in os.walk(FILE_PATH):
        list.append(file)
    return list

def list_files(connection):
    list = files()
    print(list)
    connection.send(pickle.dumps(list))

def send_file(connection):
    fileName = FILE_PATH + connection.recv(1024).decode() # tenho que tirar o caminho
    fileSize = int(connection.recv(1024).decode())
    file = open(fileName,'wb') # b - binario
    while (fileSize > 0):
        print ('Receiving...')
        content = connection.recv(1024)
        file.write(content)
        fileSize -= len(content)
    file.close()
    print('Done')

def get_file(connection):
    fileName = FILE_PATH + connection.recv(1024).decode()
    fileSize = os.path.getsize(fileName)
    connection.send(str(fileSize).encode())
    # list = files()
    # i = list.index(fileName)
    file = open(fileName,'rb') # b - binario
    while (fileSize > 0):
        print ('Sending...')
        content = file.read(1024)
        connection.send(content)
        fileSize -= len(content)
    file.close()
    print('Done')

def conectado(connection, cliente):
    print('Conectado por', cliente)
    while True:
        #msg = connection.read()
        msg = connection.recv(1024).decode()
        print(cliente, msg)
        if msg == 'list': list_files(connection)
        elif msg == 'send': send_file(connection)
        elif msg == 'get':
            get_file(connection)
            print('teste')
        elif msg == 'exit': break
        else: continue
    print('Finalizando conexao do cliente', cliente)
    connection.close()
    _thread.exit()


# context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH,capath=CERTS)
# context = ssl.SSLContext(ssl.PROTOCOL_TLS)
# context.verify_mode = ssl.CERT_REQUIRED
# context.check_hostname = False #True
# context.load_verify_locations(capath=CERTS)
# context.load_default_certs(capath=CERTS)
# context.load_cert_chain(certfile=CERT_ADMIN, keyfile=CERT_ADMIN)

sslsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
orig = (IP_BROKER, PORT_BROKER)
sslsocket.bind(orig)
sslsocket.listen(5)

while True:

    newsocket, cliente = sslsocket.accept()
    connection = ssl.wrap_socket(newsocket, server_side=True, ca_certs=CERT_ADMIN, cert_reqs=ssl.CERT_REQUIRED, certfile=CERT_BROKER, keyfile=CERT_BROKER)
    # connection = context.wrap_socket(newsocket, server_side=True)
    _thread.start_new_thread(conectado, tuple([connection, cliente]))
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

sslsocket.close()

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
