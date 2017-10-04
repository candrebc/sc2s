import socket, ssl, os, hashlib, time

import pickle

CERT_BROKER = '../certificates/broker.pem'
CERT_ADMIN = '../certificates/admin.pem'
CERT_USER1 = '../certificates/user1.pem'
CERT_USER2 = '../certificates/user2.pem'
CERTS = '../certificates/'
#CERT_BROKER = "d8d30cb266b0d14f25e83dad06846b12"
IP_BROKER = '200.19.179.201'
PORT_BROKER = 8080


def list_files(connection):
    connection.send('list'.encode())
    files = connection.recv(1024)
    print(pickle.loads(files))

def send_file(connection):
    connection.send('send'.encode())
    fileName = input("Digite o nome do arquivo: ")
    connection.send(fileName.encode())
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

def get_file(connection):
    connection.send('get'.encode())
    msg = input("Digite o nome do arquivo: ")
    connection.send(msg.encode())
    file = open(msg,'wb') # b - binario
    fileSize = int(connection.recv(1024).decode())
    while (fileSize > 0):
        print ('Receiving...')
        content = connection.recv(1024)
        file.write(content)
        fileSize -= len(content)
    file.close()
    print('Done')

def conectado(connection):
    msg = input('Comando (exit, list, send or get):')
    while msg != 'exit':
        if msg == 'list': list_files(connection)
        elif msg == 'send': send_file(connection)
        elif msg == 'get': get_file(connection)
        else: print('comando inválido')
        msg = input('Comando (exit, list, send or get):')
    connection.send(msg.encode())


# context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH,capath=CERTS)
# context = ssl.SSLContext(ssl.PROTOCOL_TLS)
# context.verify_mode = ssl.CERT_REQUIRED
# context.check_hostname = False #True
# context.load_verify_locations(capath=CERTS)
# context.load_cert_chain(certfile=CERT_ADMIN, keyfile=CERT_ADMIN)

sslsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#sslsocket = socket.socket(socket.AF_INET)
#context = ssl.create_default_context()

connection = ssl.wrap_socket(sslsocket, server_side=False, ca_certs=CERT_BROKER, cert_reqs=ssl.CERT_REQUIRED, certfile=CERT_ADMIN, keyfile=CERT_ADMIN)
#connection = context.wrap_socket(sslsocket, server_side=False)
try:
    connection.connect((IP_BROKER,PORT_BROKER))
    # if hashlib.md5(connection.getpeercert(True)).hexdigest() != CERT_BROKER:
    #     connection.close()
    #     print('CERT diferente do esperado, tentando me hackearrrrrrr')
    # else:
    #     print('200 OK')
    conectado(connection)
finally:
    connection.close()


# sock = socket.socket()
# sock.settimeout(2)
# sock.connect((IP_BROKER, PORT_BROKER))
#
# conn = ssl.wrap_socket(sock)
# print(conn.cipher())
#
# if hashlib.md5(conn.getpeercert(True)).hexdigest() != CERT_BROKER:
#     conn.close()
#     print('CERT diferente do esperado, tentando me hackearrrrrrr')
# else:
#     print('200 OK')
#     time.sleep(2)
#     conn.write('CHUPA ESSA MANGA, WIRESHARK!1!!')
#     print('enviado')
#     conn.close()
