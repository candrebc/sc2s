import socket, ssl

import os
import sys
import _thread

CERT_BROKER = 'cert.pem'
IP_BROKER = ''
PORT_BROKER = 8080

def conectado(connection, cliente):
    print('Conectado por', cliente)
    while True:
        msg = connection.recv(1024)
        #msg = connection.read()
        if not msg: break
        print(cliente, msg.decode())

    print('Finalizando conexao do cliente', cliente)
    connection.close()
    _thread.exit()

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile=CERT_BROKER, keyfile=CERT_BROKER)

sslsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#sslsocket = socket.socket()
orig = (IP_BROKER, PORT_BROKER)
sslsocket.bind(orig)
sslsocket.listen(5)

while True:

    newsocket, cliente = sslsocket.accept()
    connection = context.wrap_socket(newsocket, server_side=True)
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
