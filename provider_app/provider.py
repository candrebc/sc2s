import socket, ssl, hashlib, time

CERT_BROKER = "d8d30cb266b0d14f25e83dad06846b12"
IP_BROKER = '200.19.179.201'
PORT_BROKER = 8080

def conectado(connection):
    print('Para sair use CTRL+X\n')
    msg = input()
    while msg != '\x18':
        connection.send(msg.encode())
        msg = input()


#sslsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sslsocket = socket.socket(socket.AF_INET)
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
connection = context.wrap_socket(sslsocket, server_hostname=IP_BROKER)
try:
    connection.connect((IP_BROKER,PORT_BROKER))
    print(connection.cipher())
    if hashlib.md5(connection.getpeercert(True)).hexdigest() != CERT_BROKER:
        connection.close()
        print('CERT diferente do esperado, tentando me hackearrrrrrr')
    else:
        print('200 OK')
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
