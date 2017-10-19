import socket, ssl, os, hashlib, time


import pickle

from attestation import Attestation

from Crypto.Util.asn1 import DerSequence
from Crypto.Cipher import AES
from Crypto import Random
from hashlib import md5
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

CERT_PROVIDER = '../certificates/provider.pem'
CERT_BROKER = '../certificates/broker.pem'
CERT_ADMIN = '../certificates/admin.pem'
CERT_USER1 = '../certificates/user1.pem'
CERT_USER2 = '../certificates/user2.pem'
CERTS = '../certificates/'
KEY = '1234567890123456'
#CERT_BROKER = "d8d30cb266b0d14f25e83dad06846b12"
IP_BROKER = '200.19.179.201'
PORT_BROKER = 8080
IP_PROVIDER = '200.19.179.201'
PORT_PROVIDER = 8888


def derive_key_and_iv(password, salt, key_length, iv_length):
    d = d_i = b''  # changed '' to b''
    while len(d) < key_length + iv_length:
        # changed password to str.encode(password)
        d_i = md5(d_i + str.encode(password) + salt).digest()
        d += d_i
    return d[:key_length], d[key_length:key_length+iv_length]

def encrypt(in_file, out_file, password, salt_header='', key_length=32):
    # added salt_header=''
    bs = AES.block_size
    # replaced Crypt.Random with os.urandom
    salt = Random.new().read(bs - len(salt_header))
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # changed 'Salted__' to str.encode(salt_header)
    out_file.write(str.encode(salt_header) + salt)
    finished = False
    while not finished:
        chunk = in_file.read(1024 * bs)
        if len(chunk) == 0 or len(chunk) % bs != 0:
            padding_length = (bs - len(chunk) % bs) or bs
            # changed right side to str.encode(...)
            chunk += str.encode(
                padding_length * chr(padding_length)) ## chr_padding??
            finished = True
        out_file.write(cipher.encrypt(chunk))

def decrypt(in_file, out_file, password, salt_header='', key_length=32):
    # added salt_header=''
    bs = AES.block_size
    # changed 'Salted__' to salt_header
    salt = in_file.read(bs)[len(salt_header):]
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    next_chunk = ''
    finished = False
    while not finished:
        chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
        if len(next_chunk) == 0:
            padding_length = chunk[-1]  # removed ord(...) as unnecessary
            chunk = chunk[:-padding_length]
            finished = True
        out_file.write(bytes(x for x in chunk))  ## changed chunk to bytes(...)??

def signature(fileName,privKey):
    file = open(fileName, 'rb')
    data = file.read()
    keyFile = open(privKey, 'r')
    key = keyFile.read()
    rsakey = RSA.importKey(key)
    signer = PKCS1_v1_5.new(rsakey)
    digest = SHA256.new()
    digest.update(data)
    signFile = open(fileName+'.sha256', 'wb')
    signFile.write(signer.sign(digest))
    file.close()
    keyFile.close()
    signFile.close()

def verifier(fileName,pubKey):
    file = open(fileName, 'rb')
    data = file.read()
    keyFile = open(pubKey, 'r')
    key = keyFile.read()
    signFile = open(fileName+'.sha256', 'rb')
    sign = signFile.read()
    rsakey = RSA.importKey(key)
    signer = PKCS1_v1_5.new(rsakey)
    digest = SHA256.new()
    digest.update(data)
    file.close()
    keyFile.close()
    signFile.close()
    return signer.verify(digest, sign)


def list_files(connection):
    connection.send('list'.encode())
    files = connection.recv(1024)
    print(pickle.loads(files))

def send_file(connBroker):
    fileName = input("Digite o nome do arquivo: ")
    ciphered_fileName = fileName+'.enc'
    # teste: arquivo não existe???
    # list = files()
    # i = list.index(fileName)

    # cifragem
    file = open(fileName,'rb') # b - binario
    ciphered_file = open(ciphered_fileName,'wb')
    encrypt(file,ciphered_file,KEY)
    file.close()
    ciphered_file.close()
    signature(ciphered_fileName,'admin_key.pem')

    # passo 1 - getAtt_Metadata
    # passo 2 - PoR / ler arquivo

    # passo 3 - upload
    connProvider = connectProvider()
    connProvider.send('send'.encode())
    connProvider.send((ciphered_fileName).encode())
    fileSize = os.path.getsize(ciphered_fileName)
    connProvider.send(str(fileSize).encode())
    ciphered_file = open(ciphered_fileName,'rb')
    while (fileSize > 0):
        print ('Sending...')
        content = ciphered_file.read(1024)
        connProvider.send(content)
        fileSize -= len(content)
    ciphered_file.close()
    connProvider.close()

    # passo 4 - hash (att_metadata) e fim da transacao
    connBroker.send('send'.encode())
    connBroker.send((ciphered_fileName).encode())
    sign_file = open(ciphered_fileName+'.sha256','rb')
    connBroker.send(sign_file.read(1024))
    sign_file.close()
    end = connBroker.recv(1024).decode()
    if end == 'end':
        print('Done')

    os.remove(ciphered_fileName)
    os.remove(ciphered_fileName+'.sha256')


def connectProvider():
    soc_provider = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connProvider = ssl.wrap_socket(soc_provider, server_side=False, ca_certs=CERT_PROVIDER, cert_reqs=ssl.CERT_REQUIRED,
                                 certfile=CERT_ADMIN, keyfile=CERT_ADMIN)
    connProvider.connect((IP_PROVIDER, PORT_PROVIDER))
    return connProvider


def get_file(connBroker):
    fileName = input("Digite o nome do arquivo: ")
    deciphered_fileName = fileName.strip('.enc')
    # teste: arquivo não existe??? - no broker??

    # passo 1 alterar depois 1 send para cada msg (get,id) - user/lsn
    connBroker.send('get'.encode())
    connBroker.send(fileName.encode())
    sign_file = open(fileName+'.sha256','wb')
    sign_file.write(connBroker.recv(1024)) # resposta - attestation (hash)

    # passo 2 - download
    connProvider = connectProvider()
    connProvider.send(fileName.encode())
    file = open(fileName,'wb') # b - binario
    fileSize = int(connProvider.recv(1024).decode())
    while (fileSize > 0):
        print ('Receiving...')
        content = connProvider.recv(1024)
        file.write(content)
        fileSize -= len(content)
    file.close()
    sign_file.close()
    connProvider.close()

    # passo 3 - decifragem
    print(verifier(fileName,'admin_pubkey.pem'))
    file = open(fileName,'rb') # b - binario
    deciphered_file = open(deciphered_fileName,'wb')
    decrypt(file,deciphered_file,KEY)
    file.close()
    deciphered_file.close()

    # passo 4 - fim (devolver att)
    connBroker.send('end'.encode())
    end = connBroker.recv(1024).decode()
    if end == 'end':
        print('Done')

    os.remove(fileName)
    os.remove(fileName+'.sha256')

def conectado(connection):
    msg = input('Comando (exit, list, send or get):')
    while msg != 'exit':
        if msg == 'list': list_files(connection)
        elif msg == 'send': send_file(connection)
        elif msg == 'get': get_file(connection)
        else: print('comando inválido')
        msg = input('Comando (exit, list, send or get):')
    connection.send(msg.encode())


# teste attestation


att = Attestation(1,1,'admin_key.pem')
att.setSignature(2, CERTS+'provider_key.pem')
att.setSignature(1, CERTS+'broker_key.pem')
pubKeys = ['admin_pubkey.pem', CERTS+'broker_pubkey.pem', CERTS+'provider_pubkey.pem']
print(att.verifySignatures(pubKeys))
exit()





# context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH,capath=CERTS)
# context = ssl.SSLContext(ssl.PROTOCOL_TLS)
# context.verify_mode = ssl.CERT_REQUIRED
# context.check_hostname = False #True
# context.load_verify_locations(capath=CERTS)
# context.load_cert_chain(certfile=CERT_ADMIN, keyfile=CERT_ADMIN)

soc_broker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#sslsocket = socket.socket(socket.AF_INET)
#context = ssl.create_default_context()

connection = ssl.wrap_socket(soc_broker, server_side=False, ca_certs=CERT_BROKER, cert_reqs=ssl.CERT_REQUIRED, certfile=CERT_ADMIN, keyfile=CERT_ADMIN)
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
