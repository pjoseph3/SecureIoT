import os
import socket
import rsa
import hash
import base64
import dotenv

dotenv.load_dotenv()

HOST = 'localhost'
PORT = 8082
DEVICE = "Roku Smart TV"

priv=rsa.PrivateKey(3247, 65537, 833, 191, 17)
priv = priv.load_pkcs1(base64.b64decode(os.getenv("PRIVATE_KEY")))
hashsalt = base64.b64decode(os.getenv("HASH_SALT"))


def sign(message):
    digest = hash.hashed_pw(message, hashsalt)

    return digest


def validate_digitalsignature(digest):
    command_digest = sign(digest[0])
    halfsig = rsa.decrypt(base64.b64decode(digest[1]), priv)
    halfsig2 = rsa.decrypt(base64.b64decode(digest[2]), priv)
    print('command digest:',command_digest[33:54],command_digest[54:64])
    print('Decrypted signature:', halfsig, halfsig2)
    if command_digest[33:54] == halfsig and command_digest[54:64] == halfsig2:
        return True

    return False


def execute_command(response):
    digest = response.decode().split('|')

    if validate_digitalsignature(digest) == True:
        execution = digest[0] + " EXECUTED!|-{}".format(DEVICE)
        return execution.encode()
    else:
        return b"Invalid signature!"


with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.bind((HOST, PORT))

    while True:
        bytesAddressPair = s.recvfrom(1024)
        data = bytesAddressPair[0]

        address = bytesAddressPair[1]

        response = execute_command(data)
        print("Response sent")
        s.sendto(response, address)
