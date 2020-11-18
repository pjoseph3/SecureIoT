import os
import socket
import json
import DES
import base64
import hash
from datetime import datetime
import rsa
import getpass
import dotenv

dotenv.load_dotenv()
HOST = '127.0.0.1'  # The server's hostname or IP address
AS = 8081  # The port used by the server
IOT = 8080
authenticated = False
hashsalt = base64.b64decode(os.getenv("HASH_SALT"))
pub = rsa.PublicKey(13,7)
pub = pub.load_pkcs1(base64.b64decode(os.getenv("PUBLIC_KEY")))
i=0


def decrypt_message(data, pw):
    if data == "Nice try buddie ;-)":
        return None

    data_dict = json.loads(data)
    salt = base64.b64decode(data_dict["salt"])
    key = hash.hashed_pw(pw, salt)
    packet = DES.decrypt(key[48:56], base64.b64decode(data_dict["payload"]))
    try:
        ticket = json.loads(packet.decode())
    except:
        ticket = None

    if not ticket:
        return None
    return ticket


def sign(message):
    digest = hash.hashed_pw(message, hashsalt)
    halfsig = rsa.encrypt(digest[33:54], pub)
    halfsig2 = rsa.encrypt(digest[54:64], pub)

    return "{}|{}|{}".format(message, base64.b64encode(halfsig).decode("utf-8"),
                             base64.b64encode(halfsig2).decode("utf-8"))


def generate_authenticator(ticket, username, servername, command, logout):
    global i
    dateTimeObj = datetime.now()
    timestampStr = dateTimeObj.strftime("%Y-%m-%d %H:%M:%S.%f")
    authenticator = '{{"username":"{}","timestamp":"{}","logout":"{}"}}'.format(
        username,
        timestampStr,
        str(logout)
    )
    sessionkey = base64.b64decode(ticket["sessionkey"])
    e_authenticator = DES.encrypt(sessionkey[16:24], authenticator)

    e_authenticator_str = base64.b64encode(e_authenticator).decode("utf-8")
    message = sign(command)
    i+=1
    print(i,message)
    payload = '{{"command":"{}","server":"{}","ticket":"{}","authenticator":"{}"}}'.format(message, servername,
                                                                                           ticket["ticket"],
                                                                                           e_authenticator_str)
    return payload.encode()


def iot_connect(auth, user, server):
    global authenticated
    serverAddressPort = ("127.0.0.1", IOT)
    commands = {1: "CHANNEL UP", 2: "CHANNEL DOWN", 3: "VOLUME UP", 4: "VOLUME DOWN"}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:

        print("\nYou can now talk to IoT\n")
        while True:
            print("Commands\n1: CHANNEL UP\n2: CHANNEL DOWN\n3: VOLUME UP\n4: VOLUME DOWN\n5: LOGOUT\n")
            command = input("Enter Command Number: ")
            if int(command) == 5:
                logout = generate_authenticator(auth, user, server, "logout",True)
                s.sendto(logout, serverAddressPort)
                server_logout = s.recvfrom(1024)
                print("\n{}\n".format(server_logout[0].decode()))
                authenticated = False
                return
            payload = generate_authenticator(auth, user, server, commands[int(command)], False)
            s.sendto(payload, serverAddressPort)
            msgFromServer = s.recvfrom(1024)
            if msgFromServer[0].decode() == "expired":
                print("\nYour session has expired.\n")
                authenticated = False
                return

            response = msgFromServer[0].decode().split('|')
            print(f'\n{response[0]}\n {response[1]}\n')


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, AS))
    server = "IoTServer"
    while True:
        if not authenticated:
            print("\nPlease login to IoT\n")
            us = input("Enter your username: ")
            pw = getpass.getpass()

        if us == 'q':
            break
        val = us + '|' + server
        s.sendall(val.encode())

        data = s.recv(1024).decode()

        auth = decrypt_message(data, pw)
        if auth:
            authenticated = True
            iot_connect(auth, us, server)
        else:
            authenticated = False
            print("Wrong Password/Username")
