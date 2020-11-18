import os
import socket
import json
import DES
import base64
from datetime import datetime
import dotenv

dotenv.load_dotenv()
HOST = '0.0.0.0'
PORT = 8080
IOT = 8082


IOTKEY = base64.b64decode(os.getenv("IOTKEY"))
authenticator_set = set()


def validate_ticket(data):
    data_dict = json.loads(data)
    ticket = DES.decrypt(IOTKEY[:8], base64.b64decode(data_dict["ticket"]))
    ticket_dict = json.loads(ticket)
    try:
        sessionkey = base64.b64decode(ticket_dict["sessionkey"])
        authenticator = json.loads(
            DES.decrypt(sessionkey[16:24], base64.b64decode(data_dict["authenticator"])).decode())
    except:
        return None
    timestamp = datetime.strptime(authenticator["timestamp"], '%Y-%m-%d %H:%M:%S.%f')
    lifetime = datetime.strptime(ticket_dict["lifetime"], '%Y-%m-%d %H:%M:%S.%f')
    if authenticator["logout"] == "True":
        authenticator_set.clear()
        print("authenticator_list:\n",authenticator_set)
        return "Successfully logged out from IoT.","logout"
    if datetime.now() > lifetime:
        authenticator_set.clear()
        return "expired"
    if authenticator["username"] != ticket_dict["username"]:
        return None
    if data_dict["server"] != ticket_dict["server"]:
        return None
    if (authenticator["username"], timestamp) in authenticator_set:
        return None
    authenticator_set.add((authenticator["username"], timestamp))
    print("authenticator_list:\n",authenticator_set)
    return data_dict["command"]


def iot_device_connect(response):
    serverAddressPort = ("127.0.0.1", IOT)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(response.encode(), serverAddressPort)
        msgFromServer = s.recvfrom(1024)

    return msgFromServer[0]


with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.bind((HOST, PORT))

    while True:
        bytesAddressPair = s.recvfrom(1024)
        data = bytesAddressPair[0]

        address = bytesAddressPair[1]

        response = validate_ticket(data.decode())
        if not data:
            break

        if response is None:
            s.sendto(b'invalid session!', address)
        elif response == "expired":
            s.sendto(b'expired', address)
        elif response[1] == "logout":
            s.sendto(response[0].encode(), address)
        else:
            s.sendto(iot_device_connect(response), address)
