import os
import socket
from datetime import datetime, timedelta
import hash
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import DES
import base64
import dotenv

dotenv.load_dotenv()

HOST = '127.0.0.1'
PORT = 8081

IOTKEY = base64.b64decode(os.getenv("IOTKEY"))

# DB Config for user
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("URI")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
i = 0

class User(db.Model):
    __tablename__ = 'users'

    username = db.Column(db.String, primary_key=True)
    server = db.Column(db.String, primary_key=True)
    password = db.Column(db.String)
    __table_args__ = {'schema': 'Users'}


def generate_session(username, password, servername, network_address):
    global i
    i+=1
    key = hash.generate_session()
    dateTimeObj = datetime.now()
    timestampStr = dateTimeObj.strftime("%Y-%m-%d %H:%M:%S.%f")
    life = str(dateTimeObj + timedelta(hours=1))

    print(i, timestampStr)

    ticket = '{{"username":"{}","server":"{}","network":"{}","sessionkey":"{}","timestamp":"{}","lifetime":"{}"}}'.format(
        username, servername, network_address, key, timestampStr, life)
    print(i,ticket)
    eTicket = DES.encrypt(IOTKEY[:8], ticket)
    eticket_str = base64.b64encode(eTicket).decode("utf-8")
    payload = '{{"sessionkey":"{}","timestamp":"{}","lifetime":"{}","ticket":"{}"}}'.format(key, timestampStr, life,
                                                                                            eticket_str)

    client_key = base64.b64decode(password)
    cipher = DES.encrypt(client_key[48:56], payload)

    salt = base64.b64encode(client_key[:32]).decode("utf-8")
    return_packet = '{{"salt":"{}","payload":"{}"}}'.format(salt, base64.b64encode(cipher).decode("utf-8"))
    return return_packet.encode()


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        while True:
            data = conn.recv(1024)
            parts = data.decode().split('|')
            user = User.query.filter_by(username=parts[0], server=parts[1]).first()
            if user:
                packet = generate_session(user.username, user.password, user.server, str(addr))
                conn.sendall(packet)
            else:
                conn.sendall("Nice try buddie ;-)".encode())
