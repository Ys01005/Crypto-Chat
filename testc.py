import socket
import random
import time
import hashlib

G = 5
P = 23

class DHKE:
    def __init__(self, G, P):
        self.G_param = G
        self.P_param = P
        self.share_key = 0

    def generate_privatekey(self):
        self.pk = random.randrange(start=1, stop=10, step=1)

    def generate_publickey(self):
        self.pub_key = pow(self.G_param, self.pk) % self.P_param

    def exchange_key(self, other_public):
        self.share_key = pow(other_public, self.pk) % self.P_param

    def encrypt_string(self, message):
        hashed_message = hashlib.sha256(message.encode()).hexdigest()
        return ''.join(chr(ord(a) ^ self.share_key) for a in hashed_message)

    def decrypt_string(self, message):
        decrypted_message = ''.join(chr(ord(a) ^ self.share_key) for a in message)
        return decrypted_message

# Create a socket object
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Get local machine name
host = socket.gethostname()

port = random.randint(10000, 20000)

# Bind to the port
s.bind((host, port))

# get host:port from user
print('Enter host:port')
host_port = input()

# connect to server
s.connect((host_port.split(':')[0], int(host_port.split(':')[1])))

messages = []
exchange_key = 0

key = DHKE(G, P)
# send public key to server
key.generate_privatekey()
key.generate_publickey()
s.send(str(key.pub_key).encode("utf-8"))
print('Public key: ' + str(key.pub_key))

while len(messages) < 2:
    print('Waiting for key...')
    # get messages from server
    time.sleep(1)
    s.send(b'[$get]')
    data = s.recv(1024)

    # add messages to list
    messages = eval(data)

while True:
    # clear screen
    print('\n' * 100)

    # get key from server
    if len(messages) == 2:
        c2_key = messages[0].decode("utf-8")
        if int(c2_key) == key.pub_key:
            c2_key = messages[1].decode("utf-8")

        print('Received key: ' + c2_key)
        key.exchange_key(int(c2_key))
        print('Shared key: ' + str(key.share_key))

    # get messages from server
    s.send(b'[$get]')
    data = s.recv(1024)

    # add messages to list
    messages = eval(data)

    # print all messages
    for message in messages:
        decrypted_message = key.decrypt_string(message.decode("utf-8"))
        print(f"Decrypted Message: {decrypted_message}")
        # verify the integrity of the message using SHA-256 hash
        hashed_message = hashlib.sha256(decrypted_message.encode()).hexdigest()
        print(f"Hash of Decrypted Message: {hashed_message}")

    # get message from user
    message = input()

    if message != ".":
        # send hashed message to server
        hashed_message = hashlib.sha256(message.encode()).hexdigest()
        s.send(str(key.encrypt_string(hashed_message)).encode("utf-8"))




s.close()


