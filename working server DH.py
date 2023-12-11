import socket
import threading
import random

# Create a socket object
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Get local machine name
host = socket.gethostname()

port = random.randint(10000, 20000)

print ('Server started!')
print (host + ':' + str(port))
print ('Waiting for clients...')

# Bind to the port
server.bind((host, port))

# Now wait for client connection.
server.listen(5)

all_messages = []

def client_thread(conn):
    # infinite loop so that function do not terminate and thread do not end.
    while True:
        # Receiving from client
        data = conn.recv(1024)
        print(data)
        if not data:
            print('break')
            break
        if data.decode("utf-8") == '[$get]':
            print('sending all messages')
            conn.send(str(all_messages).encode())
        else:
            print('adding message to all messages')
            all_messages.append(data)

        # exit on keyboard interrupt
        try:
            pass
        except KeyboardInterrupt:
            print('KeyboardInterrupt')
            exit()
        
    # came out of loop
    conn.close()

while True:
    # Wait to accept a connection - blocking call
    conn, addr = server.accept()
    print ('Connected with ' + addr[0] + ':' + str(addr[1]))
    # start new thread takes 1st argument as a function name to be run, second is the tuple of arguments to the function.
    threading.Thread(target=client_thread, args=(conn,)).start()

server.close()
