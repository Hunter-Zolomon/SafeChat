from Crypto.Cipher import AES
import socket;
import select;
import errno;
import sys;
from Crypto import Random;
from Crypto.PublicKey import RSA;
import hashlib;
from termcolor import colored;

def send(client_socket, message):
    message_sender = message.encode('utf-8');
    message_sender_header = f"{len(message_sender):<{HEADER_LENGTH}}".encode('utf-8');
    client_socket.send(message_sender_header + message_sender);

def sendEncrypted(client_socket, message, AESKey):
    message_encrypted = AESKey.encrypt(message);
    message_sender = message_encrypted.encode('utf-8');
    message_sender_header = f"{len(message_sender):<{HEADER_LENGTH}}".encode('utf-8');
    client_socket.send(message_sender_header + message_sender);

def recieveEncryptedMessage(client_socket):
    message_header = client_socket.recv(HEADER_LENGTH);
    message_length = int(username_header.decode('utf-8').strip());
    return AESKey.decrypt(client_socket.recv(username_length).decode('utf-8'));

def prompt():
    sys.stdout.write("<You> ");
    sys.stdout.flush();

HEADER_LENGTH = 10;
FLAG_READY = "Ready";
FLAG_QUIT = "Quit";

hasher = hashlib.sha512();

random_generator = Random.new().read;
RSAKey = RSA.generate(4096, random_generator);
public = RSAKey.publickey().exportKey();
private = RSAKey.exportKey();
public_hash = hashlib.sha512(public);
#public_hash = hasher.update(public);
public_hash_hexdigest = public_hash.hexdigest();

print("Your Public Key: %s" %public);
print("Your Private Key: %s" %private);

IP = str(input("Enter Server IP Address: "));
Port = int(input("Enter Socket Port: "));
user_username = str(input("Username: "));

try:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
    print("Connecting to Server...");
    client_socket.connect((IP, Port));
    print(colored("Connected!", "green"));
    client_socket.setblocking(False);
except BaseException:
    print(colored("Error Occured During Connection Phase!", "red"));
    exit(1);

send(client_socket, str(public) + ":" + str(public_hash_hexdigest));

while(True):
    try:
        fGet_header = client_socket.recv(HEADER_LENGTH);
        break;
    except Exception:
        pass

#fGet_header = client_socket.recv(HEADER_LENGTH);
fGet_length = int(fGet_header.decode('utf-8').strip());
fGet = client_socket.recv(fGet_length).decode('utf-8');
split = fGet["data"].split(":");
toDecrypt = split[0];
serverPublic = split[1];
print("Server's Public Key: %s" %serverPublic);
decrypted = RSA.importKey(private).decrypt(eval(toDecrypt.replace("\r\n", '')));
splittedDecrypt = decrypted.split(":");
ttwoByte = splittedDecrypt[0];
session_hexdigest = splittedDecrypt[1];
serverPublicHash = splittedDecrypt[2];
print("Client's AES Key In Hash: %s" %session_hexdigest);
sess = hashlib.sha512(ttwoByte);
#sess = hasher.update(ttwoByte);
sess_hexdigest = sess.hexdigest();
hashObj = hashlib.sha512(serverPublic);
#hashObj = hasher.update(serverPublic);
server_public_hash = hashObj.hexdigest();
print(colored("Matching Server's Public Key & AES Key...", "yellow"));
if server_public_hash == serverPublicHash and sess_hexdigest == session_hexdigest:
    print(colored("Sending Encrypted Session Key...", "blue"));
    serverPublic = RSA.importKey(serverPublic).encrypt(ttwoByte, None);
    send(client_socket, str(serverPublic));
    print(colored("Creating AES Key...", "blue"));
    key_256 = ttwoByte + ttwoByte[::-1];
    AESKey = AES.new(key_256, AES.MODE_CTR, IV=key_256);
    ready_header = client_socket.recv(HEADER_LENGTH);
    ready_length = int(ready_header.decode('utf-8').strip());
    ready = client_socket.recv(ready_length).decode('utf-8');
    ready_msg = AESKey.decrypt(ready["data"]);
    if ready_msg == FLAG_READY:
        print("Client Is Ready To Communicate!", "green");
    else:
        print(colored("Server's Public || Session Key Doesn't Match. Shutting Down Socket!", "red"));

username = user_username.encode('utf-8');
username_header = f"{len(username):<{HEADER_LENGTH}}".encode('utf-8');
client_socket.send(username_header + username);

prompt();

while(True):
    socket_list = [sys.stdin, client_socket];
    read_sockets, write_socket, error_socket = select.select(socket_list, [], [], 0);
    for socks in read_sockets:
        if socks == client_socket:
            try:
                username_header = client_socket.recv(HEADER_LENGTH);
                if not len(username_header):
                    print("Connection Closed By The Server");
                    sys.exit();
                username_length = int(username_header.decode('utf-8').strip());
                rusername = client_socket.recv(username_length).decode('utf-8');
                message_header = client_socket.recv(HEADER_LENGTH);
                message_length = int(message_header.decode('utf-8').strip());
                message = client_socket.recv(message_length).decode('utf-8');
                print(f"{rusername} > {message}");
                prompt();
            except IOError as e:
                if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                    print("Reading error: {}".format(str(e)));
                    sys.exit();
                continue;
            except Exception as e:
                print("General Error {}".format(str(e)));
                sys.exit();
        else:
            message = sys.stdin.readline();
            if message:
                message = message.encode('utf-8');
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8');
                client_socket.send(message_header + message);
                prompt();