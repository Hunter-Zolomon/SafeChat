from Crypto.PublicKey import RSA
import socket;
import select;
import os;
import hashlib;
from Crypto import Random;
from Crypto.Cipher import AES;
from termcolor import colored;

def receive_message(client_socket):
    try:
        message_header = client_socket.recv(HEADER_LENGTH);
        if not len(message_header):
            return False;
        message_length = int(message_header.decode('utf-8').strip());
        return {'header': message_header, 'data': client_socket.recv(message_length)};
        pass;
    except:
        return False;

def broadcast(client_socket, message):
    for socket in socket_list:
        if socket != server_socket and socket != client_socket:
            try:
                socket.send(message);
            except:
                socket.close();
                socket_list.remove(socket);

def RemovePadding(s):
    return s.replace('`','');


def Padding(s):
    return s + ((16 - len(s) % 16) * '`');

def send(client_socket, message):
    message_sender = message.encode('utf-8');
    message_sender_header = f"{len(message_sender):<{HEADER_LENGTH}}".encode('utf-8');
    client_socket.send(message_sender_header + message_sender);

def sendEncrypted(client_socket, message, AESKey):
    message_encrypted = AESKey.encrypt(message);
    message_sender = message_encrypted.encode('utf-8');
    message_sender_header = f"{len(message_sender):<{HEADER_LENGTH}}".encode('utf-8');
    client_socket.send(message_sender_header + message_sender);

HEADER_LENGTH = 10;
FLAG_READY = "Ready";
FLAG_QUIT = "Quit";
YES = "1";
NO = "0";

hasher = hashlib.sha512();

random_generator = Random.new().read;
RSAkey = RSA.generate(4096, random_generator);
public = RSAkey.publickey().exportKey();
private = RSAkey.exportKey();
public_hash = hashlib.sha512(public);
#public_hash = hasher.update(public);
public_hash_hexdigest = public_hash.hexdigest();
ttwoByte = os.urandom(32);
session = hashlib.sha512(ttwoByte);
session_hexdigest = session.hexdigest();

print("Server Public Key: %s" %public);
print("Server Private Key: %s" %private);
print("Server AESKey: %s" %session_hexdigest);

IP = str(input("Enter Server IP Address: "));
Port = int(input("Enter Socket Port: "));

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1);

print("Binding to socket tuple...");
server_socket.bind((IP, Port));
server_socket.listen();

socket_list = [server_socket];
client_dic = {};

print(colored("Server Connection Successfully Setup!", "green"));
print(colored(f"Listening for connections on {IP}:{Port}...", "magenta"));

while(True):
    read_sockets, write_sockets, exception_sockets = select.select(socket_list, [], socket_list, 0);
    for socket in read_sockets:
        if socket == server_socket:
            client_socket, client_address = server_socket.accept();
            print(colored("A Client Is Trying To Connect...", "yellow"));
            """colored("Waiting for client's username", "yellow");
            socket_list.append(client_socket);
            user = receive_message(client_socket);
            client_dic[client_socket] = user;
            print("Accepted new connection from {}:{}, Username: {}".format(*client_address, user['data'].decode('utf-8')));
            literal = f"[{client_address[0]}:{client_address[1]}] Has Entered The Chat";
            literal = literal.encode('utf-8');
            literal_header = f"{len(literal):<{HEADER_LENGTH}}".encode('utf-8');
            broadcast(client_socket, literal_header + literal);"""
            handshake_data = receive_message(client_socket);
            split = handshake_data["data"].decode('utf-8').split(":");
            tmpClientPublic = split[0];
            clientPublicHash = split[1];
            print("Anonymous Client's Public Key: {}".format(tmpClientPublic));
            tmpClientPublic = tmpClientPublic.replace("\r\n", '');
            clientPublicHash = clientPublicHash.replace("\r\n", '');
            tmpHashObject = hashlib.sha512(tmpClientPublic.encode('utf-8'));
            #tmpHashObject = hasher.update(tmpClientPublic.encode('utf-8'));
            tmphash = tmpHashObject.hexdigest();

            if tmphash == clientPublicHash:
                print(colored("Client's Public Key and Public Key Hash Matched!", "blue"));
                clientPublic = RSA.importKey(tmpClientPublic);
                fSend = ttwoByte + ":" + session_hexdigest + ":" + public_hash_hexdigest;
                fSend = clientPublic.encrypt(fSend, None);
                temp = str(fSend) + ":" + public;
                send(socket, temp);
                #temp = message.encode('utf-8');
                #temp_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8');
                #client_socket.send(temp_header + message);
                clientPH = receive_message(client_socket);
                
                if clientPH["data"].decode('utf-8') != "":
                    clientPH_other = RSA.importKey(private).decrypt(eval(clientPH["data"].decode('utf-8')));
                    print(colored("Matching Session Key...", "blue"));
                    if clientPH_other == ttwoByte:
                        print("Creating AES Key...", "blue");
                        key_256 = ttwoByte + ttwoByte[::-1];
                        AESKey = AES.new(key_256, AES.MODE_CTR, IV = key_256);
                        #client_msg = AESKey.encrypt(Padding(FLAG_READY));
                        client_msg = AESKey.encrypt(FLAG_READY);
                        send(client_socket, client_msg);
                        
            user = receive_message(client_socket);
            if user is False:
                continue;
            socket_list.append(client_socket);
            client_dic[client_socket] = user;
            print("Accepted new connection from {}:{}, Username: {}".format(*client_address, user['data'].decode('utf-8')));
            literal = f"[{client_address[0]}:{client_address[1]}] Has Entered The Chat";
            literal = literal.encode('utf-8');
            literal_header = f"{len(literal):<{HEADER_LENGTH}}".encode('utf-8');
            broadcast(client_socket, literal_header + literal);
        else:
            message = receive_message(socket);
            if message is False:
                print("Closed connection from: {}".format(client_dic[socket]['data'].decode('utf-8')));
                socket_list.remove(socket);
                del client_dic[socket];
                continue;
            user = client_dic[socket];
            print(f'Received message from {user["data"].decode("utf-8")}: {message["data"].decode("utf-8")}'); #removed ["data"] for user
            """for client in client_dic:
                if client != socket:
                    client_socket.send(user['header'] + user['data'] + message['header'] + message['data']);""" #Obsolete code replaced with broadcast()
            broadcast(socket, user['header'] + user["data"] + message['header'] + message['data']);
    for socket in exception_sockets:
        socket_list.remove(socket);
        del client_dic[socket];