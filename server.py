from Crypto.PublicKey import RSA
import socket;
import select;
import os;
import hashlib;
from Crypto import Random;
from Crypto.Cipher import AES;
from Crypto.Util import Counter;
from termcolor import colored;

def AESEncrypt(key, plaintext):
    IV = os.urandom(16);
    ctr = Counter.new(128, initial_value=int.from_bytes(IV, byteorder='big'));
    aes = AES.new(key, AES.MODE_CTR, counter=ctr);
    return IV + aes.encrypt(plaintext);

def AESDecrypt(key, ciphertext):
    IV = ciphertext[:16];
    ctr = Counter.new(128, initial_value=int.from_bytes(IV, byteorder='big'));
    aes = AES.new(key, AES.MODE_CTR, counter=ctr);
    return aes.decrypt(ciphertext[16:]);

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

def broadcast(client_socket, user, message, type="byte"):
    for socket in socket_list:
        if socket != server_socket and socket != client_socket:
            try:
                #send(socket, message, type);
                user_socket_key = aes_client_mapping[socket];
                enc_message = AESEncrypt(user_socket_key, message);
                enc_message_header = f"{len(enc_message):<{HEADER_LENGTH}}".encode('utf-8');
                socket.send(user + enc_message_header + enc_message);
            except:
                socket.close();
                socket_list.remove(socket);

def RemovePadding(s):
    return s.replace('`','');


def Padding(s):
    return s + ((16 - len(s) % 16) * '`');

def send(client_socket, message, type="byte"):
    if type == "byte":
        message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8');
        client_socket.send(message_header + message);
    elif type == "string":
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

random_generator = Random.new();
RSAkey = RSA.generate(4096, random_generator.read);
public = RSAkey.publickey().exportKey();
private = RSAkey.exportKey();
public_hash = hashlib.sha512(public);
#public_hash = hasher.update(public);
public_hash_hexdigest = public_hash.hexdigest();
#ttwoByte = os.urandom(32);
#session = hashlib.sha512(ttwoByte);
#session_hexdigest = session.hexdigest();

print("Server Public Key: %s" %public);
print("Server Private Key: %s" %private);
#print("Server AESKey: %s" %session_hexdigest);

IP = str(input("Enter Server IP Address: "));
Port = int(input("Enter Socket Port: "));

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1);

try:
    print("Binding to socket tuple...");
    server_socket.bind((IP, Port));
    server_socket.listen();
    print(colored("Successfully Binded!", "green"));
except Exception as e:
    print(colored("Error In The Binding Process!", "red"));
    print(e);
    exit(1);

socket_list = [server_socket];
client_dic = {};
aes_client_mapping = {};

print(colored("Server Connection Successfully Setup!", "green"));
print(colored(f"Listening for connections on {IP}:{Port}...", "magenta"));

while(True):
    read_sockets, write_sockets, exception_sockets = select.select(socket_list, [], socket_list, 0);
    for socket in read_sockets:
        if socket == server_socket:
            client_socket, client_address = server_socket.accept();
            print(colored("A Client Is Trying To Connect...", "yellow"));
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
                ttwoByte = os.urandom(32);
                print("Client Server Map TTWoByte: %s" %ttwoByte);
                session = hashlib.sha512(ttwoByte);
                session_hexdigest = session.hexdigest();
                aes_client_mapping[client_socket] = ttwoByte;
                fSend = ttwoByte + ":0x0:".encode('utf-8') + session_hexdigest.encode('utf-8') + ":0x0:".encode('utf-8') + public_hash_hexdigest.encode('utf-8');
                print(fSend);
                print(" ");
                (fSend, ) = clientPublic.encrypt(fSend, None);
                temp = fSend + "(:0x0:)".encode('utf-8') + public;
                print(temp);
                try:
                    send(client_socket, temp, "byte");
                except Exception as e:
                    print(colored("Error while Sending fSend!", "red"));
                    print(e);
                    exit(1);
                #temp = message.encode('utf-8');
                #temp_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8');
                #client_socket.send(temp_header + message);
                while(True):
                    clientPH = receive_message(client_socket);
                    if clientPH == False:
                        continue;
                    else:
                        break;
                
                if clientPH["data"] != "".encode('utf-8'):
                    clientPH_other = RSA.importKey(private).decrypt(clientPH["data"]);
                    print(colored("Matching Session Key...", "blue"));
                    if clientPH_other == ttwoByte:
                        print(colored("Creating AES Key...", "blue"));
                        key_256 = ttwoByte;
                        #AESKey = AES.new(key_256, AES.MODE_CTR, counter=lambda: counter);
                        #AESKey = AES.new(key_256, AES.MODE_CBC, IV=key_256);
                        #client_msg = AESKey.encrypt(Padding(FLAG_READY));
                        #client_msg = AESKey.encrypt(FLAG_READY.encode('utf-8'));
                        client_msg = AESEncrypt(key_256, FLAG_READY.encode('utf-8'));
                        send(client_socket, client_msg, "byte");
                        print(colored("Waiting For Client's Username...", "blue"));
                        user = receive_message(client_socket);
                        if user is False:
                            continue;
                        socket_list.append(client_socket);
                        client_dic[client_socket] = user;
                        print("Accepted new connection from {}:{}, Username: {}".format(*client_address, user['data'].decode('utf-8')));
                        literal = f"[{client_address[0]}:{client_address[1]}] Has Entered The Chat";
                        literal = literal.encode('utf-8');
                        literal_header = f"{len(literal):<{HEADER_LENGTH}}".encode('utf-8');
                        #broadcast(client_socket, literal_header + literal);
                    else:
                        print(colored("Session Key From Client Does Not Match!", "red"));
            else:
                print(colored("Could Not Match Client's Public Hash! Exiting...", "red"));
                exit(1);
        else:
            message = receive_message(socket);
            if message is False:
                print("Closed connection from: {}".format(client_dic[socket]['data'].decode('utf-8')));
                socket_list.remove(socket);
                del client_dic[socket];
                continue;
            user = client_dic[socket];
            user_key = aes_client_mapping[socket];
            decrypted_message = AESDecrypt(user_key, message["data"]);
            """if decrypted_message[:13] == "SFTP Initiate".encode('utf-8'):
                address_data = receive_message(socket)["data"];
                f = open("extra" + AESDecrypt(user_key, address_data).decode('utf-8'), 'wb');
                l = receive_message(socket)["data"];
                l = AESDecrypt(user_key, l);
                while (l):
                    f.write(l);
                    if (l != "SFTP END".encode('utf-8')):
                        l = AESDecrypt(user_key, receive_message(socket)["data"]);
                    else:
                        break;
                f.close();"""
            print(f'Received message from {user["data"].decode("utf-8")}: {decrypted_message.decode("utf-8")}'); #removed ["data"] for user
            #broadcast(socket, user['header'] + user["data"] + message['header'] + message['data'], "byte");
            broadcast(socket, user['header'] + user["data"], decrypted_message, "byte");
    for socket in exception_sockets:
        socket_list.remove(socket);
        del client_dic[socket];

"""for client in client_dic:
                if client != socket:
                    client_socket.send(user['header'] + user['data'] + message['header'] + message['data']);""" #Obsolete code replaced with broadcast()
