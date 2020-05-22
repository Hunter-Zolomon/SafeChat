from Crypto.Hash import HMAC, SHA512;
from Crypto.PublicKey import RSA
from Crypto import Random;
from Crypto.Cipher import AES, PKCS1_OAEP;
from Crypto.Util import Counter;
from termcolor import colored;
import socket;
import select;
import os;
import hashlib;
import re;

CUSTOM_SEPARATOR = b':0x0:';

def HMACher(data, key, check_mode_var=""):
    hmac = HMAC.new(key, data, SHA512);
    if check_mode_var == "":
        return hmac.hexdigest();
    elif check_mode_var:
        if hmac.hexdigest() == check_mode_var:
            return True;
        else:
            return False;

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

def send_message(client_socket, message, type="byte"):
    if type == "byte":
        message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8');
        client_socket.send(message_header + message);
    elif type == "string":
        message_sender = message.encode('utf-8');
        message_sender_header = f"{len(message_sender):<{HEADER_LENGTH}}".encode('utf-8');
        client_socket.send(message_sender_header + message_sender);

def sendEncryptedMessage(client_socket, message, AESKey):
    hashed_message = HMACher(message, AESKey);
    message_encrypted = AESEncrypt(AESKey, message + CUSTOM_SEPARATOR + hashed_message);
    send_message(client_socket, message_encrypted, type="byte");
    #message_sender_header = f"{len(message_encrypted):<{HEADER_LENGTH}}".encode('utf-8');
    #client_socket.send(message_sender_header + message_encrypted);

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

def recieveEncryptedMessage(client_socket, AESKey, passthrough=False):
    try:
        whole_message = receive_message(client_socket);
        decrypted_message = AESDecrypt(AESKey, whole_message["data"]);
        split_decrypted_message = decrypted_message.split(CUSTOM_SEPARATOR);
        plain_message = CUSTOM_SEPARATOR.join(split_decrypted_message[:-1]);
        mac = split_decrypted_message[len(split_decrypted_message) - 1];
        if passthrough:
            return {'header': whole_message["header"], 'data': plain_message, 'integrity': True};
        #if mac == Hasher(decrypted_message[:len(decrypted_message)-69], key_256):
        if HMACher(plain_message, AESKey, mac.decode('utf-8')):
            return {'header': whole_message["header"], 'data': plain_message, 'integrity': True};
        else:
            return {'header': whole_message["header"], 'data': plain_message, 'integrity': False};
    except Exception as e:
        return False;

def broadcast(client_socket, user, message, type="byte"):
    for socket in socket_list:
        if socket != server_socket and socket != client_socket:
            try:
                username_header = f"{len(user):<{HEADER_LENGTH}}".encode('utf-8');
                user_socket_key = aes_client_mapping[socket];
                message_hash = HMACher(message, user_socket_key);
                enc_message = AESEncrypt(user_socket_key, message + CUSTOM_SEPARATOR + message_hash.encode('utf-8'));
                enc_message_header = f"{len(enc_message):<{HEADER_LENGTH}}".encode('utf-8');
                socket.send(username_header + user + enc_message_header + enc_message);
            except:
                socket.close();
                socket_list.remove(socket);

def checkIP(ip):
    regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)''';
    if (re.search(regex, ip)):
        return True;
    else:
        return False;

def checkPort(port):
    if (port >= 1 and port <= 65535):
        return True;
    else:
        return False;

HEADER_LENGTH = 10;

hasher = hashlib.sha512();

random_generator = Random.new();
RSAkey = RSA.generate(4096, random_generator.read);
public = RSAkey.publickey().exportKey();
private = RSAkey.exportKey();
public_hash = hashlib.sha512(public);
public_hash_hexdigest = public_hash.hexdigest();

print("Server Public Key: %s" %public);
print("Server Private Key: %s" %private);

IP = str(input("Enter Server IP Address: "));
while(checkIP(IP) == False):
    IP = str(input("Enter Server IP Address: "));
Port = int(input("Enter Socket Port: "));
while(checkPort(Port) == False):
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
    read_sockets, write_sockets, exception_sockets = select.select(socket_list, [], socket_list);
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
            tmphash = tmpHashObject.hexdigest();

            if tmphash == clientPublicHash:
                print(colored("Client's Public Key and Public Key Hash Matched!", "blue"));
                clientPublic = RSA.importKey(tmpClientPublic);
                pkclient = PKCS1_OAEP.new(clientPublic);
                ttwoByte = os.urandom(32);
                print("Client Server Map TTWoByte: %s" %ttwoByte);
                session = hashlib.sha512(ttwoByte);
                session_hexdigest = session.hexdigest();
                aes_client_mapping[client_socket] = ttwoByte;
                fSend = ttwoByte + ":0x0:".encode('utf-8') + session_hexdigest.encode('utf-8') + ":0x0:".encode('utf-8') + public_hash_hexdigest.encode('utf-8');
                print(fSend);
                print(" ");
                #(fSend, ) = clientPublic.encrypt(fSend, None);
                fSend = pkclient.encrypt(fSend);
                temp = fSend + "(:0x0:)".encode('utf-8') + public;
                print(temp);
                try:
                    send_message(client_socket, temp, "byte");
                except Exception as e:
                    print(colored("Error while Sending fSend!", "red"));
                    print(e);
                    exit(1);

                while(True):
                    clientPH = receive_message(client_socket);
                    if clientPH == False:
                        continue;
                    else:
                        break;
                
                if clientPH["data"] != "".encode('utf-8'):
                    #clientPH_other = RSA.importKey(private).decrypt(clientPH["data"]);
                    intermediate = RSA.importKey(private);
                    clientPH_other = PKCS1_OAEP.new(intermediate).decrypt(clientPH["data"]);
                    print(colored("Matching Session Key...", "blue"));
                    if clientPH_other == ttwoByte:
                        print(colored("Creating AES Key...", "blue"));
                        key_256 = ttwoByte;
                        client_msg = AESEncrypt(key_256, "Ready".encode('utf-8'));
                        send_message(client_socket, client_msg, "byte");
                        print(colored("Waiting For Client's Username...", "blue"));
                        user = recieveEncryptedMessage(client_socket, key_256);
                        if user is False:
                            print(colored("Error While receiving username! Halting Handshake", "red"));
                            continue;
                        socket_list.append(client_socket);
                        client_dic[client_socket] = user;
                        print("Accepted new connection from {}:{}, Username: {}".format(*client_address, user['data'].decode('utf-8')));
                        literal = f"[{client_address[0]}:{client_address[1]}] Has Entered The Chat";
                        literal = literal.encode('utf-8');
                        literal_header = f"{len(literal):<{HEADER_LENGTH}}".encode('utf-8');
                        broadcast(client_socket, user["data"], literal, type="byte");
                    else:
                        print(colored("Session Key From Client Does Not Match!", "red"));
            else:
                print(colored("Could Not Match Client's Public Hash! Exiting...", "red"));
                exit(1);
        else:
            user = client_dic[socket];
            user_key = aes_client_mapping[socket];
            decrypted_message = recieveEncryptedMessage(socket, user_key);
            if decrypted_message is False:
                print("Closed connection from: {}".format(client_dic[socket]['data'].decode('utf-8')));
                socket_list.remove(socket);
                del client_dic[socket];
                continue;
            elif decrypted_message["data"][:13] == b'SFTP Initiate':
                print(f'Received message from {user["data"].decode("utf-8")}: [{str(decrypted_message["integrity"])}] {decrypted_message["data"]}'); #removed ["data"] for user
                broadcast(socket, user["data"], decrypted_message["data"], "byte");
                decrypted_message = recieveEncryptedMessage(socket, user_key, True);
                while not (decrypted_message["data"][:8] == 'SFTP END'.encode('utf-8')):
                    broadcast(socket, user["data"], decrypted_message["data"], "byte");
                    decrypted_message = recieveEncryptedMessage(socket, user_key, True);
                print(f'Received message from {user["data"].decode("utf-8")}: [{str(decrypted_message["integrity"])}] {decrypted_message["data"]}'); #removed ["data"] for user
                broadcast(socket, user["data"], decrypted_message["data"], "byte");
                continue;
            #decrypted_message = decrypted_message["data"];
            print(f'Received message from {user["data"].decode("utf-8")}: [{str(decrypted_message["integrity"])}] {decrypted_message["data"]}'); #removed ["data"] for user
            if decrypted_message["integrity"]:
                broadcast(socket, user["data"], decrypted_message["data"], "byte");
            else:
                continue;
    for socket in exception_sockets:
        socket_list.remove(socket);
        del client_dic[socket];
