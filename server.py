from Cryptodome.Hash import HMAC, SHA512;
from Cryptodome.PublicKey import RSA
from Cryptodome import Random;
from Cryptodome.Cipher import AES, PKCS1_OAEP;
from Cryptodome.Util import Counter;
import socket;
import select;
import os;
import re;
#import hashlib;

CUSTOM_SEPARATOR = b':0x0:';

class RT:
    #Text
    BLACK = '\u001b[30m';
    RED = '\u001b[31m';
    GREEN = '\u001b[32m';
    YELLOW = '\u001b[33m';
    BLUE = '\u001b[34m';
    MAGENTA = '\u001b[35m';
    CYAN = '\u001b[36m';
    WHITE = '\u001b[37m';
    
    #Background
    BBLACK = '\u001b[40m';
    BRED = '\u001b[41m';
    BGREEN = '\u001b[42m';
    BYELLOW = '\u001b[43m';
    BBLUE = '\u001b[44m';
    BMAGENTA = '\u001b[45m';
    BCYAN = '\u001b[46m';
    BWHITE = '\u001b[47m';

    RESET = '\u001b[0m';

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

def recv_exact(socket, size):
    buflist = [];
    while size:
        buf = socket.recv(size);
        if not buf:
            return False;
        buflist.append(buf);
        size -= len(buf);
    return b''.join(buflist);

def receive_message(client_socket):
    try:
        #message_header = client_socket.recv(HEADER_LENGTH);
        message_header = recv_exact(client_socket, HEADER_LENGTH);
        if not len(message_header):
            return False;
        message_length = int(message_header.decode('utf-8').strip());
        #return {'header': message_header, 'data': client_socket.recv(message_length)};
        return {'header': message_header, 'data': recv_exact(client_socket, message_length)};
        pass;
    except Exception as e:
        print(e);
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
        print(e);
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

def close_connection(socket, sock_list, client_dictionary):
    user = client_dictionary[socket]["data"]
    print("Closed connection from: {}".format(user.decode('utf-8')));
    literal = f"[{user.decode('utf-8')}] Has Left The Chat";
    literal = literal.encode('utf-8');
    literal_header = f"{len(literal):<{HEADER_LENGTH}}".encode('utf-8');
    broadcast(socket, user, literal, type="byte");
    sock_list.remove(socket);
    del client_dictionary[socket];
    return (sock_list, client_dictionary);

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

#hasher = hashlib.sha512();
hasher = SHA512.new();

random_generator = Random.new();
RSAkey = RSA.generate(4096, random_generator.read);
public = RSAkey.publickey().exportKey('DER');
private = RSAkey.exportKey('DER');
#public_hash = hashlib.sha512(public);
public_hash = SHA512.new(public);
public_hash_hexdigest = public_hash.hexdigest();

#Server's Public Key Debug
#print("Server Public Key: %s" %public);
#Server's Private Key Debug
#print("Server Private Key: %s" %private);

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
    print(f"{RT.GREEN}Successfully Binded!{RT.RESET}");
except Exception as e:
    print(f"{RT.RED}Error In The Binding Process!{RT.RESET}");
    print(e);
    exit(1);

socket_list = [server_socket];
client_dic = {};
aes_client_mapping = {};

print(f"{RT.GREEN}Server Connection Successfully Setup!{RT.RESET}");
print(f"{RT.MAGENTA}Listening for connections on {IP}:{Port}...{RT.RESET}");

while(True):
    read_sockets, write_sockets, exception_sockets = select.select(socket_list, [], socket_list);
    for socket in read_sockets:
        if socket == server_socket:
            client_socket, client_address = server_socket.accept();
            print(f"{RT.YELLOW}A Client Is Trying To Connect...{RT.RESET}");
            handshake_data = receive_message(client_socket);
            #split = handshake_data["data"].decode('utf-8').split(":");
            split = handshake_data["data"].split(CUSTOM_SEPARATOR);
            tmpClientPublic = split[0];
            clientPublicHash = split[1];
            #Connecting Client's Public Key Debug
            #print("Anonymous Client's Public Key: {}".format(tmpClientPublic));

            #tmpClientPublic = tmpClientPublic.replace("\r\n", '');
            tmpClientPublic = tmpClientPublic.replace(b'\r\n', b'');
            #clientPublicHash = clientPublicHash.replace("\r\n", '');
            clientPublicHash = clientPublicHash.replace(b"\r\n", b'');
            #tmpHashObject = hashlib.sha512(tmpClientPublic.encode('utf-8'));
            #tmpHashObject = SHA512.new(tmpClientPublic.encode('utf-8')); 
            tmpHashObject = SHA512.new(tmpClientPublic); 
            tmphash = tmpHashObject.hexdigest();

            if tmphash == clientPublicHash.decode('utf-8'):
                print(f"{RT.BLUE}Client's Public Key and Public Key Hash Matched!{RT.RESET}");
                clientPublic = RSA.import_key(tmpClientPublic);
                pkclient = PKCS1_OAEP.new(clientPublic);
                ttwoByte = os.urandom(32);
                #Connecting Client's TTwoByte Debug
                #print("Client Server Map TTWoByte: %s" %ttwoByte);

                #session = hashlib.sha512(ttwoByte);
                session = SHA512.new(ttwoByte);
                session_hexdigest = session.hexdigest();
                aes_client_mapping[client_socket] = ttwoByte;
                #fSend = ttwoByte + ":0x0:".encode('utf-8') + session_hexdigest.encode('utf-8') + ":0x0:".encode('utf-8') + public_hash_hexdigest.encode('utf-8');
                fSend = ttwoByte + CUSTOM_SEPARATOR + session_hexdigest.encode('utf-8') + CUSTOM_SEPARATOR + public_hash_hexdigest.encode('utf-8');
                #TTwoByte, Session Hash, and Public Hash Debug
                #print(fSend);
                #(fSend, ) = clientPublic.encrypt(fSend, None);
                fSend = pkclient.encrypt(fSend);
                temp = fSend + "(:0x0:)".encode('utf-8') + public;
                #TTwoByte, Session Hash, Public Hash, and Public Key Debug
                #print(temp);
                try:
                    send_message(client_socket, temp, "byte");
                except Exception as e:
                    print(f"{RT.RED}Error while Sending fSend!{RT.RESET}");
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
                    intermediate = RSA.import_key(private);
                    clientPH_other = PKCS1_OAEP.new(intermediate).decrypt(clientPH["data"]);
                    print(f"{RT.BLUE}Matching Session Key...{RT.RESET}");
                    if clientPH_other == ttwoByte:
                        print(f"{RT.BLUE}Creating AES Key...{RT.RESET}");
                        key_256 = ttwoByte;
                        client_msg = AESEncrypt(key_256, "Ready".encode('utf-8'));
                        send_message(client_socket, client_msg, "byte");
                        print(f"{RT.BLUE}Waiting For Client's Username...{RT.RESET}");
                        user = recieveEncryptedMessage(client_socket, key_256);
                        if user is False:
                            print(f"{RT.RED}Error While receiving username! Halting Handshake{RT.RESET}");
                            continue;
                        socket_list.append(client_socket);
                        client_dic[client_socket] = user;
                        print("Accepted new connection from {}:{}, Username: {}".format(*client_address, user['data'].decode('utf-8')));
                        literal = f"[{client_address[0]}:{client_address[1]}] Has Entered The Chat";
                        literal = literal.encode('utf-8');
                        literal_header = f"{len(literal):<{HEADER_LENGTH}}".encode('utf-8');
                        broadcast(client_socket, user["data"], literal, type="byte");
                    else:
                        print(f"{RT.RED}Session Key From Client Does Not Match!{RT.RESET}");
            else:
                print(f"{RT.RED}Could Not Match Client's Public Hash! Exiting...{RT.RESET}");
                exit(1);
        else:
            user = client_dic[socket];
            user_key = aes_client_mapping[socket];
            decrypted_message = recieveEncryptedMessage(socket, user_key);
            if decrypted_message is False:
                (socket_list, client_dic) = close_connection(socket, socket_list, client_dic);
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
        (socket_list, client_dic) = close_connection(socket, socket_list, client_dic);