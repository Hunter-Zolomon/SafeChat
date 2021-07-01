from Cryptodome.Hash import SHA512;
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pss;
from Cryptodome import Random;
from Cryptodome.Cipher import ChaCha20_Poly1305, PKCS1_OAEP;
import socket;
import select;
import os;
import re;

CUSTOM_SEPARATOR = b':0x0:';
CHACHA_HEADER = b"header";
HEADER_LENGTH = 10;
socket_list = [];
socket_list_vo_com = [];
client_dic = {};
client_dic_vo_com = {};
chacha_client_mapping = {};

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

def ChaChaEncrypt(key, header, plaintext):
    chacha = ChaCha20_Poly1305.new(key=key);
    chacha.update(header);
    return (chacha.encrypt_and_digest(plaintext), chacha.nonce);

def ChaChaDecrypt(key, tag, header, ciphertext):
    chacha = ChaCha20_Poly1305.new(key=key, nonce=ciphertext[:12]);
    chacha.update(header);
    return chacha.decrypt_and_verify(ciphertext[12:], tag);

def send_message(client_socket, message, type="byte"):
    if type == "byte":
        message_header = encode(f"{len(message):<{HEADER_LENGTH}}");
        client_socket.send(message_header + message);
    elif type == "string":
        message_sender = encode(message);
        message_sender_header = encode(f"{len(message_sender):<{HEADER_LENGTH}}");
        client_socket.send(message_sender_header + message_sender);

def sendEncryptedMessage(client_socket, message, Chakey):
    ((message_encrypted, message_tag), nonce) = ChaChaEncrypt(Chakey, CHACHA_HEADER, message);
    send_message(client_socket, nonce + message_encrypted + CUSTOM_SEPARATOR + message_tag, type="byte");

def recv_exact(socket, size):
    buf_list = [];
    while size:
        buf = socket.recv(size);
        if not buf:
            return False;
        buf_list.append(buf);
        size -= len(buf);
    return b''.join(buf_list);

def receive_message(client_socket):
    try:
        message_header = recv_exact(client_socket, HEADER_LENGTH);
        if not len(message_header):
            return False;
        try:
            message_length = int(message_header.decode('utf-8').strip());
        except Exception as e:
            print("Int conversion failed. Probably recv overflow: " + str(e));
        return {'header': message_header, 'data': recv_exact(client_socket, message_length)};
        pass;
    except Exception as e:
        print(e);
        return False;

def receiveEncryptedMessage(client_socket, Chakey, passthrough=False):
    decrypted_message = '';
    try:
        whole_message = receive_message(client_socket);
        message_split = whole_message["data"].split(CUSTOM_SEPARATOR);
        decrypted_message = ChaChaDecrypt(Chakey, message_split[1], CHACHA_HEADER, message_split[0]);
        return {'header': whole_message["header"], 'data': decrypted_message, 'integrity': True};
    except ValueError as ve:
        return {'header': whole_message["header"], 'data': decrypted_message, 'integrity': False}; 
    except Exception as e:
        print(e);
        return False;

def broadcast(client_socket, user, message, type="byte", socket_array=socket_list):
    for socket in socket_array:
        if socket != server_socket and socket != client_socket:
            try:
                username_header = encode(f"{len(user):<{HEADER_LENGTH}}");
                user_socket_key = chacha_client_mapping[socket];
                ((enc_message, msg_tag), msg_nonce) = ChaChaEncrypt(user_socket_key, CHACHA_HEADER, message);
                message_combined = msg_nonce + enc_message + CUSTOM_SEPARATOR + msg_tag;
                enc_message_header = encode(f"{len(message_combined):<{HEADER_LENGTH}}");
                socket.send(username_header + user + enc_message_header + message_combined);
            except:
                socket.close();
                socket_list.remove(socket);

def close_connection(socket, sock_list, sock_list_vo_com, client_dictionary, client_dictionary_vo_com):
    if len(client_dictionary):
        user = client_dictionary[socket]["data"];
        print("Closed connection from: {}".format(user.decode('utf-8')));
        literal = f"[{user.decode('utf-8')}] Has Left The Chat";
        literal = encode(literal);
        literal_header = encode(f"{len(literal):<{HEADER_LENGTH}}");
        broadcast(socket, user, literal, type="byte");
        if socket in sock_list: sock_list.remove(socket);
        if socket in socket_list_vo_com: sock_list_vo_com.remove(socket);
        if socket in client_dictionary: del client_dictionary[socket];
        if socket in client_dictionary_vo_com: del client_dictionary_vo_com[socket];
        if socket in chacha_client_mapping: del chacha_client_mapping[socket];
        return [sock_list, sock_list_vo_com, client_dictionary, client_dictionary_vo_com];
    else:
        print("Closed connection from: UNKNOWN");
        if socket in sock_list: sock_list.remove(socket);
        if socket in socket_list_vo_com: sock_list_vo_com.remove(socket);
        return [sock_list, sock_list_vo_com, client_dictionary, client_dictionary_vo_com];
    
def encode(richstring):
    return richstring.encode('utf-8');

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

hasher = SHA512.new();
random_generator = Random.new();
RSA_key = RSA.generate(4096, random_generator.read);
public = RSA_key.publickey().exportKey('DER');
private = RSA_key.exportKey('DER');
public_hash = SHA512.new(public);
public_hash_hexdigest = public_hash.hexdigest();

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
    print(f"{RT.GREEN}Successfully Bound!{RT.RESET}");
except Exception as e:
    print(f"{RT.RED}Error In The Binding Process!{RT.RESET}");
    print(e);
    exit(1);

socket_list.append(server_socket);
socket_list_vo_com.append(server_socket);

print(f"{RT.GREEN}Server Connection Successfully Setup!{RT.RESET}");
print(f"{RT.MAGENTA}Listening for connections on {IP}:{Port}...{RT.RESET}");

while(True):
    read_sockets, write_sockets, exception_sockets = select.select(socket_list, [], socket_list);
    for socket in read_sockets:
        if socket == server_socket:
            client_socket, client_address = server_socket.accept();
            print(f"{RT.YELLOW}A Client Is Trying To Connect...{RT.RESET}");
            handshake_data = receive_message(client_socket);
            split = handshake_data["data"].split(CUSTOM_SEPARATOR);
            tmpClientPublic = split[0];
            clientPublicHash = split[1];
            clientSignature = split[2];
            tmpClientPublic = tmpClientPublic.replace(b'\r\n', b'');
            clientPublicHash = clientPublicHash.replace(b"\r\n", b'');
            tmpHashObject = SHA512.new(tmpClientPublic); 
            tmphash = tmpHashObject.hexdigest();

            if tmphash == clientPublicHash.decode('utf-8'):
                print(f"{RT.BLUE}Client's Public Key and Public Key Hash Matched!{RT.RESET}");
                clientPublic = RSA.import_key(tmpClientPublic);
                signature_hash = SHA512.new(tmpClientPublic + CUSTOM_SEPARATOR + clientPublicHash);
                verifier = pss.new(clientPublic);
                try:
                    verifier.verify(signature_hash, clientSignature);
                    print(f"{RT.CYAN}Client Signature Verified!{RT.RESET}");
                except (ValueError, TypeError):
                    print(f"{RT.RED}Could Not Verify Client's Signature! Rejecting Connection!{RT.RESET}");
                    close_connection(client_socket, socket_list, socket_list_vo_com, client_dic, client_dic_vo_com);
                    continue;
                pk_client = PKCS1_OAEP.new(clientPublic);
                ttwoByte = os.urandom(32);
                session = SHA512.new(ttwoByte);
                session_hexdigest = session.hexdigest();
                chacha_client_mapping[client_socket] = ttwoByte;
                fSend = ttwoByte + CUSTOM_SEPARATOR + encode(session_hexdigest) + CUSTOM_SEPARATOR + encode(public_hash_hexdigest);
                fSend = pk_client.encrypt(fSend);
                temp = fSend + encode("(:0x0:)") + public;
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
                
                if clientPH["data"] != encode(""):
                    intermediate = RSA.import_key(private);
                    clientPH_other = PKCS1_OAEP.new(intermediate).decrypt(clientPH["data"]);
                    print(f"{RT.BLUE}Matching Session Key...{RT.RESET}");
                    if clientPH_other == ttwoByte:
                        print(f"{RT.BLUE}Creating ChaCha Key...{RT.RESET}");
                        key_256 = ttwoByte;
                        ((client_msg, tag), nonce) = ChaChaEncrypt(key_256, CHACHA_HEADER, encode("Ready"));
                        send_message(client_socket, nonce + client_msg + CUSTOM_SEPARATOR + tag, "byte");
                        print(f"{RT.BLUE}Waiting For Client's Username...{RT.RESET}");
                        user = receiveEncryptedMessage(client_socket, key_256);
                        if user is False:
                            print(f"{RT.RED}Error While receiving username! Halting Handshake{RT.RESET}");
                            close_connection(client_socket, socket_list, socket_list_vo_com, client_dic, client_dic_vo_com);
                            continue;
                        socket_list.append(client_socket);
                        client_dic[client_socket] = user;
                        print("Accepted new connection from {}:{}, Username: {}".format(*client_address, user['data'].decode('utf-8')));
                        literal = f"[{client_address[0]}:{client_address[1]}] Has Entered The Chat";
                        literal = encode(literal);
                        literal_header = encode(f"{len(literal):<{HEADER_LENGTH}}");
                        broadcast(client_socket, user["data"], literal, type="byte");
                    else:
                        print(f"{RT.RED}Session Key From Client Does Not Match!{RT.RESET}");
                        close_connection(client_socket, socket_list, socket_list_vo_com, client_dic, client_dic_vo_com);
                        continue;
            else:
                print(f"{RT.RED}Could Not Match Client's Public Hash! Exiting...{RT.RESET}");
                close_connection(client_socket, socket_list, socket_list_vo_com, client_dic, client_dic_vo_com);
                continue;
        else:
            user = client_dic[socket];
            user_key = chacha_client_mapping[socket];
            if socket in client_dic_vo_com:
                decrypted_message = receiveEncryptedMessage(socket, user_key, True);
                if decrypted_message is False:
                    close_connection(socket, socket_list, socket_list_vo_com, client_dic, client_dic_vo_com);
                    continue;
                broadcast(socket, user["data"], decrypted_message["data"], "byte", socket_list_vo_com);
                continue;
            decrypted_message = receiveEncryptedMessage(socket, user_key);
            if decrypted_message is False:
                close_connection(socket, socket_list, socket_list_vo_com, client_dic, client_dic_vo_com);
                continue;
            elif decrypted_message["data"][:13] == b'SFTP Initiate':
                print(f'Received message from {user["data"].decode("utf-8")}: [{str(decrypted_message["integrity"])}] {decrypted_message["data"]}'); #removed ["data"] for user
                broadcast(socket, user["data"], decrypted_message["data"], "byte");
                decrypted_message = receiveEncryptedMessage(socket, user_key, True);
                while not (decrypted_message["data"][:8] == encode('SFTP END')):
                    broadcast(socket, user["data"], decrypted_message["data"], "byte");
                    decrypted_message = receiveEncryptedMessage(socket, user_key, True);
                print(f'Received message from {user["data"].decode("utf-8")}: [{str(decrypted_message["integrity"])}] {decrypted_message["data"]}'); #removed ["data"] for user
                broadcast(socket, user["data"], decrypted_message["data"], "byte");
                continue;
            elif decrypted_message["data"][:14] == b'VoCom Initiate':
                client_dic_vo_com[socket] = user;
                socket_list_vo_com.append(socket);
                continue;
            print(f'Received message from {user["data"].decode("utf-8")}: [{str(decrypted_message["integrity"])}] {decrypted_message["data"]}'); #removed ["data"] for user
            if decrypted_message["integrity"]:
                broadcast(socket, user["data"], decrypted_message["data"], "byte");
            else:
                continue;
    for socket in exception_sockets:
        close_connection(socket, socket_list, socket_list_vo_com, client_dic, client_dic_vo_com);