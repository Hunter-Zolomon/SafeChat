from cryptography.hazmat.primitives.serialization import load_der_private_key, load_der_public_key;
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305;
from cryptography.hazmat.primitives.serialization import PublicFormat;
from cryptography.hazmat.primitives.serialization import Encoding;
from cryptography.exceptions import InvalidTag, InvalidKey;
from cryptography.hazmat.primitives.asymmetric import ec;
from cryptography.hazmat.primitives.kdf.hkdf import HKDF;
from cryptography.hazmat.primitives import hashes;
import socket;
import select;
import os;
import re;

CUSTOM_SEPARATOR = b':0x0:';
CHACHA_HEADER = b'header';
HEADER_LENGTH = 10;
socket_list = [];
socket_list_vocom = [];
client_dic = {};
client_dic_vocom = {};
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

def SHA3_512_Hasher(string):
    hashobj = hashes.Hash(hashes.SHA3_512());
    hashobj.update(string);
    return hashobj.finalize();

def ChaChaEncrypt(key, header, plaintext):
    chacha = ChaCha20Poly1305(key);
    nonce = os.urandom(12);
    return chacha.encrypt(nonce, plaintext, header) + nonce;

def ChaChaDecrypt(key, header, ciphertext):
    chacha = ChaCha20Poly1305(key);
    return chacha.decrypt(ciphertext[-12:], ciphertext[:-12], header);

def send_message(client_socket, message, type="byte"):
    if type == "byte":
        message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8');
        client_socket.send(message_header + message);
    elif type == "string":
        message_sender = message.encode('utf-8');
        message_sender_header = f"{len(message_sender):<{HEADER_LENGTH}}".encode('utf-8');
        client_socket.send(message_sender_header + message_sender);

def sendEncryptedMessage(client_socket, message, chaKey):
    message_encrypted = ChaChaEncrypt(chaKey, CHACHA_HEADER, message);
    send_message(client_socket, message_encrypted, type="byte");

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

def recieveEncryptedMessage(client_socket, chaKey, passthrough=False):
    try:
        whole_message = receive_message(client_socket);
        decrypted_message = ChaChaDecrypt(chaKey, CHACHA_HEADER, whole_message["data"]);
        return {'header': whole_message["header"], 'data': decrypted_message, 'integrity': True};
    except InvalidTag as eit:
        return {'header': whole_message["header"], 'data': decrypted_message, 'integrity': False};
    except Exception as e:
        print(e);
        return False;

def broadcast(client_socket, user, message, type="byte", socket_array=socket_list):
    for socket in socket_array:
        if socket != server_socket and socket != client_socket:
            try:
                username_header = f"{len(user):<{HEADER_LENGTH}}".encode('utf-8');
                user_socket_key = chacha_client_mapping[socket];
                enc_message = ChaChaEncrypt(user_socket_key, CHACHA_HEADER, message);
                enc_message_header = f"{len(enc_message):<{HEADER_LENGTH}}".encode('utf-8');
                socket.send(username_header + user + enc_message_header + enc_message);
            except:
                socket.close();
                socket_list.remove(socket);

def close_connection(socket, sock_list, sock_list_vocom, client_dictionary, client_dictionary_vocom):
    if len(client_dictionary):
        user = client_dictionary[socket]["data"];
        print("Closed connection from: {}".format(user.decode('utf-8')));
        literal = f"[{user.decode('utf-8')}] Has Left The Chat";
        literal = literal.encode('utf-8');
        literal_header = f"{len(literal):<{HEADER_LENGTH}}".encode('utf-8');
        broadcast(socket, user, literal, type="byte");
        if socket in sock_list: sock_list.remove(socket);
        if socket in socket_list_vocom: sock_list_vocom.remove(socket);
        if socket in client_dictionary: del client_dictionary[socket];
        if socket in client_dictionary_vocom: del client_dictionary_vocom[socket];
        if socket in chacha_client_mapping: del chacha_client_mapping[socket];
        return [sock_list, sock_list_vocom, client_dictionary, client_dictionary_vocom];
    else:
        print("Closed connection from: UNKNOWN");
        if socket in sock_list: sock_list.remove(socket);
        if socket in socket_list_vocom: sock_list_vocom.remove(socket);
        return [sock_list, sock_list_vocom, client_dictionary, client_dictionary_vocom];
    

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

ecdhe_private_key = ec.generate_private_key(ec.SECP521R1());
public_hash_final = SHA3_512_Hasher(ecdhe_private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo));
client_exchange_msg = ecdhe_private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo) + CUSTOM_SEPARATOR + public_hash_final;
client_exchange_ecdhe_signature = ecdhe_private_key.sign(SHA3_512_Hasher(client_exchange_msg), ec.ECDSA(hashes.SHA3_512())); #WARNING: Change this to a global derived key later.

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

socket_list.append(server_socket);
socket_list_vocom.append(server_socket);

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
            received_client_public = split[0];
            received_client_public_hash = split[1];
            received_client_sig = split[2];
            received_client_public = received_client_public.replace(b'\r\n', b'');
            received_client_public_hash = received_client_public_hash.replace(b"\r\n", b'');
            tmphash_final = SHA3_512_Hasher(received_client_public);

            if tmphash_final == received_client_public_hash:
                print(f"{RT.BLUE}Client's Public Key and Public Key Hash Matched!{RT.RESET}");
                tmp_client_pubkey = load_der_public_key(received_client_public, None);
                signature_hash = SHA3_512_Hasher(received_client_public + CUSTOM_SEPARATOR + received_client_public_hash);
                try:
                    tmp_client_pubkey.verify(received_client_sig, signature_hash, ec.ECDSA(hashes.SHA3_512()));
                    print(f"{RT.CYAN}Client Signature Verified!{RT.RESET}");
                except (ValueError, TypeError):
                    print(f"{RT.RED}Could Not Verify Client's Signature! Rejecting Connection!{RT.RESET}");
                    close_connection(client_socket, socket_list, socket_list_vocom, client_dic, client_dic_vocom);
                    continue;
                shared_key = ecdhe_private_key.exchange(ec.ECDH(), tmp_client_pubkey);
                derived_key = HKDF(
                    algorithm=hashes.SHA3_512(),
                    length=32,
                    salt=None,
                    info=b'handshake data',
                ).derive(shared_key);
                chacha_client_mapping[client_socket] = derived_key;
                try:
                    send_message(client_socket, client_exchange_msg + CUSTOM_SEPARATOR + client_exchange_ecdhe_signature, "byte");
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
                
                if clientPH["data"] == ecdhe_private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo):
                    client_msg = ChaChaEncrypt(derived_key, CHACHA_HEADER, "Ready".encode('utf-8'));
                    send_message(client_socket, client_msg, "byte");
                    print(f"{RT.BLUE}Waiting For Client's Username...{RT.RESET}");
                    user = recieveEncryptedMessage(client_socket, derived_key);
                    if user is False:
                        print(f"{RT.RED}Error While receiving username! Halting Handshake{RT.RESET}");
                        close_connection(client_socket, socket_list, socket_list_vocom, client_dic, client_dic_vocom);
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
                    close_connection(client_socket, socket_list, socket_list_vocom, client_dic, client_dic_vocom);
                    continue;
            else:
                print(f"{RT.RED}Could Not Match Client's Public Hash! Exiting...{RT.RESET}");
                close_connection(client_socket, socket_list, socket_list_vocom, client_dic, client_dic_vocom);
                continue;
        else:
            user = client_dic[socket];
            user_key = chacha_client_mapping[socket];
            if socket in client_dic_vocom:
                decrypted_message = recieveEncryptedMessage(socket, user_key, True);
                if decrypted_message is False:
                    close_connection(socket, socket_list, socket_list_vocom, client_dic, client_dic_vocom);
                    continue;
                broadcast(socket, user["data"], decrypted_message["data"], "byte", socket_list_vocom);
                continue;
            decrypted_message = recieveEncryptedMessage(socket, user_key);
            if decrypted_message is False:
                close_connection(socket, socket_list, socket_list_vocom, client_dic, client_dic_vocom);
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
            elif decrypted_message["data"][:14] == b'VoCom Initiate':
                client_dic_vocom[socket] = user;
                socket_list_vocom.append(socket);
                continue;
            print(f'Received message from {user["data"].decode("utf-8")}: [{str(decrypted_message["integrity"])}] {decrypted_message["data"]}'); #removed ["data"] for user
            if decrypted_message["integrity"]:
                broadcast(socket, user["data"], decrypted_message["data"], "byte");
            else:
                continue;
    for socket in exception_sockets:
        close_connection(socket, socket_list, socket_list_vocom, client_dic, client_dic_vocom);