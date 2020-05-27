from threading import Thread
from Cryptodome.Cipher import AES, PKCS1_OAEP;
from Cryptodome.PublicKey import RSA;
from Cryptodome.Signature import pss;
from Cryptodome.Util import Counter;
from Cryptodome.Hash import HMAC, SHA512;
from Cryptodome import Random;
import tqdm;
import tarfile;
import socket;
import select;
import errno;
import sys;
import os;
import pyaudio;
import threading;
import time;
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

def VoIPInitialize(chunk_size=1024, audio_format=pyaudio.paInt16, channels=1, rate=20000):
    p = pyaudio.PyAudio();
    playing_stream = p.open(format=audio_format, channels=channels, rate=rate, output=True, frames_per_buffer=chunk_size);
    recording_stream = p.open(format=audio_format, channels=channels, rate=rate, input=True, frames_per_buffer=chunk_size);
    return (playing_stream, recording_stream);

def receive_server_data(playing_stream, socket, key):
    while True:
        try:
            user_data = receive_message(socket);
            message_stream = recieveEncryptedMessage(socket, key)["data"];
            playing_stream.write(message_stream);
        except Exception as e:
            pass;
        
def send_data_to_server(recording_stream, socket, key, chunk_size):
    while True:
        try:
            data = recording_stream.read(chunk_size);
            sendEncryptedMessage(socket, data, key);
        except Exception as e:
            pass;

def FileCompressor(tar_file, files):
    tar = tarfile.open(tar_file, "w:gz");
    progress = tqdm.tqdm(files);
    for file in progress:
        tar.add(file);
        progress.set_description(f"Compressing {file}");
    tar.close();

def FileDecompressor(tar_file, file_name):
    tar = tarfile.open(tar_file, "r:gz");
    file_name = tar.getmembers()
    progress = tqdm.tqdm(file_name);
    for file in progress:
        tar.extract(file);
        progress.set_description(f"Extracting {file.name}")
    tar.close()

def UploadFile(socket, address, key, size_uncompressed, size_compressed, buffer=2048):
    #f = open(address, 'rb');
    f = open("temp.tar.gz", "rb");
    #file_hash_uc = hashlib.sha512();
    file_hash_uc = SHA512.new();
    #file_hash_c = hashlib.sha512();
    file_hash_c = SHA512.new();
    progress = tqdm.tqdm(range(size_compressed),f"Sending {address}", unit="B", unit_scale=True, unit_divisor=1024);
    with open(address, "rb") as filehandle:
        while True:
            block = filehandle.read(buffer);
            if not block:
                break;
            file_hash_uc.update(block);
    for _ in progress:
        l = f.read(buffer);
        if not l:
            break;
        read_socket, write_socket, exception_socket = select.select([], [socket], []);
        sendEncryptedMessage(socket, l, key);
        progress.update(len(l));
        file_hash_c.update(l);
    f.close();
    return (file_hash_uc, file_hash_c);

def DownloadFile(socket, name, key, size_uncompressed, size_compressed, buffer=2048):
    #f = open(name, 'wb');
    f = open("temp.tar.gz", "wb");
    #file_hash = hashlib.sha512();
    file_hash = SHA512.new();
    progress = tqdm.tqdm(range(size_compressed), f"Receiving {name}", unit="B", unit_scale=True, unit_divisor=1024);
    for _ in progress:
        user_data = receive_message(socket);
        l = recieveEncryptedMessage(socket, key)["data"];
        if (l[:8] != "SFTP END".encode('utf-8')):
            f.write(l);
            progress.update(len(l));
            file_hash.update(l);
        else:
            print(f"{RT.BLUE}SFTP END{RT.RESET}");
            f.close();
            split_data = l.split(CUSTOM_SEPARATOR);
            received_file_hash_uc = split_data[1].decode('utf-8');
            received_file_hash_c = split_data[2].decode('utf-8');
            if received_file_hash_c == file_hash.hexdigest():
                FileDecompressor("temp.tar.gz", [name]);
                with open(name, "rb") as filehandle:
                    #ucfilehash = hashlib.sha512();
                    ucfilehash = SHA512.new();
                    while True:
                        block = filehandle.read(buffer);
                        if not block:
                            break;
                        ucfilehash.update(block);
            filehandle.close();
            if received_file_hash_c == file_hash.hexdigest() and received_file_hash_uc == ucfilehash.hexdigest():
                print(f"{RT.GREEN}SFTP Checksum Matched!{RT.RESET}");
                break;
            else:
                print(f"{RT.RED}SFTP Checksum Did Not Match! File Is Corrupt{RT.RESET}");
                break;  

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
    message_encrypted = AESEncrypt(AESKey, message + CUSTOM_SEPARATOR + hashed_message.encode('utf-8'));
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
        return False;

def recieveEncryptedMessage(client_socket, AESKey):
    try:
        whole_message = receive_message(client_socket);
        decrypted_message = AESDecrypt(AESKey, whole_message["data"]);
        split_decrypted_message = decrypted_message.split(CUSTOM_SEPARATOR);
        plain_message = CUSTOM_SEPARATOR.join(split_decrypted_message[:-1]);
        mac = split_decrypted_message[len(split_decrypted_message) - 1];
        if HMACher(plain_message, AESKey, mac.decode('utf-8')):
            return {'header': whole_message["header"], 'data': plain_message, 'integrity': True};
        else:
            return {'header': whole_message["header"], 'data': plain_message, 'integrity': False};
    except Exception as e:
        return False;

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

def prompt(specialmessage=""):
    sys.stdout.write("<You> %s" %specialmessage);
    sys.stdout.flush();

HEADER_LENGTH = 10;

key_256 = b'';
random_generator = Random.new();
RSAKey = RSA.generate(4096, random_generator.read);
public = RSAKey.publickey().exportKey('DER');
private = RSAKey.exportKey('DER');
#public_hash = hashlib.sha512(public);
public_hash = SHA512.new(public);
public_hash_hexdigest = public_hash.hexdigest();

first_exchange_msg = public + CUSTOM_SEPARATOR + public_hash_hexdigest.encode('utf-8');
first_exchange_msg_hashobj = SHA512.new(first_exchange_msg);
signature = pss.new(RSAKey).sign(first_exchange_msg_hashobj);

#User's Public Key Debug
#print("Your Public Key: %s" %public); 
#User's Private Key Debug
#print("Your Private Key: %s" %private); 
#User's Public Hash Debug
#print("Your Public SHA512 Hash: %s" %public_hash_hexdigest); 

IP = str(input("Enter Server IP Address: "));
while(checkIP(IP) == False):
    IP = str(input("Enter Server IP Address: "));
Port = int(input("Enter Socket Port: "));
while(checkPort(Port) == False):
    Port = int(input("Enter Socket Port: "));
user_username = str(input("Username: "));

try:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
    print("Connecting to Server...");
    client_socket.connect((IP, Port));
    print(f"{RT.GREEN}Connected!{RT.RESET}");
    client_socket.setblocking(False);
except BaseException:
    print(f"{RT.RED}Error Occured During Connection Phase!{RT.RESET}");
    exit(1);

send_message(client_socket, first_exchange_msg + CUSTOM_SEPARATOR + signature, "byte");

while(True):
    fGet = receive_message(client_socket);
    if fGet == False:
        continue;
    else:
        break;
split = fGet["data"].split("(:0x0:)".encode('utf-8'));
toDecrypt = ''.encode('utf-8');
for i in range(0, len(split) - 1):
    toDecrypt += split[i];
serverPublic = split[len(split) - 1];
#Server's Public Key Debug
#print("Server's Public Key: %s" %serverPublic);
#Obsolete RSA Import Key
#decrypted = RSA.importKey(private).decrypt(toDecrypt);
intermediate = RSA.import_key(private);
decrypted = PKCS1_OAEP.new(intermediate).decrypt(toDecrypt);
#splittedDecrypt = decrypted.split(":0x0:".encode('utf-8'));
splittedDecrypt = decrypted.split(CUSTOM_SEPARATOR);
ttwoByte = splittedDecrypt[0];
session_hexdigest = splittedDecrypt[1];
serverPublicHash = splittedDecrypt[2];
#User's AES Key Hash Debug
#print("Client's AES Key In Hash: %s" %session_hexdigest);

#sess = hashlib.sha512(ttwoByte);
sess = SHA512.new(ttwoByte);
sess_hexdigest = sess.hexdigest();
#hashObj = hashlib.sha512(serverPublic);
hashObj = SHA512.new(serverPublic);
server_public_hash = hashObj.hexdigest();
print(f"{RT.YELLOW}Matching Server's Public Key & AES Key...{RT.RESET}");
if server_public_hash == serverPublicHash.decode('utf-8') and sess_hexdigest == session_hexdigest.decode('utf-8'):
    print(f"{RT.BLUE}Sending Encrypted Session Key...{RT.RESET}");
    #(serverPublic, ) = RSA.importKey(serverPublic).encrypt(ttwoByte, None);
    intermediate = RSA.import_key(serverPublic);
    serverPublic = PKCS1_OAEP.new(intermediate).encrypt(ttwoByte);
    send_message(client_socket, serverPublic, "byte");
    print(f"{RT.BLUE}Creating AES Key...{RT.RESET}");
    key_256 = ttwoByte;
    try:
        while(True):
            ready = receive_message(client_socket);
            if ready == False:
                continue;
            else:
                break;
    except Exception as e:
        print(f"{RT.RED}Error Occurred During Second Phase Of Handshake Sequence!{RT.RESET}");
        print(e);
        exit(1);
    ready_msg = AESDecrypt(key_256, ready["data"]);
    if ready_msg == "Ready".encode('utf-8'):
        print(f"{RT.GREEN}Client Is Ready To Communicate!{RT.RESET}");
    else:
        print(f"{RT.RED}Server's Public || Session Key Doesn't Match. Shutting Down Socket!{RT.RESET}");
        client_socket.close();
        exit(1);

sendEncryptedMessage(client_socket, user_username.encode('utf-8'), key_256);
#User's Username Hash(HMAC) Debug
#print(HMACher(user_username.encode('utf-8'), key_256));

prompt();

def sender_function(sock):
    while True:
        procedure_lock.wait();
        message = sys.stdin.readline();
        if not procedure_lock.isSet():
            procedure_lock.wait();
            continue;
        if message:
            if message == "?:0x0VoIPtestcmd\n":
                message = "VoIP Initiate".encode('utf-8');
                sendEncryptedMessage(sock, message, key_256);
                time.sleep(15);
                user_data = receive_message(sock);
                confirmation = recieveEncryptedMessage(sock, key_256)["data"];
                if confirmation == "VoIP Reject".encode('utf-8'):
                    print(f"{RT.BLUE}VoIP Rejected By End User!{RT.RESET}");
                    prompt();
                    continue;
                elif confirmation == "VoIP Accept".encode('utf-8'):
                    (playing_stream, recording_stream) = VoIPInitialize(1024, pyaudio.paInt16, 1, 20000);
                    voip_receive_thread = threading.Thread(target=receive_server_data, kwargs=dict(playing_stream=playing_stream, socket=sock, key=key_256)).start();
                    voip_handle_thread = threading.Thread(target=send_data_to_server, kwargs=dict(recording_stream=recording_stream, socket=sock, key=key_256, chunk_size=1024)).start();
                    prompt();
            elif message[:15] == "?:0x0FTPtestcmd":
                procedure_lock.clear();
                address = message[16:].strip();
                filesize_uc = os.path.getsize(address);
                FileCompressor("temp.tar.gz", [address]);
                filesize_c = os.path.getsize("temp.tar.gz");
                ftp_flag = ("SFTP Initiate" + ":0x0:" + address + ":0x0:" + str(filesize_uc) + ":0x0:" + str(filesize_c)).encode('utf-8');
                sendEncryptedMessage(sock, ftp_flag, key_256);
                file_hash = UploadFile(sock, address, key_256, filesize_uc, filesize_c, 16384);
                sendEncryptedMessage(sock, ("SFTP END" + ":0x0:" + file_hash[0].hexdigest() + ":0x0:" + file_hash[1].hexdigest()).encode('utf-8'), key_256);
                os.remove("temp.tar.gz");
                print("");
                prompt();
                procedure_lock.set();
            else:
                message = message.encode('utf-8');
                sendEncryptedMessage(sock, message, key_256);
                prompt();

def receiver_function(sock):
    while True:
        socket_list = [client_socket];
        read_sockets, write_socket, error_socket = select.select(socket_list, [], []);
        procedure_lock.wait();
        try:
            user_data = receive_message(sock);
            if user_data == False:
                print("Connection Closed By The Server");
                sys.exit();
            rusername = user_data["data"];
            decrypted_message_package = recieveEncryptedMessage(sock, key_256);
            decrypted_message = decrypted_message_package["data"];
            #split_decrypted_message = decrypted_message.split(":0x0:".encode('utf-8'));
            split_decrypted_message = decrypted_message.split(CUSTOM_SEPARATOR);
            if split_decrypted_message[0] == "SFTP Initiate".encode('utf-8'):
                procedure_lock.clear();
                print("Incoming File....");
                #prompt("Enter File Name: ");
                #name = sys.stdin.readline().strip();
                dfilename = split_decrypted_message[1].decode('utf-8').strip();
                filesize_uc = split_decrypted_message[2];
                filesize_c = split_decrypted_message[3];
                #if (name == "x0default0x"):
                DownloadFile(sock, dfilename, key_256, int(filesize_uc), int(filesize_c), 16384);
                #else:
                #    DownloadFile(sock, name, key_256, int(filesize_uc), int(filesize_c),16384);
                os.remove("temp.tar.gz");
                prompt();
                procedure_lock.set();
                continue;
            if decrypted_message == "VoIP Initiate".encode('utf-8'):
                print("VoIP Request");
                prompt("Accept?(Y,N) ");
                if (sys.stdin.readline().strip() == "Y"):
                    acceptance = "VoIP Accept".encode('utf-8');
                    sendEncryptedMessage(sock, acceptance, key_256);
                    (playing_stream, recording_stream) = VoIPInitialize(1024, pyaudio.paInt16, 1, 20000);
                    voip_receive_thread = threading.Thread(target=receive_server_data, kwargs=dict(playing_stream=playing_stream, socket=sock, key=key_256)).start();
                    voip_handle_thread = threading.Thread(target=send_data_to_server, kwargs=dict(recording_stream=recording_stream, socket=sock, key=key_256, chunk_size=1024)).start();
                    prompt();
                elif (sys.stdin.readline().strip() == "N"):
                    rejection = "VoIP Reject".encode('utf-8');
                    sendEncryptedMessage(sock, rejection, key_256);
                    prompt();
                    continue;
                else:
                    print(f"{RT.RED}Invalid Input. Quitting!{RT.RESET}");
                    sys.exit(1);
            if decrypted_message_package["integrity"]:
                print(f"{rusername.decode('utf-8')} > [I] {decrypted_message.decode('utf-8')}");
            else:
                print(f"{rusername.decode('utf-8')} > [C] {decrypted_message.decode('utf-8')}");
            prompt();
        except IOError as e:
            if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                print("Reading error: {}".format(str(e)));
                sys.exit();
        except Exception as e:
            print("General Error {}".format(str(e)));
            sys.exit();

procedure_lock = threading.Event();
procedure_lock.set();

Thread(target=sender_function, args=(client_socket,), daemon=True).start();
Thread(target=receiver_function, args=(client_socket,)).start();