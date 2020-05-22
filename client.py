from Crypto.Cipher import AES, PKCS1_OAEP;
from Crypto.PublicKey import RSA;
from Crypto.Util import Counter;
from Crypto.Hash import HMAC, SHA512;
from Crypto import Random;
from termcolor import colored;
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
import hashlib;

CUSTOM_SEPARATOR = b':0x0:';

def VoIPInitialize(chunk_size=1024, audio_format=pyaudio.paInt32, channels=1, rate=20000):
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
        except:
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
    file_hash_uc = hashlib.sha512();
    file_hash_c = hashlib.sha512();
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
        sendEncryptedMessage(socket, l, key);
        progress.update(len(l));
        file_hash_c.update(l);
    f.close();
    return (file_hash_uc, file_hash_c);

def DownloadFile(socket, name, key, size_uncompressed, size_compressed, buffer=2048):
    #f = open(name, 'wb');
    f = open("temp.tar.gz", "wb");
    file_hash = hashlib.sha512();
    progress = tqdm.tqdm(range(size_compressed), f"Receiving {name}", unit="B", unit_scale=True, unit_divisor=1024);
    for _ in progress:
        user_data = receive_message(socket);
        l = recieveEncryptedMessage(socket, key)["data"];
        if (l[:8] != "SFTP END".encode('utf-8')):
            f.write(l);
            progress.update(len(l));
            file_hash.update(l);
        else:
            print(colored("SFTP END", "blue"));
            f.close();
            split_data = l.split(":0x0:");
            received_file_hash_uc = split_data[1].decode('utf-8');
            received_file_hash_c = split_data[2].decode('utf-8');
            if received_file_hash_c == file_hash.hexdigest():
                FileDecompressor("temp.tar.gz", [name]);
                with open(name, "rb") as filehandle:
                    ucfilehash = hashlib.sha512();
                    while True:
                        block = filehandle.read(buffer);
                        if not block:
                            break;
                        ucfilehash.update(block);
            filehandle.close();
            if received_file_hash_c == file_hash.hexdigest() and received_file_hash_uc == ucfilehash.hexdigest():
                print(colored("SFTP Checksum Matched!", "green"));
                break;
            else:
                print(colored("SFTP Checksum Did Not Match! File Is Corrupt", "red"));
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
public = RSAKey.publickey().exportKey();
private = RSAKey.exportKey();
public_hash = hashlib.sha512(public);
public_hash_hexdigest = public_hash.hexdigest();

print("Your Public Key: %s" %public);
print("Your Private Key: %s" %private);
print("Your Public SHA512 Hash: %s" %public_hash_hexdigest);

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
    print(colored("Connected!", "green"));
    client_socket.setblocking(False);
except BaseException:
    print(colored("Error Occured During Connection Phase!", "red"));
    exit(1);

send_message(client_socket, public + ":".encode('utf-8') + public_hash_hexdigest.encode('utf-8'), "byte");

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
print("Server's Public Key: %s" %serverPublic);
#decrypted = RSA.importKey(private).decrypt(toDecrypt);
intermediate = RSA.importKey(private);
decrypted = PKCS1_OAEP.new(intermediate).decrypt(toDecrypt);
splittedDecrypt = decrypted.split(":0x0:".encode('utf-8'));
ttwoByte = splittedDecrypt[0];
session_hexdigest = splittedDecrypt[1];
serverPublicHash = splittedDecrypt[2];
print("Client's AES Key In Hash: %s" %session_hexdigest);
sess = hashlib.sha512(ttwoByte);
sess_hexdigest = sess.hexdigest();
hashObj = hashlib.sha512(serverPublic);
server_public_hash = hashObj.hexdigest();
print(colored("Matching Server's Public Key & AES Key...", "yellow"));
if server_public_hash == serverPublicHash.decode('utf-8') and sess_hexdigest == session_hexdigest.decode('utf-8'):
    print(colored("Sending Encrypted Session Key...", "blue"));
    #(serverPublic, ) = RSA.importKey(serverPublic).encrypt(ttwoByte, None);
    intermediate = RSA.importKey(serverPublic);
    serverPublic = PKCS1_OAEP.new(intermediate).encrypt(ttwoByte);
    send_message(client_socket, serverPublic, "byte");
    print(colored("Creating AES Key...", "blue"));
    key_256 = ttwoByte;
    try:
        while(True):
            ready = receive_message(client_socket);
            if ready == False:
                continue;
            else:
                break;
    except Exception as e:
        print(colored("Error Occurred During Second Phase Of Handshake Sequence!", "red"));
        print(e);
        exit(1);
    ready_msg = AESDecrypt(key_256, ready["data"]);
    if ready_msg == "Ready".encode('utf-8'):
        print(colored("Client Is Ready To Communicate!", "green"));
    else:
        print(colored("Server's Public || Session Key Doesn't Match. Shutting Down Socket!", "red"));
        client_socket.close();
        exit(1);

sendEncryptedMessage(client_socket, user_username.encode('utf-8'), key_256);
print(HMACher(user_username.encode('utf-8'), key_256));

prompt();

while(True):
    socket_list = [sys.stdin, client_socket];
    read_sockets, write_socket, error_socket = select.select(socket_list, [], []);
    for socks in read_sockets:
        if socks == client_socket:
            try:
                user_data = receive_message(client_socket);
                if user_data == False:
                    print("Connection Closed By The Server");
                    sys.exit();
                rusername = user_data["data"];
                decrypted_message_package = recieveEncryptedMessage(client_socket, key_256);
                decrypted_message = decrypted_message_package["data"];
                split_decrypted_message = decrypted_message.split(":0x0:".encode('utf-8'));
                if split_decrypted_message[0] == "SFTP Initiate".encode('utf-8'):
                    print("Incoming File....");
                    prompt("Enter File Name: ");
                    name = sys.stdin.readline().strip();
                    dfilename = split_decrypted_message[1].decode('utf-8').strip();
                    filesize_uc = split_decrypted_message[2];
                    filesize_c = split_decrypted_message[3];
                    if (name == "x0default0x"):
                        DownloadFile(socks, dfilename, key_256, int(filesize_uc), int(filesize_c), 16384);
                    else:
                        DownloadFile(socks, name, key_256, int(filesize_uc), int(filesize_c),16384);
                    os.remove("temp.tar.gz");
                    prompt();
                    continue;
                if decrypted_message == "VoIP Initiate".encode('utf-8'):
                    print("VoIP Request");
                    prompt("Accept?(Y,N) ");
                    if (sys.stdin.readline().strip() == "Y"):
                        acceptance = "VoIP Accept".encode('utf-8');
                        sendEncryptedMessage(client_socket, acceptance, key_256);
                        (playing_stream, recording_stream) = VoIPInitialize(512, pyaudio.paInt32, 1, 44100);
                        voip_receive_thread = threading.Thread(target=receive_server_data, kwargs=dict(playing_stream=playing_stream, socket=socks, key=key_256)).start();
                        voip_handle_thread = threading.Thread(target=send_data_to_server, kwargs=dict(recording_stream=recording_stream, socket=socks, key=key_256, chunk_size=512)).start();
                    elif (sys.stdin.readline().strip() == "N"):
                        rejection = "VoIP Reject".encode('utf-8');
                        sendEncryptedMessage(client_socket, rejection, key_256);
                        prompt();
                        continue;
                    else:
                        print(colored("Invalid Input. Quitting!", "red"));
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
                continue;
            except Exception as e:
                print("General Error {}".format(str(e)));
                sys.exit();
        else:
            message = sys.stdin.readline();
            if message:
                if message == "?:0x0VoIPtestcmd\n":
                    message = "VoIP Initiate".encode('utf-8');
                    sendEncryptedMessage(client_socket, message, key_256);
                    time.sleep(15);
                    user_data = receive_message(client_socket);
                    confirmation = recieveEncryptedMessage(client_socket, key_256)["data"];
                    if confirmation == "VoIP Reject".encode('utf-8'):
                        print(colored("VoIP Rejected By End User!", "blue"));
                        prompt();
                        continue;
                    elif confirmation == "VoIP Accept".encode('utf-8'):
                        (playing_stream, recording_stream) = VoIPInitialize(512, pyaudio.paInt32, 1, 44100);
                        voip_receive_thread = threading.Thread(target=receive_server_data, kwargs=dict(playing_stream=playing_stream, socket=socks, key=key_256)).start();
                        voip_handle_thread = threading.Thread(target=send_data_to_server, kwargs=dict(recording_stream=recording_stream, socket=socks, key=key_256, chunk_size=512)).start();
                elif message[:15] == "?:0x0FTPtestcmd":
                    address = message[16:].strip();
                    filesize_uc = os.path.getsize(address);
                    FileCompressor("temp.tar.gz", [address]);
                    filesize_c = os.path.getsize("temp.tar.gz");
                    ftp_flag = ("SFTP Initiate" + ":0x0:" + address + ":0x0:" + str(filesize_uc) + ":0x0:" + str(filesize_c)).encode('utf-8');
                    sendEncryptedMessage(client_socket, ftp_flag, key_256);
                    file_hash = UploadFile(client_socket, address, key_256, filesize_uc, filesize_c, 16384);
                    sendEncryptedMessage(client_socket, ("SFTP END" + ":0x0:" + file_hash[0].hexdigest() + ":0x0:" + file_hash[1].hexdigest()).encode('utf-8'), key_256);
                    os.remove("temp.tar.gz");
                    print("");
                    prompt();
                else:
                    message = message.encode('utf-8');
                    sendEncryptedMessage(client_socket, message, key_256);
                    prompt();
