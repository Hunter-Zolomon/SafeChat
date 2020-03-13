from Crypto.Cipher import AES;
from Crypto.Cipher import PKCS1_OAEP;
from Crypto.PublicKey import RSA;
from Crypto.Util import Counter;
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

"""
class VoIP:
    _chunk_size = 1024;
    _audio_format = pyaudio.paInt32;
    _channels = 1;
    _rate = 20000;
    def __init__(self, chunk_size, audio_format, channels, rate):
        super().__init__();
        self._chunk_size = chunk_size;
        self._audio_format = audio_format;
        self._channels = channels;
        self._rate = rate;
        self.p = pyaudio.PyAudio();
        self.playing_stream = self.p.open(format=audio_format, channels=channels, rate=rate, output=True, frames_per_buffer=chunk_size);
        self.recording_stream = self.p.open(format=audio_format, channels=channels, rate=rate, input=True, frames_per_buffer=chunk_size);

    def receive_server_data(self, socket, key):
        while True:
            try:
                user_data = receive_message(socket);
                message_stream = recieveEncryptedMessage(socket, key)["data"];
                self.playing_stream.write(message_stream);
            except:
                pass;
        
    def send_data_to_server(self, socket, key):
        while True:
            try:
                data = self.recording_stream.read(self._chunk_size);
                sendEncryptedMessage(socket, data, key);
            except Exception as e:
                pass;
"""
def VoIPInitialize(chunk_size, audio_format, channels, rate):
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

def UploadFile(socket, address, key, filesize, buffer=2048):
    FileCompressor("temp.tar.gz", [address]);
    #f = open(address, 'rb');
    f = open("temp.tar.gz", "rb");
    file_hash = hashlib.sha512();
    progress = tqdm.tqdm(range(filesize), f"Sending {address}", unit="B", unit_scale=True, unit_divisor=1024);
    """l = f.read(buffer);
    while (l):
        time.sleep(0.01);
        sendEncryptedMessage(socket, l, key);
        l = f.read(buffer);
    f.close();"""
    for _ in progress:
        l = f.read(buffer);
        if not l:
            break;
        sendEncryptedMessage(socket, l, key);
        progress.update(len(l));
        file_hash.update(l);
    f.close();
    return file_hash;

def DownloadFile(socket, name, key, filesize, buffer=2048):
    #f = open(name, 'wb');
    f = open("temp.tar.gz", "wb");
    file_hash = hashlib.sha512();
    progress = tqdm.tqdm(range(filesize), f"Receiving {name}", unit="B", unit_scale=True, unit_divisor=1024);
    """user_data = receive_message(socket);
    l = recieveEncryptedMessage(socket, key)["data"];
    while(l):
        if (l != "SFTP END".encode('utf-8')):
            f.write(l);
            time.sleep(0.02);
            user_data = receive_message(socket);
            l = recieveEncryptedMessage(socket, key)["data"];
        else:
            print(colored("SFTP END", "green"));
            break;
    f.close();"""
    for _ in progress:
        user_data = receive_message(socket);
        l = recieveEncryptedMessage(socket, key)["data"];
        if (l[:8] != "SFTP END".encode('utf-8')):
            f.write(l);
            progress.update(len(l));
            file_hash.update(l);
        else:
            print(colored("SFTP END", "blue"));
            received_file_hash = l[13:].decode('utf-8');
            if received_file_hash == file_hash.hexdigest():
                print(colored("SFTP Checksum Matched!", "green"));
                break;
            else:
                print(colored("SFTP Checksum Did Not Match! File Is Corrupt", "red"));
                break;  
    f.close();
    FileDecompressor("temp.tar.gz", [name]);

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
    message_encrypted = AESEncrypt(AESKey, message);
    message_sender_header = f"{len(message_encrypted):<{HEADER_LENGTH}}".encode('utf-8');
    client_socket.send(message_sender_header + message_encrypted);

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
        message_header = client_socket.recv(HEADER_LENGTH);
        if not len(message_header):
            return False;
        message_length = int(message_header.decode('utf-8').strip());
        encrypted_message = client_socket.recv(message_length);
        decrypted_message = AESDecrypt(AESKey, encrypted_message);
        return {'header': message_header, 'data': decrypted_message};
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
FLAG_READY = "Ready";
FLAG_QUIT = "Quit";

hasher = hashlib.sha512();

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
    if ready_msg == FLAG_READY.encode('utf-8'):
        print(colored("Client Is Ready To Communicate!", "green"));
    else:
        print(colored("Server's Public || Session Key Doesn't Match. Shutting Down Socket!", "red"));
        client_socket.close();
        exit(1);

sendEncryptedMessage(client_socket, user_username.encode('utf-8'), key_256);

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
                decrypted_message = recieveEncryptedMessage(client_socket, key_256)["data"];
                split_decrypted_message = decrypted_message.split(":0x0:".encode('utf-8'));
                if split_decrypted_message[0] == "SFTP Initiate".encode('utf-8'):
                    print("Incoming File....");
                    prompt("Enter File Name: ");
                    name = sys.stdin.readline().strip();
                    if (name == "x0default0x"):
                        #DownloadFile(socks, decrypted_message[13:].strip(), key_256, 2048);
                        DownloadFile(socks, split_decrypted_message[1].decode('utf-8').strip(), key_256, split_decrypted_message[2], 2048);
                    else:
                        DownloadFile(socks, name, key_256, int(split_decrypted_message[2].decode('utf-8')), 2048);
                    os.remove("temp.tar.gz");
                    prompt();
                    continue;
                if decrypted_message == "VoIP Initiate".encode('utf-8'):
                    print("VoIP Request");
                    prompt("Accept?(Y,N) ");
                    if (sys.stdin.readline().strip() == "Y"):
                        acceptance = "VoIP Accept".encode('utf-8');
                        sendEncryptedMessage(client_socket, acceptance, key_256);
                        #voip_handle = VoIP(512, pyaudio.pa.paInt32, 1, 44100);
                        (playing_stream, recording_stream) = VoIPInitialize(512, pyaudio.paInt32, 1, 44100);
                        #voip_receive_thread = threading.Thread(target=voip_handle.receive_server_data, args=(socks, )).start();
                        #voip_handle_thread = threading.Thread(target=voip_handle.send_data_to_server, args=(socks, key_256)).start();
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
                print(f"{rusername.decode('utf-8')} > {decrypted_message.decode('utf-8')}");
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
                        #voip_handle = VoIP(512, pyaudio.paInt32, 1, 44100);
                        (playing_stream, recording_stream) = VoIPInitialize(512, pyaudio.paInt32, 1, 44100);
                        #voip_receive_thread = threading.Thread(target=voip_handle.receive_server_data, kwargs=dict(socket=socks, key=key_256)).start();
                        #voip_handle_thread = threading.Thread(target=voip_handle.send_data_to_server, kwargs=dict(socket=socks, key=key_256)).start();
                        voip_receive_thread = threading.Thread(target=receive_server_data, kwargs=dict(playing_stream=playing_stream, socket=socks, key=key_256)).start();
                        voip_handle_thread = threading.Thread(target=send_data_to_server, kwargs=dict(recording_stream=recording_stream, socket=socks, key=key_256, chunk_size=512)).start();
                elif message[:15] == "?:0x0FTPtestcmd":
                    address = message[16:].strip();
                    filesize = os.path.getsize(address);
                    ftp_flag = ("SFTP Initiate" + ":0x0:" + address + ":0x0:" + str(filesize)).encode('utf-8');
                    sendEncryptedMessage(client_socket, ftp_flag, key_256);
                    file_hash = UploadFile(client_socket, address, key_256, filesize, 2048);
                    sendEncryptedMessage(client_socket, ("SFTP END" + ":0x0:" + file_hash.hexdigest()).encode('utf-8'), key_256);
                    os.remove("temp.tar.gz");
                    print("");
                    prompt();
                else:
                    message = message.encode('utf-8');
                    sendEncryptedMessage(client_socket, message, key_256);
                    prompt();