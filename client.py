from Crypto.Cipher import AES
import socket;
import select;
import errno;
import sys;
import os;
import pyaudio;
import threading;
import time;
import re;
from Crypto import Random;
from Crypto.PublicKey import RSA;
from Crypto.Util import Counter;
import hashlib;
from termcolor import colored;

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

def UploadFile(socket, address, key, buffer=2048):
    f = open(address, 'rb');
    l = f.read(buffer);
    while (l):
        sendEncryptedMessage(socket, l, key);
        l = f.read(buffer);
    f.close();

def DownloadFile(socket, name, key, buffer=2048):
    f = open(name, 'wb');
    user_data = receive_message(socket);
    l = recieveEncryptedMessage(socket, key)["data"];
    while(l):
        if (l != "SFTP END".encode('utf-8')):
            f.write(l);
            user_data = receive_message(socket);
            l = recieveEncryptedMessage(socket, key)["data"];
        else:
            print(colored("SFTP END", "green"));
            break;
    f.close();

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
decrypted = RSA.importKey(private).decrypt(toDecrypt);
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
    (serverPublic, ) = RSA.importKey(serverPublic).encrypt(ttwoByte, None);
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
    read_sockets, write_socket, error_socket = select.select(socket_list, [], [], 0);
    for socks in read_sockets:
        if socks == client_socket:
            try:
                user_data = receive_message(client_socket);
                if user_data == False:
                    print("Connection Closed By The Server");
                    sys.exit();
                rusername = user_data["data"];
                decrypted_message = recieveEncryptedMessage(client_socket, key_256)["data"];
                if decrypted_message[:13] == "SFTP Initiate".encode('utf-8'):
                    print("Incoming File....");
                    prompt("Enter File Name: ");
                    name = sys.stdin.readline().strip();
                    if (name == "x0default0x"):
                        DownloadFile(socks, decrypted_message[13:].strip(), key_256, 2048);
                    else:
                        DownloadFile(socks, name, key_256, 2048);
                    prompt();
                    continue;
                if decrypted_message == "VoIP Initiate".encode('utf-8'):
                    print("VoIP Request");
                    prompt("Accept?(Y,N) ");
                    if (sys.stdin.readline().strip() == "Y"):
                        acceptance = "VoIP Accept".encode('utf-8');
                        sendEncryptedMessage(client_socket, acceptance, key_256);
                        voip_handle = VoIP(512, pyaudio.pa.paInt32, 1, 44100);
                        voip_receive_thread = threading.Thread(target=voip_handle.receive_server_data, args=(socks, )).start();
                        voip_handle_thread = threading.Thread(target=voip_handle.send_data_to_server, args=(socks, key_256)).start();
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
                    time.sleep(5);
                    user_data = receive_message(client_socket);
                    confirmation = recieveEncryptedMessage(client_socket, key_256)["data"];
                    if confirmation == "VoIP Reject".encode('utf-8'):
                        print(colored("VoIP Rejected By End User!", "orange"));
                        prompt();
                        continue;
                    elif confirmation == "VoIP Accept".encode('utf-8'):
                        voip_handle = VoIP(512, pyaudio.paInt32, 1, 44100);
                        voip_receive_thread = threading.Thread(target=voip_handle.receive_server_data, args=(socks, )).start();
                        voip_handle_thread = threading.Thread(target=voip_handle.send_data_to_server, args=(socks, key_256, )).start();
                elif message[:15] == "?:0x0FTPtestcmd":
                    ftp_flag = ("SFTP Initiate" + message[16:]).encode('utf-8');
                    sendEncryptedMessage(client_socket, ftp_flag, key_256);
                    address = message[16:];
                    UploadFile(client_socket, address.strip(), key_256, 2048);
                    sendEncryptedMessage(client_socket, "SFTP END".encode('utf-8'), key_256);
                    prompt();
                else:
                    message = message.encode('utf-8');
                    sendEncryptedMessage(client_socket, message, key_256);
                    prompt();
