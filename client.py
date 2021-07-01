from threading import Thread;
from rich.progress import (
    BarColumn,
    DownloadColumn,
    TextColumn,
    TransferSpeedColumn,
    TimeRemainingColumn,
    Progress,
    TaskID,
)
from Cryptodome.Cipher import AES, PKCS1_OAEP;
from Cryptodome.PublicKey import RSA;
from Cryptodome.Signature import pss;
from Cryptodome.Util import Counter;
from Cryptodome.Hash import HMAC, SHA512;
from Cryptodome import Random;
import sounddevice as sd;
import traceback;
import atexit;
import tarfile;
import socket;
import select;
import errno;
import sys;
import os;
import threading;
import time;
import re;

CUSTOM_SEPARATOR = b':0x0:';
logfilehandle = open("client_log.txt", "w");

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

class VoCom:
    def __init__(self, socket, key, read_chunk=None, block_chunk=0, audio_format=None, channels=None, rate=None):
        self._read_chunk = read_chunk;
        self._block_chunk = block_chunk;
        self._audio_format = audio_format;
        self._channels = channels;
        self._rate = rate;
        self._socket = socket;
        self._key = key;
        print(f"{RT.CYAN}Initializing Voice Streams{RT.RESET}");
        self.playing_stream = sd.RawOutputStream(samplerate=self._rate, blocksize=self._block_chunk, channels=self._channels, dtype=self._audio_format);
        self.recording_stream = sd.RawInputStream(samplerate=self._rate, blocksize=self._block_chunk, channels=self._channels, dtype=self._audio_format);
        self.playing_stream.start();
        self.recording_stream.start();
        receive_thread = threading.Thread(target=self.receive_server_data).start();
        print(f"{RT.CYAN}Voice Stream Active{RT.RESET}");
        self.send_data_to_server();
    
    def receive_server_data(self):
        while True:
            try:
                user_data = receive_message(self._socket);
                message_stream = recieveEncryptedMessage(self._socket, self._key)["data"];
                self.playing_stream.write(message_stream);
            except Exception as e:
                pass;

    def send_data_to_server(self):
        while True:
            try:
                (data, overflow) = self.recording_stream.read(self._read_chunk);
                sendEncryptedMessage(self._socket, data[:], self._key, False);
            except Exception as e:
                pass;

def FileCompressor(tar_file, files):
    with tarfile.open(tar_file, "w:gz") as tar:
        for file in files:
            with Progress() as progress:
                task = progress.add_task(f"[yellow]Compressing {file}");
                while not progress.finished:
                    tar.add(file);
                    progress.update(task, advance=100);

def FileDecompressor(tar_file, file_name):
    with tarfile.open(tar_file, "r:gz") as tar:
        file_name = tar.getmembers()
        for file in file_name:
            with Progress() as progress:
                task = progress.add_task(f"[yellow]Decompressing {file}", start=False);
                tar.extract(file);

def UploadFile(socket, address, key, size_uncompressed, size_compressed, buffer=2048):
    with open("temp.tar.gz", "rb") as f:
        file_hash_uc = SHA512.new();
        file_hash_c = SHA512.new();
        for address_singular in address:
            with open(address_singular, "rb") as filehandle:
                while True:
                    block = filehandle.read(buffer);
                    if not block:
                        break;
                    file_hash_uc.update(block);
        with Progress(TextColumn("[bold blue]{task.description}", justify="right"),
                    BarColumn(bar_width=None),
                    "[progress.percentage]{task.percentage:>3.1f}%",
                    "•",
                    DownloadColumn(),
                    "•",
                    TransferSpeedColumn(),
                    "•",
                    TimeRemainingColumn(),) as progress:
            task = progress.add_task("Uploading file(s)", total=size_compressed);
            while not progress.finished:
                l = f.read(buffer);
                if not l:
                    break;
                select.select([], [socket], []);
                sendEncryptedMessage(socket, l, key);
                progress.update(task, advance=len(l));
                file_hash_c.update(l);
    return (file_hash_uc, file_hash_c);

def DownloadFile(socket, name, key, size_uncompressed, size_compressed, buffer=2048):
    with open("temp.tar.gz", "wb") as f:
        file_hash = SHA512.new();
        with Progress(TextColumn("[bold blue]{task.description}", justify="right"),
                    BarColumn(bar_width=None),
                    "[progress.percentage]{task.percentage:>3.1f}%",
                    "•",
                    DownloadColumn(),
                    "•",
                    TransferSpeedColumn(),
                    "•",
                    TimeRemainingColumn(),) as progress:
            task = progress.add_task(f"Downloading file(s)", total=size_compressed);
            while not progress.finished:
                select.select([client_socket], [], []);
                user_data = receive_message(socket);
                l = recieveEncryptedMessage(socket, key)["data"];
                f.write(l);
                progress.update(task, advance=len(l));
                file_hash.update(l);
        user_data = receive_message(socket);
        l = recieveEncryptedMessage(socket, key)["data"];
        if l[:8] == "SFTP END".encode('utf-8'):
            print(f"{RT.BLUE}SFTP END{RT.RESET}");
        else:
            print(f"{RT.RED}SFTP Did Not End! Retry File Transfer.{RT.End}");
            return;
        split_data = l.split(CUSTOM_SEPARATOR);
        received_file_hash_uc = split_data[1].decode('utf-8');
        received_file_hash_c = split_data[2].decode('utf-8');
        if received_file_hash_c == file_hash.hexdigest():
            FileDecompressor("temp.tar.gz", name);
            ucfilehash = SHA512.new();
            for name_singular in name:
                with open(name_singular, "rb") as filehandle:
                    while True:
                        block = filehandle.read(buffer);
                        if not block:
                            break;
                        ucfilehash.update(block);
        if received_file_hash_c == file_hash.hexdigest() and received_file_hash_uc == ucfilehash.hexdigest():
            print(f"{RT.GREEN}SFTP Checksum Matched!{RT.RESET}");
        else:
            print(f"{RT.RED}SFTP Checksum Did Not Match! File Is Corrupt{RT.RESET}");

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

def sendEncryptedMessage(client_socket, message, AESKey, Hash=True):
    if Hash:    
        hashed_message = HMACher(message, AESKey); 
    else:
        hashed_message = "";
    message_encrypted = AESEncrypt(AESKey, message + CUSTOM_SEPARATOR + hashed_message.encode('utf-8'));
    send_message(client_socket, message_encrypted, type="byte");
    #message_sender_header = f"{len(message_encrypted):<{HEADER_LENGTH}}".encode('utf-8');
    #client_socket.send(message_sender_header + message_encrypted);

def recv_exact(socket, size):
    buflist = [];
    while size:
        while(True):
            try:
                buf = socket.recv(size);
                break;
            except IOError as e:
                if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                    sys.exit();
                else:
                    continue;
        if not buf:
            logfilehandle.write("recv_exact(): Failed prematurely\n");
            return False;
        buflist.append(buf);
        size -= len(buf);
    return b''.join(buflist);

def receive_message(client_socket):
    try:
        #message_header = client_socket.recv(HEADER_LENGTH);
        message_header = recv_exact(client_socket, HEADER_LENGTH);
        if not len(message_header):
            logfilehandle.write("receive_message(): Failed prematurely\n");
            return False;
        message_length = int(message_header.decode('utf-8').strip());
        #return {'header': message_header, 'data': client_socket.recv(message_length)};
        return {'header': message_header, 'data': recv_exact(client_socket, message_length)};
    except IOError as e:
        if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
            print("Reading error: {}".format(str(e)));
            logfilehandle.write("receive_message(): " + str(e) + "\n");
            logfilehandle.close();
            sys.exit();
        else:
            logfilehandle.write("Stack: " + traceback.format_exc() + "\n");
            raise;
    except Exception as e:
        logfilehandle.write("receive_message(): " + str(e) + "\n");
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
        logfilehandle.write("recieveEncryptedMessage(): " + str(e) + "\n");
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
    logfilehandle.write("Socket Connection Error: " + str(e) + "\n");
    logfilehandle.close();
    exit(1);

send_message(client_socket, first_exchange_msg + CUSTOM_SEPARATOR + signature, "byte");

"""while(True):
    fGet = receive_message(client_socket);
    if fGet == False:
        continue;
    else:
        break;"""
while(True):
    try:
        fGet = receive_message(client_socket);
    except:
        continue;
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
        """while(True):
            ready = receive_message(client_socket);
            if ready == False:
                continue;
            else:
                break;"""
        while(True):
            try:
                ready = receive_message(client_socket);
            except:
                continue;
            break;
    except Exception as e:
        print(f"{RT.RED}Error Occurred During Second Phase Of Handshake Sequence!{RT.RESET}");
        logfilehandle.write("Handshake Error: " + str(e) + "\n");
        logfilehandle.close();
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
            if message == "?:0x0VoCom\n":
                procedure_lock.clear();
                sendEncryptedMessage(sock, "VoCom Initiate".encode('utf-8'), key_256);
                VoiceCommunication_obj = VoCom(sock, key_256, read_chunk=5120);
            elif message[:12] == "?:0x0SFTPcmd":
                procedure_lock.clear();
                addresses = message.split(",");
                #address = message[16:].strip();
                filesize_uc = 0;
                addresses_string = "";
                for i in range(1, len(addresses)):
                    addresses[i] = addresses[i].strip();
                    filesize_uc += os.path.getsize(addresses[i]);
                    addresses_string += addresses[i] + ",";
                #filesize_uc = os.path.getsize(address);
                FileCompressor("temp.tar.gz", addresses[1:]);
                #FileCompressor("temp.tar.gz", [address]);
                filesize_c = os.path.getsize("temp.tar.gz");
                ftp_flag = ("SFTP Initiate" + ":0x0:" + addresses_string + ":0x0:" + str(filesize_uc) + ":0x0:" + str(filesize_c)).encode('utf-8');
                #ftp_flag = ("SFTP Initiate" + ":0x0:" + address + ":0x0:" + str(filesize_uc) + ":0x0:" + str(filesize_c)).encode('utf-8');
                sendEncryptedMessage(sock, ftp_flag, key_256);
                file_hash = UploadFile(sock, addresses[1:], key_256, filesize_uc, filesize_c, 16384);
                #file_hash = UploadFile(sock, address, key_256, filesize_uc, filesize_c, 16384);
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
                print("Incoming File(s)....");
                dfilename_split = split_decrypted_message[1].decode('utf-8').strip().split(",");
                dfilename = dfilename_split[:len(dfilename_split) - 1];
                #dfilename = split_decrypted_message[1].decode('utf-8').strip();
                filesize_uc = split_decrypted_message[2];
                filesize_c = split_decrypted_message[3];
                DownloadFile(sock, dfilename, key_256, int(filesize_uc), int(filesize_c), 16384);
                os.remove("temp.tar.gz");
                prompt();
                procedure_lock.set();
                continue;
            if decrypted_message_package["integrity"]:
                print(f"{rusername.decode('utf-8')} > [I] {decrypted_message.decode('utf-8')}");
            else:
                print(f"{rusername.decode('utf-8')} > [C] {decrypted_message.decode('utf-8')}");
            prompt();
        except IOError as e:
            if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                print("Reading error: {}".format(str(e)));
                logfilehandle.write("IOError: " + str(e) + "\n");
                logfilehandle.close();
                sys.exit();
        except Exception as e:
            print("General Error {}".format(str(e)));
            logfilehandle.write("General Error: " + str(e) + "\n");
            logfilehandle.close();
            sys.exit();

procedure_lock = threading.Event();
procedure_lock.set();

Thread(target=sender_function, args=(client_socket,), daemon=True).start();
Thread(target=receiver_function, args=(client_socket,)).start();

def exit_cleanup():
    print(f"{RT.RED}Exiting Program{RT.RESET}");
    logfilehandle.close();
    try:
        os.remove("temp.tar.gz");
    except:
        pass;

atexit.register(exit_cleanup);