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
from Cryptodome.Cipher import ChaCha20_Poly1305, PKCS1_OAEP;
from Cryptodome.PublicKey import RSA;
from Cryptodome.Signature import pss;
from Cryptodome.Hash import SHA512;
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
CHACHA_HEADER = b"header";
HEADER_LENGTH = 10;
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
        if l[:8] == encode("SFTP END"):
            print(f"{RT.BLUE}SFTP END{RT.RESET}");
        else:
            print(f"{RT.RED}SFTP Did Not End! Retry File Transfer.{RT.RESET}");
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
        message_header = recv_exact(client_socket, HEADER_LENGTH);
        if not len(message_header):
            logfilehandle.write("receive_message(): Failed prematurely\n");
            return False;
        message_length = int(message_header.decode('utf-8').strip());
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

def recieveEncryptedMessage(client_socket, Chakey):
    try:
        whole_message = receive_message(client_socket);
        message_split = whole_message["data"].split(CUSTOM_SEPARATOR);
        decrypted_message = ChaChaDecrypt(Chakey, message_split[1], CHACHA_HEADER, message_split[0]);
        return {'header': whole_message["header"], 'data': decrypted_message, 'integrity': True};
    except ValueError as ve:
        return {'header': whole_message["header"], 'data': decrypted_message, 'integrity': False};
    except Exception as e:
        logfilehandle.write("recieveEncryptedMessage(): " + str(e) + "\n");
        return False;

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

def prompt(specialmessage=""):
    sys.stdout.write("<You> %s" %specialmessage);
    sys.stdout.flush();

key_256 = b'';
random_generator = Random.new();
RSAKey = RSA.generate(4096, random_generator.read);
public = RSAKey.publickey().exportKey('DER');
private = RSAKey.exportKey('DER');
public_hash = SHA512.new(public);
public_hash_hexdigest = public_hash.hexdigest();
first_exchange_msg = public + CUSTOM_SEPARATOR + encode(public_hash_hexdigest);
first_exchange_msg_hashobj = SHA512.new(first_exchange_msg);
signature = pss.new(RSAKey).sign(first_exchange_msg_hashobj);

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
except BaseException as e:
    print(f"{RT.RED}Error Occured During Connection Phase!{RT.RESET}");
    logfilehandle.write("Socket Connection Error: " + str(e) + "\n");
    logfilehandle.close();
    exit(1);

send_message(client_socket, first_exchange_msg + CUSTOM_SEPARATOR + signature, "byte");

while(True):
    try:
        fGet = receive_message(client_socket);
    except:
        continue;
    break;
split = fGet["data"].split(encode("(:0x0:)"));
toDecrypt = encode('');
for i in range(0, len(split) - 1):
    toDecrypt += split[i];
serverPublic = split[len(split) - 1];
intermediate = RSA.import_key(private);
decrypted = PKCS1_OAEP.new(intermediate).decrypt(toDecrypt);
splittedDecrypt = decrypted.split(CUSTOM_SEPARATOR);
ttwoByte = splittedDecrypt[0];
session_hexdigest = splittedDecrypt[1];
serverPublicHash = splittedDecrypt[2];
sess = SHA512.new(ttwoByte);
sess_hexdigest = sess.hexdigest();
hashObj = SHA512.new(serverPublic);
server_public_hash = hashObj.hexdigest();

print(f"{RT.YELLOW}Matching Server's Public Key & ChaCha Key...{RT.RESET}");
if server_public_hash == serverPublicHash.decode('utf-8') and sess_hexdigest == session_hexdigest.decode('utf-8'):
    print(f"{RT.BLUE}Sending Encrypted Session Key...{RT.RESET}");
    intermediate = RSA.import_key(serverPublic);
    serverPublic = PKCS1_OAEP.new(intermediate).encrypt(ttwoByte);
    send_message(client_socket, serverPublic, "byte");
    print(f"{RT.BLUE}Creating ChaCha Key...{RT.RESET}");
    key_256 = ttwoByte;
    try:
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
    splitreceived = ready["data"].split(CUSTOM_SEPARATOR);
    ready_msg = ChaChaDecrypt(key_256, splitreceived[1], CHACHA_HEADER, splitreceived[0]);
    if ready_msg == encode("Ready"):
        print(f"{RT.GREEN}Client Is Ready To Communicate!{RT.RESET}");
    else:
        print(f"{RT.RED}Server's Public || Session Key Doesn't Match. Shutting Down Socket!{RT.RESET}");
        client_socket.close();
        exit(1);

sendEncryptedMessage(client_socket, encode(user_username), key_256);

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
                sendEncryptedMessage(sock, encode("VoCom Initiate"), key_256);
                VoiceCommunication_obj = VoCom(sock, key_256, read_chunk=5120);
            elif message[:12] == "?:0x0SFTPcmd":
                procedure_lock.clear();
                addresses = message.split(",");
                filesize_uc = 0;
                addresses_string = "";
                for i in range(1, len(addresses)):
                    addresses[i] = addresses[i].strip();
                    filesize_uc += os.path.getsize(addresses[i]);
                    addresses_string += addresses[i] + ",";
                FileCompressor("temp.tar.gz", addresses[1:]);
                filesize_c = os.path.getsize("temp.tar.gz");
                ftp_flag = encode("SFTP Initiate") + CUSTOM_SEPARATOR + encode(addresses_string) + CUSTOM_SEPARATOR + encode(str(filesize_uc)) + CUSTOM_SEPARATOR + encode(str(filesize_c));
                sendEncryptedMessage(sock, ftp_flag, key_256);
                file_hash = UploadFile(sock, addresses[1:], key_256, filesize_uc, filesize_c, 16384);
                sendEncryptedMessage(sock, encode("SFTP END") + CUSTOM_SEPARATOR + encode(file_hash[0].hexdigest()) + CUSTOM_SEPARATOR + encode(file_hash[1].hexdigest()), key_256);
                os.remove("temp.tar.gz");
                print("");
                prompt();
                procedure_lock.set();
            else:
                message = encode(message);
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
            split_decrypted_message = decrypted_message.split(CUSTOM_SEPARATOR);
            if split_decrypted_message[0] == encode("SFTP Initiate"):
                procedure_lock.clear();
                print("Incoming File(s)....");
                dfilename_split = split_decrypted_message[1].decode('utf-8').strip().split(",");
                dfilename = dfilename_split[:len(dfilename_split) - 1];
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