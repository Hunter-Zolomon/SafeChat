from cryptography.hazmat.primitives.serialization import load_der_private_key, load_der_public_key;
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305;
from cryptography.hazmat.primitives.serialization import PublicFormat;
from cryptography.hazmat.primitives.serialization import Encoding;
from cryptography.exceptions import InvalidTag, InvalidKey;
from cryptography.hazmat.primitives.asymmetric import ec;
from cryptography.hazmat.primitives.kdf.hkdf import HKDF;
from cryptography.hazmat.primitives import hashes;
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
import sounddevice as sd;
import threading;
import traceback;
import tarfile;
import atexit;
import socket;
import select;
import errno;
import time;
import sys;
import os;
import re;

CUSTOM_SEPARATOR = b':0x0:';
CHACHA_HEADER = b'header';
HEADER_LENGTH = 10;
derived_key = b'';
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
        file_hash_uc = hashes.Hash(hashes.SHA3_512());
        file_hash_c = hashes.Hash(hashes.SHA3_512());
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
        file_hash = hashes.Hash(hashes.SHA3_512());
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
        received_file_hash_uc = split_data[1];
        received_file_hash_c = split_data[2];
        if received_file_hash_c == file_hash.finalize():
            FileDecompressor("temp.tar.gz", name);
            ucfilehash = hashes.Hash(hashes.SHA3_512());
            for name_singular in name:
                with open(name_singular, "rb") as filehandle:
                    while True:
                        block = filehandle.read(buffer);
                        if not block:
                            break;
                        ucfilehash.update(block);
        if received_file_hash_c == file_hash.finalize() and received_file_hash_uc == ucfilehash.finalize():
            print(f"{RT.GREEN}SFTP Checksum Matched!{RT.RESET}");
        else:
            print(f"{RT.RED}SFTP Checksum Did Not Match! File Is Corrupt{RT.RESET}");

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

def sendEncryptedMessage(client_socket, message, chaKey, Hash=True):
    message_encrypted = ChaChaEncrypt(chaKey, CHACHA_HEADER, message);
    send_message(client_socket, message_encrypted, type="byte");

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

def recieveEncryptedMessage(client_socket, chaKey):
    try:
        whole_message = receive_message(client_socket);
        decrypted_message = ChaChaDecrypt(chaKey, CHACHA_HEADER, whole_message["data"]);
        return {'header': whole_message["header"], 'data': decrypted_message, 'integrity': True};
    except InvalidTag as eit:
        return {'header': whole_message["header"], 'data': decrypted_message, 'integrity': False};
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

ecdhe_private_key = ec.generate_private_key(ec.SECP521R1());
public_hash_final = SHA3_512_Hasher(ecdhe_private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo));
first_exchange_msg = ecdhe_private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo) + CUSTOM_SEPARATOR + public_hash_final;
ecdhe_signature = ecdhe_private_key.sign(SHA3_512_Hasher(first_exchange_msg), ec.ECDSA(hashes.SHA3_512())); #WARNING: Change this to a global derived key later.

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

send_message(client_socket, first_exchange_msg + CUSTOM_SEPARATOR + ecdhe_signature, "byte");

while(True):
    try:
        handshake_data = receive_message(client_socket);
    except:
        continue;
    break;
split = handshake_data["data"].split(CUSTOM_SEPARATOR);
received_server_public = split[0];
received_server_public_hash = split[1];
received_server_sig = split[2];
received_server_public = received_server_public.replace(b'\r\n', b'');
received_server_public_hash = received_server_public_hash.replace(b"\r\n", b'');
tmphash_final = SHA3_512_Hasher(received_server_public);
if tmphash_final == received_server_public_hash:
    print(f"{RT.BLUE}Server's Public Key and Public Key Hash Matched!{RT.RESET}");
    tmp_server_pubkey = load_der_public_key(received_server_public, None);
    signature_hash = SHA3_512_Hasher(received_server_public + CUSTOM_SEPARATOR + received_server_public_hash);
    try:
        tmp_server_pubkey.verify(received_server_sig, signature_hash, ec.ECDSA(hashes.SHA3_512()));
        print(f"{RT.CYAN}Server Signature Verified!{RT.RESET}");
    except (ValueError, TypeError) as e:
        print(f"{RT.RED}Could Not Verify Server's Signature! Rejecting Connection!{RT.RESET}");
        exit(2);
    shared_key = ecdhe_private_key.exchange(ec.ECDH(), tmp_server_pubkey);
    derived_key = HKDF(
        algorithm=hashes.SHA3_512(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key);
send_message(client_socket, tmp_server_pubkey.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo), "byte");
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
ready_msg = ChaChaDecrypt(derived_key, CHACHA_HEADER, ready["data"]);
if ready_msg == "Ready".encode('utf-8'):
    print(f"{RT.GREEN}Client Is Ready To Communicate!{RT.RESET}");
else:
    print(f"{RT.RED}Server's Ready Message Was Interrupted. Shutting Down!{RT.RESET}");
    client_socket.close();
    exit(1);

sendEncryptedMessage(client_socket, user_username.encode('utf-8'), derived_key);

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
                sendEncryptedMessage(sock, "VoCom Initiate".encode('utf-8'), derived_key);
                VoiceCommunication_obj = VoCom(sock, derived_key, read_chunk=5120);
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
                ftp_flag = ("SFTP Initiate" + ":0x0:" + addresses_string + ":0x0:" + str(filesize_uc) + ":0x0:" + str(filesize_c)).encode('utf-8');
                sendEncryptedMessage(sock, ftp_flag, derived_key);
                file_hash = UploadFile(sock, addresses[1:], derived_key, filesize_uc, filesize_c, 16384);
                sendEncryptedMessage(sock, ("SFTP END" + ":0x0:" + file_hash[0].hexdigest() + ":0x0:" + file_hash[1].hexdigest()).encode('utf-8'), derived_key);
                os.remove("temp.tar.gz");
                print("");
                prompt();
                procedure_lock.set();
            else:
                message = message.encode('utf-8');
                sendEncryptedMessage(sock, message, derived_key);
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
            decrypted_message_package = recieveEncryptedMessage(sock, derived_key);
            decrypted_message = decrypted_message_package["data"];
            split_decrypted_message = decrypted_message.split(CUSTOM_SEPARATOR);
            if split_decrypted_message[0] == "SFTP Initiate".encode('utf-8'):
                procedure_lock.clear();
                print("Incoming File(s)....");
                dfilename_split = split_decrypted_message[1].decode('utf-8').strip().split(",");
                dfilename = dfilename_split[:len(dfilename_split) - 1];
                filesize_uc = split_decrypted_message[2];
                filesize_c = split_decrypted_message[3];
                DownloadFile(sock, dfilename, derived_key, int(filesize_uc), int(filesize_c), 16384);
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