import atexit
import errno
import os
import re
import select
import socket
import sys
import tarfile
import threading
import traceback
from threading import Thread

import sounddevice as sd
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.asymmetric.x25519 import (X25519PrivateKey,
                                                              X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from rich.progress import (BarColumn, DownloadColumn, Progress, TextColumn,
                           TimeRemainingColumn, TransferSpeedColumn)

CUSTOM_SEPARATOR = b":0x0:"
CHACHA_HEADER = b"header"
HEADER_LENGTH = 10
TEMP_FILE_NAME = "temp.tar.gz"
derived_key = b""
logfilehandle = open("client_log.txt", "w")

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


class RT:
    # Text
    BLACK = "\u001b[30m"
    RED = "\u001b[31m"
    GREEN = "\u001b[32m"
    YELLOW = "\u001b[33m"
    BLUE = "\u001b[34m"
    MAGENTA = "\u001b[35m"
    CYAN = "\u001b[36m"
    WHITE = "\u001b[37m"

    # Background
    BBLACK = "\u001b[40m"
    BRED = "\u001b[41m"
    BGREEN = "\u001b[42m"
    BYELLOW = "\u001b[43m"
    BBLUE = "\u001b[44m"
    BMAGENTA = "\u001b[45m"
    BCYAN = "\u001b[46m"
    BWHITE = "\u001b[47m"

    RESET = "\u001b[0m"


class VoCom:
    def __init__(
        self,
        socket,
        key,
        read_chunk=None,
        block_chunk=0,
        audio_format=None,
        channels=None,
        rate=None,
    ):
        self._read_chunk = read_chunk
        self._block_chunk = block_chunk
        self._audio_format = audio_format
        self._channels = channels
        self._rate = rate
        self._socket = socket
        self._key = key
        print(f"{RT.CYAN}Initializing Voice Streams{RT.RESET}")
        self.playing_stream = sd.RawOutputStream(
            samplerate=self._rate,
            blocksize=self._block_chunk,
            channels=self._channels,
            dtype=self._audio_format,
        )
        self.recording_stream = sd.RawInputStream(
            samplerate=self._rate,
            blocksize=self._block_chunk,
            channels=self._channels,
            dtype=self._audio_format,
        )
        self.playing_stream.start()
        self.recording_stream.start()
        receive_thread = threading.Thread(target=self.receive_server_data).start()
        print(f"{RT.CYAN}Voice Stream Active{RT.RESET}")
        self.send_data_to_server()

    def receive_server_data(self):
        while True:
            try:
                user_data = receive_message(self._socket)
                message_stream = recieveEncryptedMessage(self._socket, self._key)[
                    "data"
                ]
                self.playing_stream.write(message_stream)
            except Exception:
                pass

    def send_data_to_server(self):
        while True:
            try:
                (data, _) = self.recording_stream.read(self._read_chunk)
                sendEncryptedMessage(self._socket, data[:], self._key, False)
            except Exception:
                pass


def FileCompressor(tar_file, files):
    with tarfile.open(tar_file, "w:gz") as tar:
        for file in files:
            with Progress() as progress:
                task = progress.add_task(f"[yellow]Compressing {file}")
                while not progress.finished:
                    tar.add(file)
                    progress.update(task, advance=100)


def FileDecompressor(tar_file, file_name):
    with tarfile.open(tar_file, "r:gz") as tar:
        file_name = tar.getmembers()
        for file in file_name:
            with Progress() as progress:
                task = progress.add_task(f"[yellow]Decompressing {file}", start=False)
                while not progress.finished:
                    tar.extract(file)
                    progress.update(task, advance=100)


def UploadFile(socket, address, key, size_compressed, buffer=2048):
    with open(TEMP_FILE_NAME, "rb") as f:
        file_hash_uc = hashes.Hash(hashes.SHA3_512())
        file_hash_c = hashes.Hash(hashes.SHA3_512())
        for address_singular in address:
            with open(address_singular, "rb") as filehandle:
                while True:
                    block = filehandle.read(buffer)
                    if not block:
                        break
                    file_hash_uc.update(block)
        with Progress(
            TextColumn("[bold blue]{task.description}", justify="right"),
            BarColumn(bar_width=None),
            "[progress.percentage]{task.percentage:>3.1f}%",
            "•",
            DownloadColumn(),
            "•",
            TransferSpeedColumn(),
            "•",
            TimeRemainingColumn(),
        ) as progress:
            task = progress.add_task("Uploading file(s)", total=size_compressed)
            while not progress.finished:
                block = f.read(buffer)
                if not block:
                    break
                select.select([], [socket], [])
                sendEncryptedMessage(socket, block, key)
                progress.update(task, advance=len(block))
                file_hash_c.update(block)
    return (file_hash_uc, file_hash_c)


def DownloadFile(socket, name, key, size_compressed, buffer=2048):
    with open(TEMP_FILE_NAME, "wb") as f:
        file_hash = hashes.Hash(hashes.SHA3_512())
        with Progress(
            TextColumn("[bold blue]{task.description}", justify="right"),
            BarColumn(bar_width=None),
            "[progress.percentage]{task.percentage:>3.1f}%",
            "•",
            DownloadColumn(),
            "•",
            TransferSpeedColumn(),
            "•",
            TimeRemainingColumn(),
        ) as progress:
            task = progress.add_task("Downloading file(s)", total=size_compressed)
            while not progress.finished:
                # select.select([client_socket], [], [])
                select.select([socket], [], [])
                # user_data = receive_message(socket)
                file_content = recieveEncryptedMessage(socket, key)["data"]
                f.write(file_content)
                progress.update(task, advance=len(file_content))
                file_hash.update(file_content)
        # user_data = receive_message(socket)
        message = recieveEncryptedMessage(socket, key)["data"]
        if message[:8] == "SFTP END".encode("utf-8"):
            print(f"{RT.BLUE}SFTP END{RT.RESET}")
        else:
            print(f"{RT.RED}SFTP Did Not End! Retry File Transfer.{RT.RESET}")
            return
        split_data = message.split(CUSTOM_SEPARATOR)
        received_file_hash_uc = split_data[1]
        received_file_hash_c = split_data[2]
        if received_file_hash_c == file_hash.finalize():
            FileDecompressor(TEMP_FILE_NAME, name)
            ucfilehash = hashes.Hash(hashes.SHA3_512())
            for name_singular in name:
                with open(name_singular, "rb") as filehandle:
                    while True:
                        block = filehandle.read(buffer)
                        if not block:
                            break
                        ucfilehash.update(block)
        if (
            received_file_hash_c == file_hash.finalize()
            and received_file_hash_uc == ucfilehash.finalize()
        ):
            print(f"{RT.GREEN}SFTP Checksum Matched!{RT.RESET}")
        else:
            print(f"{RT.RED}SFTP Checksum Did Not Match! File Is Corrupt{RT.RESET}")


def SHA3_512_Hasher(string: bytes) -> bytes:
    hashobj = hashes.Hash(hashes.SHA3_512())
    hashobj.update(string)
    return hashobj.finalize()


def ChaChaEncrypt(key: bytes, header: bytes, plaintext: bytes) -> bytes:
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    return chacha.encrypt(nonce, plaintext, header) + nonce


def ChaChaDecrypt(key: bytes, header: bytes, ciphertext: bytes) -> bytes:
    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(ciphertext[-12:], ciphertext[:-12], header)


def send_message(client_socket, message, type="byte") -> None:
    if type == "byte":
        message_header = f"{len(message):<{HEADER_LENGTH}}".encode("utf-8")
        client_socket.send(message_header + message)
    elif type == "string":
        message_sender = message.encode("utf-8")
        message_sender_header = f"{len(message_sender):<{HEADER_LENGTH}}".encode(
            "utf-8"
        )
        client_socket.send(message_sender_header + message_sender)


def sendEncryptedMessage(client_socket, message, chaKey) -> None:
    message_encrypted = ChaChaEncrypt(chaKey, CHACHA_HEADER, message)
    send_message(client_socket, message_encrypted, type="byte")


def recv_exact(socket, size) -> bytes | None:
    buflist = []
    while size:
        while True:
            try:
                buf = socket.recv(size)
                break
            except IOError as e:
                if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                    exit_program()
                else:
                    continue
        if not buf:
            logfilehandle.write("recv_exact(): Failed prematurely\n")
            return
        buflist.append(buf)
        size -= len(buf)
    return b"".join(buflist)


def receive_message(client_socket) -> dict[str, bytes | None] | None:
    try:
        message_header = recv_exact(client_socket, HEADER_LENGTH)
        if not message_header:
            logfilehandle.write("receive_message(): Failed prematurely\n")
            return
        message_length = int(message_header.decode("utf-8").strip())
        return {
            "header": message_header,
            "data": recv_exact(client_socket, message_length),
        }
    except IOError as e:
        if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
            print("Reading error: {}".format(str(e)))
            logfilehandle.write("receive_message(): " + str(e) + "\n")
            logfilehandle.close()
            exit_program()
        else:
            logfilehandle.write("Stack: " + traceback.format_exc() + "\n")
            raise
    except Exception as e:
        logfilehandle.write("receive_message(): " + str(e) + "\n")
        return


def recieveEncryptedMessage(client_socket, chaKey) -> dict | None:
    try:
        whole_message = receive_message(client_socket)
        if not whole_message:
            return
        decrypted_message = ChaChaDecrypt(chaKey, CHACHA_HEADER, whole_message["data"])
        return {
            "header": whole_message["header"],
            "data": decrypted_message,
            "integrity": True,
        }
    except InvalidTag:
        # TODO fix unbound whole_message
        return {
            "header": whole_message["header"],
            "data": decrypted_message,
            "integrity": False,
        }
    except Exception as e:
        logfilehandle.write("recieveEncryptedMessage(): " + str(e) + "\n")
        return


def checkIP(ip) -> bool:
    regex = """^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)"""
    return True if re.search(regex, ip) else False


def checkPort(port) -> bool:
    return True if port >= 1 and port <= 65535 else False


def prompt(specialmessage="") -> None:
    sys.stdout.write(f"<You> {specialmessage}")
    sys.stdout.flush()


def exit_cleanup() -> None:
    print(f"{RT.RED}Exiting Program{RT.RESET}")
    logfilehandle.close()
    try:
        os.remove(TEMP_FILE_NAME)
    except:
        pass


# TODO change exit codes
def exit_program(exit_code=5) -> None:
    exit_cleanup()
    sys.exit(exit_code)


def sender_function(sock, procedure_lock, derived_key):
    while True:
        procedure_lock.wait()
        message = sys.stdin.readline()
        if not procedure_lock.is_set():
            procedure_lock.wait()
            continue
        if message:
            if message == "?:0x0VoCom\n":
                procedure_lock.clear()
                sendEncryptedMessage(
                    sock, "VoCom Initiate".encode("utf-8"), derived_key
                )
                # TODO Voice communication
                VoiceCommunication_obj = VoCom(sock, derived_key, read_chunk=5120)
            elif message[:12] == "?:0x0SFTPcmd":
                procedure_lock.clear()
                addresses = message.split(",")
                filesize_uc = 0
                addresses_string = ""
                for i in range(1, len(addresses)):
                    addresses[i] = addresses[i].strip()
                    filesize_uc += os.path.getsize(addresses[i])
                    addresses_string += addresses[i] + ","
                FileCompressor(TEMP_FILE_NAME, addresses[1:])
                filesize_c = os.path.getsize(TEMP_FILE_NAME)
                ftp_flag = (
                    "SFTP Initiate"
                    + str(CUSTOM_SEPARATOR)
                    + addresses_string
                    + str(CUSTOM_SEPARATOR)
                    + str(filesize_uc)
                    + str(CUSTOM_SEPARATOR)
                    + str(filesize_c)
                ).encode("utf-8")
                sendEncryptedMessage(sock, ftp_flag, derived_key)
                file_hash = UploadFile(
                    sock, addresses[1:], derived_key, filesize_c, 16384
                )
                sendEncryptedMessage(
                    sock,
                    (
                        "SFTP END"
                        + str(CUSTOM_SEPARATOR)
                        + str(file_hash[0].finalize())
                        + str(CUSTOM_SEPARATOR)
                        + str(file_hash[1].finalize())
                    ).encode("utf-8"),
                    derived_key,
                )
                os.remove(TEMP_FILE_NAME)
                print("")
                prompt()
                procedure_lock.set()
            else:
                message = message.encode("utf-8")
                sendEncryptedMessage(sock, message, derived_key)
                prompt()


def receiver_function(sock, procedure_lock, derived_key):
    while True:
        socket_list = [sock]
        _, _, _ = select.select(socket_list, [], [])
        procedure_lock.wait()
        try:
            user_data = receive_message(sock)
            if user_data is False:
                print("Connection Closed By The Server")
                exit_program()
            if not user_data:
                # TODO handle this scenario
                continue
            rusername = user_data["data"]
            decrypted_message_package = recieveEncryptedMessage(sock, derived_key)
            if not decrypted_message_package:
                # TODO handle this scenario
                continue
            decrypted_message = decrypted_message_package["data"]
            split_decrypted_message = decrypted_message.split(CUSTOM_SEPARATOR)
            if split_decrypted_message[0] == "SFTP Initiate".encode("utf-8"):
                procedure_lock.clear()
                print("Incoming File(s)....")
                dfilename_split = (
                    split_decrypted_message[1].decode("utf-8").strip().split(",")
                )
                dfilename = dfilename_split[: len(dfilename_split) - 1]
                filesize_uc = split_decrypted_message[2]
                filesize_c = split_decrypted_message[3]
                DownloadFile(
                    sock,
                    dfilename,
                    derived_key,
                    # int(filesize_uc),
                    int(filesize_c),
                    16384,
                )
                os.remove(TEMP_FILE_NAME)
                prompt()
                procedure_lock.set()
                continue
            if decrypted_message_package["integrity"]:
                print(
                    f"{rusername.decode('utf-8')} > [I] {decrypted_message.decode('utf-8')}"
                )
            else:
                print(
                    f"{rusername.decode('utf-8')} > [C] {decrypted_message.decode('utf-8')}"
                )
            prompt()
        except IOError as e:
            if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                print("Reading error: {}".format(str(e)))
                logfilehandle.write("IOError: " + str(e) + "\n")
                logfilehandle.close()
                exit_program()
        except Exception as e:
            print("General Error {}".format(str(e)))
            logfilehandle.write("General Error: " + str(e) + "\n")
            logfilehandle.close()
            exit_program()


def main():
    asym_private_key = X25519PrivateKey.generate()
    public_hash_final = SHA3_512_Hasher(
        asym_private_key.public_key().public_bytes_raw()
    )
    first_exchange_msg = (
        asym_private_key.public_key().public_bytes_raw()
        + CUSTOM_SEPARATOR
        + public_hash_final
    )

    asym_sig_private_key = Ed25519PrivateKey.generate()
    asym_signature = asym_sig_private_key.sign(SHA3_512_Hasher(first_exchange_msg))
    asym_sig_public_key = asym_sig_private_key.public_key().public_bytes_raw()
    asym_sig_public_key_hash = SHA3_512_Hasher(asym_sig_public_key)
    # ecdhe_signature = ecdhe_private_key.sign(
    #     SHA3_512_Hasher(first_exchange_msg), ec.ECDSA(hashes.SHA3_512())
    # )  # WARNING TODO: Change this to a global derived key later.

    exchange_msg = (
        first_exchange_msg
        + CUSTOM_SEPARATOR
        + asym_signature
        + CUSTOM_SEPARATOR
        + asym_sig_public_key
        + CUSTOM_SEPARATOR
        + asym_sig_public_key_hash
    )

    IP = str(input("Enter Server IP Address: "))
    while checkIP(IP) is False:
        IP = str(input("Enter Server IP Address: "))
    Port = int(input("Enter Socket Port: "))
    while checkPort(Port) is False:
        Port = int(input("Enter Socket Port: "))
    user_username = str(input("Username: "))

    print("Connecting to Server...")

    try:
        client_socket.connect((IP, Port))
        print(f"{RT.GREEN}Connected!{RT.RESET}")
        client_socket.setblocking(False)
    except BaseException as e:
        print(f"{RT.RED}Error Occured During Connection Phase!{RT.RESET}")
        logfilehandle.write("Socket Connection Error: " + str(e) + "\n")
        logfilehandle.close()
        exit_program(1)

    send_message(client_socket, exchange_msg)

    while True:
        try:
            handshake_data = receive_message(client_socket)
            if handshake_data is None:
                continue
        except:
            continue
        break
    split = handshake_data["data"].split(CUSTOM_SEPARATOR)
    received_server_asym_public = split[0]
    received_server_asym_public_hash = split[1]
    received_server_sig = split[2]
    received_server_sig_public = split[3]
    received_server_sig_public_hash = split[4]
    received_server_asym_public = received_server_asym_public.replace(b"\r\n", b"")
    received_server_sig_public = received_server_sig_public.replace(b"\r\n", b"")
    received_server_asym_public_hash = received_server_asym_public_hash.replace(
        b"\r\n", b""
    )
    received_server_sig_public_hash = received_server_sig_public_hash.replace(
        b"\r\n", b""
    )
    local_server_asym_public_hash = SHA3_512_Hasher(received_server_asym_public)
    local_server_sig_public_hash = SHA3_512_Hasher(received_server_sig_public)

    if local_server_sig_public_hash == received_server_sig_public_hash:
        print(f"{RT.BLUE}Server's Signature Hash Matched!{RT.RESET}")
        tmp_server_sig_pubkey = Ed25519PublicKey.from_public_bytes(
            received_server_sig_public
        )
        local_server_sig_hash = SHA3_512_Hasher(
            received_server_asym_public
            + CUSTOM_SEPARATOR
            + received_server_asym_public_hash
        )
        try:
            tmp_server_sig_pubkey.verify(received_server_sig, local_server_sig_hash)
            print(f"{RT.CYAN}Server Signature Verified!{RT.RESET}")
        except (ValueError, TypeError):
            print(
                f"{RT.RED}Could Not Verify Server's Signature! Rejecting Connection!{RT.RESET}"
            )
            exit_program(2)
        if local_server_asym_public_hash != received_server_asym_public_hash:
            print(
                f"{RT.RED}Server's Public Key Hash Did Not Match! Rejecting Connection!{RT.RESET}"
            )
            exit_program(2)
        print(f"{RT.MAGENTA}Server's Public Key Hash Matched!{RT.RESET}")
        tmp_server_pubkey = X25519PublicKey.from_public_bytes(
            received_server_asym_public
        )
        shared_key = asym_private_key.exchange(tmp_server_pubkey)
        derived_key = HKDF(
            algorithm=hashes.SHA3_512(),
            length=32,
            salt=None,
            info=b"handshake data",
        ).derive(shared_key)

    send_message(client_socket, tmp_server_pubkey.public_bytes_raw())
    try:
        while True:
            try:
                ready = receive_message(client_socket)
                if not ready:
                    continue
            except:
                continue
            break
    except Exception as e:
        print(
            f"{RT.RED}Error Occurred During Second Phase Of Handshake Sequence!{RT.RESET}"
        )
        logfilehandle.write("Handshake Error: " + str(e) + "\n")
        logfilehandle.close()
        exit_program(1)
    ready_msg = ChaChaDecrypt(derived_key, CHACHA_HEADER, ready["data"])
    if ready_msg == "Ready".encode("utf-8"):
        print(f"{RT.GREEN}Client Is Ready To Communicate!{RT.RESET}")
    else:
        print(
            f"{RT.RED}Server's Ready Message Was Interrupted. Shutting Down!{RT.RESET}"
        )
        client_socket.close()
        exit_program(1)

    sendEncryptedMessage(client_socket, user_username.encode("utf-8"), derived_key)

    prompt()

    procedure_lock = threading.Event()
    procedure_lock.set()

    Thread(
        target=sender_function,
        args=(client_socket, procedure_lock, derived_key),
        daemon=True,
    ).start()
    Thread(
        target=receiver_function, args=(client_socket, procedure_lock, derived_key)
    ).start()

    atexit.register(exit_cleanup)


if __name__ == "__main__":
    main()
