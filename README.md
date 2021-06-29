# SafeChat

SafeChat is a TCP/IP socket chat program with RSA handshake protocol, ChaCha20_Poly1305 symmetric encryption & verification (End-To-End), and separate SHA512 hashing. It supports multi client encryption and communication.

This program was created purely for the demonstration of simple cryptography and socket programming concepts. It is not intended for commercial use!

# Library Dependancies

  - PyCryptoDomex (Download Link: https://pypi.org/project/pycryptodomex/)
  - Rich (Download Link: https://pypi.org/project/rich/)
  - Sounddevice (Download Link: https://pypi.org/project/sounddevice/)
  
# Usage
Run the server module on the appropriate machine:
    `python3 server.py`
You will be asked to enter the IP address of the interface & a static Port to bind to. When you see the output **Listening for connections on {IP}:{Port}...** the server is ready for communication.

Every client has to run the client module in order to connect to the server and initiate comms:
    `python3 client.py`
You will be asked to enter the IP address of the interface, a static Port and a username as an identifier in the chatroom. When you see the prompt `<You>`, you can start sending/receiving messages.

# Future Plans
1. Increased security through improved encryption protocol (Forward Secrecy, EC).
2. Dynamic send/receive collision aversion.
3. Data Integrity (Hash Check/HMAC)(Currently in Alpha).
4. File transfer capabilities(Currently in Alpha).
5. VoIP(Currently in Development)
6. VideoChat(Quite Unlikely)

Note: Thanks to mjm918 for parts of the handshake protocol outline.
