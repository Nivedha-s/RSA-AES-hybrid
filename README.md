# RSA-AES-hybrid

# Client 
The message that is to be sent to the server is first encrypted using AES encryption algorithm and the AES symmetric key is encrypted with RSA public key of the server. These are then sent to the server and decryption happens at the server end.
# Server
The received encrypted AES key is decrypted with server's private key. The AES symmetric key got is used to decrypt the message.


