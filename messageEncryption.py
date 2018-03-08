import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

#Encrypt

backend = default_backend()

def MyEncrypt(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    print("Plaintext Message: ", message)
    byteMessage = str.encode(message)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(byteMessage) + padder.finalize()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    print("Encrypted message:", ct)
    print("IV: ", iv)
    return [ct, iv]


key = os.urandom(32)
if (len(key) <32):
    print('ERROR: Key less than 32 bytes. Key must be exactly 32 bytes in length')

ctIV =  MyEncrypt('cecs378', key)

def MyDecrypt(cipherIV):
    # #Decrypt
    iv = cipherIV[1]
    ct = cipherIV[0]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    ct = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    ct = unpadder.update(ct) + unpadder.finalize()
    ct = str(ct, 'utf-8')
    print("Decrypted Message: ", ct)

MyDecrypt(ctIV)