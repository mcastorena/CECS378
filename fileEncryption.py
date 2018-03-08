import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

keySize = 32
ivSize = 16
blockSize = 128
fileEncrypt = '/Users/mcastro/Desktop/fruitbat.jpg'
encryptedFileLoc = '/Users/mcastro/Desktop/encrypt'
fileDecrypt = '/Users/mcastro/Desktop/decrypt'


#Encrypt
backend = default_backend()

def MyfileEncrypt(filepath):
    with open(filepath, "rb") as imageFile:
        fileStr = base64.b64encode(imageFile.read())
    filename, extension = os.path.splitext(filepath)
    key = os.urandom(keySize)
    iv = os.urandom(ivSize)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()


    padder = padding.PKCS7(blockSize).padder()
    padded_data = padder.update(fileStr) + padder.finalize()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    print("Cipher:", ct)
    print("IV: ", iv)
    print("Key: ", key)
    print("File Extension: ", extension)

    encryptedFile = encryptedFileLoc + extension
    fh = open(encryptedFile, "wb")
    fh.write(base64.b64decode(ct))
    fh.close()

    return [ct, iv, key, extension]


decrypt =  MyfileEncrypt(fileEncrypt)

def MyfileDecrypt(cipherIVKeyEXT):
    # #Decrypt
    iv = cipherIVKeyEXT[1]
    ct = cipherIVKeyEXT[0]
    key = cipherIVKeyEXT[2]
    extension = cipherIVKeyEXT[3]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    ct = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(blockSize).unpadder()
    ct = unpadder.update(ct) + unpadder.finalize()
    newFileLocation = fileDecrypt + extension
    fh = open(newFileLocation, "wb")
    fh.write(base64.b64decode(ct))
    fh.close()

MyfileDecrypt(decrypt)