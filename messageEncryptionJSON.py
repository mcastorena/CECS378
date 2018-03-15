import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import json
import base64

keySize = 32
ivSize = 16
blockSize = 128
plaintext = 'CECS378'
encryptedFileLoc = '/Users/mcastro/Desktop/encryptMsg.json'

#Encrypt

backend = default_backend()

def MyEncrypt(message):
    key = os.urandom(keySize)
    if (len(key) < keySize):
        print('ERROR: Key less than 32 bytes. Key must be exactly 32 bytes in length')
    iv = os.urandom(ivSize)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    print("Plaintext Message: ", message)
    byteMessage = str.encode(message)

    padder = padding.PKCS7(blockSize).padder()
    padded_data = padder.update(byteMessage) + padder.finalize()
    ct = encryptor.update(padded_data) + encryptor.finalize()

    encodedCT = base64.encodestring(ct)                     #byte to base64
    asciiCT = encodedCT.decode('ascii')                     #base64 to ascii so JSON will accept it
    encodedIV = base64.encodestring(iv)
    asciiIV = encodedIV.decode('ascii')
    encodedKey = base64.encodestring(key)
    asciiKey = encodedKey.decode('ascii')
    data = {'Cipher': asciiCT, 'IV': asciiIV, 'Key': asciiKey}  # create dictionary with our values
    jsonData = json.dumps(data)  # dictionary to json
    with open(encryptedFileLoc, 'w') as outfile:  # write to JSON file
        json.dump(jsonData, outfile)


    print("Encrypted message:", ct)
    print("IV: ", iv)
    return [ct, iv]
MyEncrypt(plaintext)



def MyDecrypt(encryptedMsg):
    # #Decrypt
    with open(encryptedMsg) as json_data:
        data = json.load(json_data)
        d = json.loads(data)                    #open JSON file and put it into dictionary
    asciiCT = d['Cipher']                       #get values from dictionary
    asciiIV = d['IV']
    asciiKey = d['Key']

    decodedCT = asciiCT.encode('ascii')         #ascii to b64
    decodedIV = asciiIV.encode('ascii')
    decodedKey = asciiKey.encode('ascii')

    ct = base64.decodestring(decodedCT)         #b64 to bytes
    key = base64.decodestring(decodedKey)
    iv = base64.decodestring(decodedIV)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    ct = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(blockSize).unpadder()
    ct = unpadder.update(ct) + unpadder.finalize()
    ct = str(ct, 'utf-8')
    print("Decrypted Message: ", ct)

MyDecrypt(encryptedFileLoc)