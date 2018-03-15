import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import json

keySize = 32
ivSize = 16
blockSize = 128
fileEncrypt = '/Users/mcastro/Desktop/fruitbat.jpg'
encryptedFileLoc = '/Users/mcastro/Desktop/encrypt.json'
fileDecrypt = '/Users/mcastro/Desktop/decrypt'


#Encrypt
backend = default_backend()     #creates cipher backend



def MyfileEncrypt(filepath):
    with open(filepath, "rb") as imageFile:
        fileStr = base64.b64encode(imageFile.read())        #opens file and reads as string, converts to b64 encoding
    filename, extension = os.path.splitext(filepath)        #get file name and file extension
    key = os.urandom(keySize)                               #generate key
    iv = os.urandom(ivSize)                                 #generate iv
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)    #create cipher object using AES in CBC mode using the generated key and iv
    encryptor = cipher.encryptor()                          #create encryptor object


    padder = padding.PKCS7(blockSize).padder()              #create padder object using PKCS7, blocksize = 128
    padded_data = padder.update(fileStr) + padder.finalize()    #pad fileStr, which is the file read as string
    ct = encryptor.update(padded_data) + encryptor.finalize()   #create ciphertext, padded fileStr after encryption
    print("Cipher:", ct)
    print("IV: ", iv)
    print("Key: ", key)
    print("File Extension: ", extension)

    encodedCT = base64.encodestring(ct)                     #byte to base64
    asciiCT = encodedCT.decode('ascii')                     #base64 to ascii so JSON will accept it
    encodedIV = base64.encodestring(iv)
    asciiIV = encodedIV.decode('ascii')
    encodedKey = base64.encodestring(key)
    asciiKey = encodedKey.decode('ascii')
    # decodedAs = asciiCT.encode('ascii')
    # ct2 = base64.decodestring(decodedAs)


    data = {'Cipher' : asciiCT, 'IV': asciiIV, 'Key': asciiKey, 'FileExtension': extension, 'FileName': filename}   #create dictionary with our values
    jsonData = json.dumps( data)    #dictionary to json
    with open(encryptedFileLoc, 'w') as outfile:    #write to JSON file
        json.dump(jsonData, outfile)

    return [ct, iv, key, extension]


MyfileEncrypt(fileEncrypt)

def MyfileDecrypt(encryptedFile):

    with open(encryptedFile) as json_data:
        data = json.load(json_data)
        d = json.loads(data)                    #open JSON file and put it into dictionary
    asciiCT = d['Cipher']                       #get values from dictionary
    asciiIV = d['IV']
    asciiKey = d['Key']
    extension = d['FileExtension']

    decodedCT = asciiCT.encode('ascii')         #ascii to b64
    decodedIV = asciiIV.encode('ascii')
    decodedKey = asciiKey.encode('ascii')

    ct = base64.decodestring(decodedCT)         #b64 to bytes
    key = base64.decodestring(decodedKey)
    iv = base64.decodestring(decodedIV)


    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)    #create new cipher object
    decryptor = cipher.decryptor()                                          #create decryptor object
    ct = decryptor.update(ct) + decryptor.finalize()                        #decrypt cipher text
    unpadder = padding.PKCS7(blockSize).unpadder()                          #create unpadder
    ct = unpadder.update(ct) + unpadder.finalize()                          #unpad plaintext
    newFileLocation = fileDecrypt + extension                               #create file location using original file extension
    fh = open(newFileLocation, "wb")                                        #decode and write to file
    fh.write(base64.b64decode(ct))
    fh.close()

MyfileDecrypt(encryptedFileLoc)