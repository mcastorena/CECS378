import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
import json
import base64

publicCertificate = "/Users/mcastro/Desktop/public.pem"
privateCertificate = "/Users/mcastro/Desktop/private.pem"
jsonFile = "/Users/mcastro/Desktop/encrypt.json"
k1 = ''
k2 = ''

def rsaEncryption(certFile, jsonFile):
    with open(certFile, "rb") as key_file:              #open public certificate from specified file path
        publicKey = serialization.load_pem_public_key(key_file.read(),backend = default_backend())      #create publicKey object from public key data
    key_file.close()
    with open(jsonFile) as json_data:
        data = json.load(json_data)
        d = json.loads(data)                    #open JSON file and put it into dictionary
    json_data.close()
    asciiKey = d['Key']                       #get encryption key
    print("Key before encryption:",asciiKey)
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
    print("Key after encryption:",ct)

rsaEncryption(publicCertificate, jsonFile)

def rsaDecryption(certFile, jsonFile):
    with open(jsonFile) as json_data:
        data = json.load(json_data)
        d = json.loads(data)                    #open JSON file and put it into dictionary
    json_data.close()
    asciiCT = d['Key']                          #get RSA encrypted key
    decodedCT = asciiCT.encode('ascii')         #ascii to b64
    ct = base64.decodestring(decodedCT)  # b64 to bytes
    with open(certFile, "rb") as key_file:  # open private certificate from specified file path
        privateKey = serialization.load_pem_private_key(key_file.read(), password = None, backend = default_backend()) # create privateKey object from pprivate key data
    key = privateKey.decrypt(ct, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)) #decrypt key
    encodedKey = base64.encodestring(key)       #bytes to b64
    asciiKey = encodedKey.decode('ascii')       #b64 to ascii
    print("Key after decryption:",asciiKey)
    d['Key'] = asciiKey
    jsonData = json.dumps(d)  # dictionary to json
    with open(jsonFile, 'w') as outfile:  # write to JSON file
        json.dump(jsonData, outfile)


rsaDecryption(privateCertificate, jsonFile)