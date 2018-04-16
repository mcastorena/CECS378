import os
import json
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

keySize = 32
encryptedFileLoc = "/Users/mcastro/Desktop/encrypt.json"

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
    with open(encryptedFileLoc, 'w') as outfile:  # write to JSON file
        json.dump(jsonData, outfile)

HMACGeneration(encryptedFileLoc)

def HMACVerification(jsonFile):

    with open(jsonFile) as json_data:
        data = json.load(json_data)
        d = json.loads(data)                    #open JSON file and put it into dictionary
    json_data.close()                           #close JSON file
    asciiDigest = d['Tag']                      #get digest
    decodedDigest = asciiDigest.encode('ascii') #ascii to b64
    digest = base64.decodestring(decodedDigest) #b64 to bytes
    asciiHMACKey = d['HMACKey']                 #get HMACKey
    decodedKey = asciiHMACKey.encode('ascii')   #ascii to b64
    HMACKey = base64.decodestring(decodedKey)   #b64 to bytes
    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())  #create hash algorithm object
    asciiCT = d['Cipher']  # get encrypted cipher
    decodedCT = asciiCT.encode('ascii')  # ascii to b64
    ct = base64.decodestring(decodedCT)  # b64 to bytes
    h.update(ct)  # bytes to hash and authenticate
    h.verify(digest)         #compare stored hash with new hash created from ciphertext and HMACKey in JSON file
                             #returns cryptography.exceptions.InvalidSignature if hashes do not match

HMACVerification(encryptedFileLoc)
