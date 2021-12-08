# Creates a Key Pair, then encodes and decodes text.
# Got most of the code here: https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/


import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def createKeyPair(prKFileStr,puKFileStr):
  private_key = rsa.generate_private_key(
      public_exponent=65537,
      key_size=2048,
      backend=default_backend())
  public_key = private_key.public_key()

  pemPriv = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption())
  with open(prKFileStr, 'wb') as f:
    f.write(pemPriv)    
  
  pemPub = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)
  with open(puKFileStr, 'wb') as f:
    f.write(pemPub)
  
def readPrivKPem(FileStr):
  with open(FileStr, "rb") as key_file:
    private_key = serialization.load_pem_private_key(
    key_file.read(),
    password=None,
    backend=default_backend())
  return private_key

def readPubKPem():
  with open("public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
    key_file.read(),
    backend=default_backend())
  return public_key

def encrypt(FileStr,keyFileStr):
  with open(FileStr, "rb") as msgFile:
    message = msgFile.read() # Read in txt to encrypt
  
  with open(keyFileStr, "rb") as key_file:
    public_key = serialization.load_pem_public_key(key_file.read(),
      backend=default_backend()) # read in key for encoding
  
  encrypted = public_key.encrypt( message,padding.OAEP( mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
  with open('encryptedmsg.txt', 'wb') as f:
    f.write(encrypted) # encode process


def decrypt(privKeyFileStr,FileStr,DecodedOutputFile):
  private_key = readPrivKPem(privKeyFileStr)
  with open(FileStr, "rb") as msgFile:
    encrypted = msgFile.read()

  original_message = private_key.decrypt( encrypted, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))

  with open(DecodedOutputFile, 'wb') as f:
    f.write(original_message)


### MAIN RUN SECTION ###
createKeyPair("private_key.pem","public_key.pem")
encrypt('originalmsg.txt','public_key.pem')
decrypt('private_key.pem','encryptedmsg.txt','decryptedmsg.txt')


