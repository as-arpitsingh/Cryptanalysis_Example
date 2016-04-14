from Crypto.PublicKey import RSA
from Crypto import Random
from libRSA import encrypt_file_RSA_Lib
from libRSA import decrypt_file_RSA_Lib
import re

random_generator = Random.new().read
key = RSA.generate(1024, random_generator)

public_key = key.publickey()

in_filename="plainTextRSA.txt"
out_filename="encryptTextRSA.txt"
de_out_filename="decryptTextRSA.txt"

encrypt_file_RSA_Lib(in_filename, out_filename, public_key)

#print("Cipher Text");
#with open('cipherText.enc', 'r') as f:
#    print ('cipherText.enc: %s' % f.read())

#print("After Decrypt")
decrypt_file_RSA_Lib(out_filename, de_out_filename, key)
#with open('plain1.dec', 'r') as f:
#    print ('plain1.dec: %s' % f.read())
