from Crypto import Random
from libDes import encrypt_file
from libDes import decrypt_file
import re

iv = Random.get_random_bytes(8)
print(iv)
key="01234567abcdefgh"
with open('plain.txt', 'r') as f:
    print ('plain.txt: %s' % f.read())

encrypt_file('plain.txt', 'cipherText.enc', 8192, key, iv)

print("Cipher Text");
with open('cipherText.enc', 'r') as f:
    print ('cipherText.enc: %s' % f.read())

print("After Decrypt")
decrypt_file('cipherText.enc', 'plain1.dec', 8192, key, iv)
with open('plain1.dec', 'r') as f:
    print ('plain1.dec: %s' % f.read())
