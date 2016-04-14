import os
import pdb

from Crypto.Cipher import DES3
def encrypt_file(in_filename, out_filename, chunk_size, key, iv):
    des3 = DES3.new(key, DES3.MODE_CFB, iv)
    with open(in_filename, 'r+') as in_file:
        with open(out_filename, 'w') as out_file:
            while True:
                chunk = in_file.read(chunk_size)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)
                out_file.write(str(des3.encrypt(chunk)))
                #print((des3.encrypt(chunk)))
                #print("\n")
def decrypt_file(in_filename, out_filename, chunk_size, key, iv):
    des3 = DES3.new(key, DES3.MODE_CFB, iv)
    with open(in_filename, 'r+') as in_file:
        print("Decrypt")
        with open(out_filename, 'w') as out_file:
            while True:
                chunk = in_file.read(chunk_size)
                if len(chunk) == 0:
                    break
                #out_file.write(str(eval(str(des3.decrypt(eval(chunk))))))
                output = (str(des3.decrypt(eval(chunk))))
                print (output)
                output = str(((output.split("'")[1]).strip(" ")))
                output = output.split("\\n")
                for item in output:
                    out_file.write (item)
                    out_file.write ("\n")
 #               out_file.write()

