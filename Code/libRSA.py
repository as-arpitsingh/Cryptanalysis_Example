import os
import pdb

def encrypt_file_RSA_Lib(in_filename,out_filename,public_key):
    #de_out_file= open(de_out_filename, 'wb')
    chunk_size=32
    #def encrypt_file(in_filename, out_filename, chunk_size):
    with open(in_filename, 'r+') as in_file:
        with open(out_filename, 'w') as out_file:
            while True:
                chunk = in_file.read(chunk_size)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)
                enc_data=public_key.encrypt(chunk.encode('utf-8'), 32)
                print(len(enc_data))
                out_file.write(str(enc_data))

                #plain_data=key.decrypt(enc_data)
                #de_out_file.write(plain_data)

def decrypt_file_RSA_Lib(in_filename,out_filename,key):
    #de_out_file= open(out_filename, 'wb')
    chunk_size=32
    #def encrypt_file(in_filename, out_filename, chunk_size):
    with open(in_filename, 'r+') as in_file:
        with open(out_filename, 'w') as out_file:
            while True:
                chunk = in_file.read(chunk_size)
                if len(chunk) == 0:
                    break
                #elif len(chunk) % 16 != 0:
                    #chunk += ' ' * (16 - len(chunk) % 16)
                #plain_data=str(key.decrypt(chunk.encode('utf-8')))
                plain_data=str(key.decrypt(eval(chunk)))
                print (plain_data)
                #out_file.write(str(plain_data))
            
