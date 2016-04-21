################################################################################
#
# References:
# The code for changing pages was derived from:
# http://stackoverflow.com/questions/7546050/switch-between-two-frames-in-tkinter
# License: http://creativecommons.org/licenses/by-sa/3.0/
# Referenced from:
# https://pythonprogramming.net/tkinter-depth-tutorial-making-actual-program/
#
################################################################################
#---------------   importing dependencies
################################################################################

#-------- get Bytes --> 'Sting'.encode('UTF-8')
#-------- get String --> 'Bytes'.decode('UTF-8')

import os, re, time, pdb # python standard modules/lbraries
import makeRsaKeys, rsaCipher, pyDes # implemented Functions

# ------- these modules / libraries must be installed before importing.
# ------- please refer the ReadMe.txt file.
import numpy as np

import matplotlib
import matplotlib.animation as animation
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2TkAgg
from matplotlib.figure import Figure
from matplotlib import style
from matplotlib import pyplot as plt

import tkinter as tk
from tkinter import ttk
from tkinter.messagebox import *

import rsa as RSAL
from rsa import key  as RSALkey
from rsa import common as RSALcommon

from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES
from Crypto.Hash import SHA256
from Crypto.Hash import MD5

################################################################################
#---------------   initializing global variables
################################################################################

CURRENT_DIRECTORY = os.getcwd()
INTRO_TEXT = 'Welcome!'
PROJECT_NAME = 'Cryptanalysis'
LARGE_FONT = ("Helvetica", 16)
MID_FONT= ("Verdana", 12)
NORM_FONT= ("Verdana", 10)
SMALL_FONT= ("Verdana", 8)

PLACE_VERTICAL_SPACING = 0.06
PLACE_HORIZONTAL_SPACING = 0.1
PLACE_ANCHOR = 'center'
PACK_SIDE = 'top'
style.use("ggplot")

PLAIN_TEXT_FILE = 'plainText.txt'
ENCRYPTED_TEXT_FILE = 'encrypted_file.txt'
DECRYPTED_TEXT_FILE = 'decrypted_file.txt'

LABEL_LIST = [1, 2, 3, 4]
ENCRYPTION_TIME_LIST = [0,0,0,0]
DECRYPTION_TIME_LIST = [0,0,0,0]
INPUT_LEN_LIST = [0,0,0,0]

f = Figure()
a = f.add_subplot(111)
b = a.twinx()

################################################################################
#---------------   Functions
################################################################################

#---------------   Animation function
def animate(i):
    xTicksLabelList = ['RSA Function', 'RSA Lib.', 'DES Function', 'DES Lib.']
    labelList = LABEL_LIST
    encryptionList = ENCRYPTION_TIME_LIST
    decryptionList = DECRYPTION_TIME_LIST
    inputLengthList = INPUT_LEN_LIST
    a.clear()

    N = 4
    ind = np.arange(N)
    width = 0.2
    barEn = a.bar(ind, encryptionList, width, color='b')
    barDe = a.bar(ind+width, decryptionList, width, color='g')
    barLen = b.bar(ind+(2*width), inputLengthList, width, color='r')

    a.set_title('Performance Analysis by Encryption Algorithm')
    a.set_xticks(ind + width)
    a.set_xticklabels(xTicksLabelList)
    a.legend((barEn[0], barDe[0], barLen[0]), ('Ecryption', 'Decryption', 'Input Length'))
    a.set_xlabel('Encryption Algorithm')
    a.set_ylabel('Encryption / Decryption Time (milliseconds)', color='b')
    b.set_ylabel('Input Size (in char len)', color='r')



################################################################################
#---------------   Main Class
################################################################################

class Cryptanalysis(tk.Tk):

    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        tk.Tk.wm_title(self, PROJECT_NAME)
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand = True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}

        for F in (PageMainMenu, PageRSA, PageDES, PageRSAFunction, PageRSALib, PageDESFunction, PageDESLib, PagePerformanceAnalysis, PageHashFunction):

            frame = F(container, self)

            self.frames[F] = frame

            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame(PageMainMenu)

    def show_frame(self, cont):

        frame = self.frames[cont]
        frame.tkraise()

################################################################################
#---------------   Main Menu Page
################################################################################

class PageMainMenu(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self,parent)
        labelTitle = tk.Label(self, text=INTRO_TEXT, font=LARGE_FONT)
        labelTitle.pack(pady=10,padx=10, side=PACK_SIDE)
        labelTitle.place(relx=0.5, rely=1*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)
        
        label2 = tk.Label(self, text="Main Menu", font=LARGE_FONT)
        label2.pack(pady=10,padx=10, side=PACK_SIDE)
        label2.place(relx=0.5, rely=2*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)
        
        button1 = ttk.Button(self, text="RSA", command=lambda: controller.show_frame(PageRSA))
        button1.pack(side=PACK_SIDE)
        button1.place(relx=0.5, rely=5*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        button2 = ttk.Button(self, text="DES", command=lambda: controller.show_frame(PageDES))
        button2.pack(side=PACK_SIDE)
        button2.place(relx=0.5, rely=7*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        paButton = ttk.Button(self, text="Hash Function", command=lambda: controller.show_frame(PageHashFunction))
        paButton.pack(side=PACK_SIDE)
        paButton.place(relx=0.5, rely=9*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        paButton = ttk.Button(self, text="Performance Analysis", command=lambda: controller.show_frame(PagePerformanceAnalysis))
        paButton.pack(side=PACK_SIDE)
        paButton.place(relx=0.5, rely=11*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        quitButton = ttk.Button(self, text="Quit", command=quit)
        quitButton.pack(side=PACK_SIDE)
        quitButton.place(relx=0.5, rely=15*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

################################################################################
#---------------   Hash Function Page
################################################################################

class PageHashFunction(tk.Frame):
    def get_file_checksum(self):
        h = MD5.new()
        chunk_size = 8192
        with open(PLAIN_TEXT_FILE, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if len(chunk) == 0:
                    break
                h.update(chunk)
        return h.hexdigest()


    def hashFunc(self):
        if not os.path.isfile(os.getcwd()+'/'+PLAIN_TEXT_FILE):
            showerror(title='ERROR', message='Plain Text file is missing!')
        else:
            checkSum = self.get_file_checksum()
            if checkSum:
                showinfo(title='Checksum', message='Checksum for the Plain Text file is:\n\n%s'% checkSum)
            else:
                showerror(title='ERROR', message='Checksum could not be calculated for the Plain Text File.')


    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        labelTitle = tk.Label(self, text="Hash Function", font=LARGE_FONT)
        labelTitle.pack(pady=10,padx=10, side=PACK_SIDE)
        labelTitle.place(relx=0.5, rely=1*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)
        
        button1 = ttk.Button(self, text="Main Menu", command=lambda: controller.show_frame(PageMainMenu))
        button1.pack(side=PACK_SIDE)
        button1.place(relx=0.5, rely=2*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        labelCS = tk.Label(self, text="Hash Function to calculate Checksum", font=LARGE_FONT)
        labelCS.pack(pady=10,padx=10, side=PACK_SIDE)
        labelCS.place(relx=0.5, rely=6*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        button2 = ttk.Button(self, text="Get Checksum", command=self.hashFunc)
        button2.pack(side=PACK_SIDE)
        button2.place(relx=0.5, rely=8*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        paButton = ttk.Button(self, text="Performance Analysis", command=lambda: controller.show_frame(PagePerformanceAnalysis))
        paButton.pack(side=PACK_SIDE)
        paButton.place(relx=0.5, rely=15*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)



################################################################################
#---------------   RSA Page
################################################################################

class PageRSA(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        labelTitle = tk.Label(self, text="RSA", font=LARGE_FONT)
        labelTitle.pack(pady=10,padx=10, side=PACK_SIDE)
        labelTitle.place(relx=0.5, rely=1*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        button1 = ttk.Button(self, text="Main Menu", command=lambda: controller.show_frame(PageMainMenu))
        button1.pack(side=PACK_SIDE)
        button1.place(relx=0.5, rely=2*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        button2 = ttk.Button(self, text="RSA Function", command=lambda: controller.show_frame(PageRSAFunction))
        button2.pack(side=PACK_SIDE)
        button2.place(relx=0.5, rely=6*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        button3 = ttk.Button(self, text="RSA Lib.", command=lambda: controller.show_frame(PageRSALib))
        button3.pack(side=PACK_SIDE)
        button3.place(relx=0.5, rely=8*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        paButton = ttk.Button(self, text="Performance Analysis", command=lambda: controller.show_frame(PagePerformanceAnalysis))
        paButton.pack(side=PACK_SIDE)
        paButton.place(relx=0.5, rely=15*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)



class PageRSAFunction(tk.Frame):
    PLAIN_TEXT_FILE_RSAF = PLAIN_TEXT_FILE
    ENCRYPTED_TEXT_FILE_RSAF = 'RSAF_'+ENCRYPTED_TEXT_FILE
    DECRYPTED_TEXT_FILE_RSAF = 'RSAF_'+DECRYPTED_TEXT_FILE
    PUBLIC_KEY_FILE_RSAF = 'RSAF_pubkey.txt'
    PRIVATE_KEY_FILE_RSAF = 'RSAF_privkey.txt'

    #---------------   Function to call makeRsaKeys.py main function to generate Keys
    def runRSAKeyFunction(self):
        pathRSAPubKey = os.getcwd()+'/'+self.PUBLIC_KEY_FILE_RSAF
        pathRSAPrivKey = os.getcwd()+'/'+self.PRIVATE_KEY_FILE_RSAF
        if os.path.isfile(pathRSAPubKey) or os.path.isfile(pathRSAPrivKey):
            showerror(title='ERROR', message='Keys already exist!')
        else:
            makeRsaKeys.main()
            pathRSAPubKey = os.getcwd()+'/'+self.PUBLIC_KEY_FILE_RSAF
            pathRSAPrivKey = os.getcwd()+'/'+self.PRIVATE_KEY_FILE_RSAF
            if os.path.isfile(pathRSAPubKey) and os.path.isfile(pathRSAPrivKey):
                showinfo(title='Done', message='Created keys successfully!')
            else:
                showerror(title='ERROR', message='One of the keys missing!')

    #---------------   Function to call rsaCipher.py Encryption function
    def runRSAEncryptionFunction(self):
        pathPlaintTextFile = os.getcwd()+'/'+self.PLAIN_TEXT_FILE_RSAF
        pathEncryptedFile = os.getcwd()+'/'+self.ENCRYPTED_TEXT_FILE_RSAF
        if not os.path.isfile(pathPlaintTextFile):
            showerror(title='ERROR', message='Plain Text file is missing!')
        elif os.path.isfile(pathEncryptedFile):
            showerror(title='ERROR', message='Encrypted file already exists!')
        else: #get size and time
            msgSize, encryptionTime = rsaCipher.main(mode='encrypt', textFileName=self.PLAIN_TEXT_FILE_RSAF)
            encryptionTime = round((encryptionTime*1000), 2)
            if os.path.isfile(pathEncryptedFile):
                showinfo(title='Encryption successful!', message='Input Message Size : '+str(msgSize)+'\nEncryption Time : '+str(encryptionTime))
                ENCRYPTION_TIME_LIST[0] = encryptionTime
                INPUT_LEN_LIST[0] = msgSize

    #---------------   Function to call rsaCipher.py Decryption function
    def runRSADecryptionFunction(self):
        pathDecryptedFile = os.getcwd()+'/'+self.DECRYPTED_TEXT_FILE_RSAF
        pathEncryptedFile = os.getcwd()+'/'+self.ENCRYPTED_TEXT_FILE_RSAF
        if not os.path.isfile(pathEncryptedFile):
            showerror(title='ERROR', message='No Encrypted file found to Decrypt!')
        elif os.path.isfile(pathDecryptedFile):
            showwarning(title='Warning', message='Another decrypted file already exists!')
        else: #get size and time
            decryptionTime = rsaCipher.main(mode='decrypt', textFileName=self.DECRYPTED_TEXT_FILE_RSAF)
            decryptionTime = round((decryptionTime)*1000, 2)
            if os.path.isfile(pathDecryptedFile):
                showinfo(title='Decryption successful!', message='Decryption Time : '+str(decryptionTime))
                DECRYPTION_TIME_LIST[0] = decryptionTime

#---------------   RSA Function Class : Main function
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        labelTitle = tk.Label(self, text="RSA Function", font=LARGE_FONT)
        labelTitle.pack(pady=10,padx=10, side=PACK_SIDE)
        labelTitle.place(relx=0.5, rely=1*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        button2 = ttk.Button(self, text="RSA", command=lambda: controller.show_frame(PageRSA))
        button2.pack(side=PACK_SIDE)
        button2.place(relx=5*PLACE_HORIZONTAL_SPACING, rely=2*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        button4 = ttk.Button(self, text="Generate RSA Function Keys", command=self.runRSAKeyFunction)
        button4.pack(side=PACK_SIDE)
        button4.place(relx=5*PLACE_HORIZONTAL_SPACING, rely=6*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)
        
        button5 = ttk.Button(self, text="RSA Function Encryption", command=self.runRSAEncryptionFunction)
        button5.pack(side=PACK_SIDE)
        button5.place(relx=5*PLACE_HORIZONTAL_SPACING, rely=8*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)
        
        button6 = ttk.Button(self, text="RSA Function Decryption", command=self.runRSADecryptionFunction)
        button6.pack(side=PACK_SIDE)
        button6.place(relx=5*PLACE_HORIZONTAL_SPACING, rely=10*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        paButton = ttk.Button(self, text="Performance Analysis", command=lambda: controller.show_frame(PagePerformanceAnalysis))
        paButton.pack(side=PACK_SIDE)
        paButton.place(relx=5*PLACE_HORIZONTAL_SPACING, rely=15*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)


class PageRSALib(tk.Frame):
        PLAIN_TEXT_FILE_RSAL = PLAIN_TEXT_FILE
        ENCRYPTED_TEXT_FILE_RSAL = 'RSAL_'+ENCRYPTED_TEXT_FILE
        DECRYPTED_TEXT_FILE_RSAL = 'RSAL_'+DECRYPTED_TEXT_FILE
        RSALKEY = ''
        RSALKEY_FLAG = False
        PUBLIC_KEY_FILE_RSAL = 'RSAL_pubkey.pem'
        PRIVATE_KEY_FILE_RSAL = 'RSAL_privkey.pem'
        ENCRYPTED_DATA = ''

        #---------------   Function to generate keys unsing RSA Lib.
        def initializeRSAKeyLib(self):
            pathRSAPubKey = os.getcwd()+'/'+self.PUBLIC_KEY_FILE_RSAL
            pathRSAPrivKey = os.getcwd()+'/'+self.PRIVATE_KEY_FILE_RSAL
            if os.path.isfile(pathRSAPubKey) or os.path.isfile(pathRSAPrivKey):
                showerror(title='ERROR', message='Keys already exist!')
            else:
                random_generator = Random.new().read
                key = RSA.generate(1024, random_generator)
                self.RSALKEY = key
                self.RSALKEY_FLAG = True
                fo_pub = open(self.PUBLIC_KEY_FILE_RSAL, 'w')
                fo_pub.write((key.publickey().exportKey('PEM')).decode('utf-8'))
                fo_pub.close()
                fo_priv = open(self.PRIVATE_KEY_FILE_RSAL, 'w')
                fo_priv.write((key.exportKey('PEM')).decode('utf-8'))
                fo_priv.close()
                pathRSAPubKey = os.getcwd()+'/'+self.PUBLIC_KEY_FILE_RSAL
                pathRSAPrivKey = os.getcwd()+'/'+self.PRIVATE_KEY_FILE_RSAL
                if os.path.isfile(pathRSAPubKey) and os.path.isfile(pathRSAPrivKey):
                    showinfo(title='Done', message='Created keys successfully!')
                else:
                    showerror(title='ERROR', message='One of the keys missing!')
                


        #---------------   Function to encrypt unsing RSA Lib.
        def runRSAEncryptionLib(self):
            pathPlaintTextFile = os.getcwd()+'/'+self.PLAIN_TEXT_FILE_RSAL
            pathEncryptedFile = os.getcwd()+'/'+self.ENCRYPTED_TEXT_FILE_RSAL
            if self.RSALKEY_FLAG == False:
                showerror(title='ERROR', message='Check Keys!')
            if not os.path.isfile(pathPlaintTextFile):
                showerror(title='ERROR', message='Plain Text file is missing!')
            elif os.path.isfile(pathEncryptedFile):
                showerror(title='ERROR', message='Encrypted file already exists!')
            else:
                fo_pub = open(self.PUBLIC_KEY_FILE_RSAL,'r')
                key = RSA.importKey(fo_pub.read())
                key = self.RSALKEY
                fo_pub.close()
                
                dataToEncryptFile = open(self.PLAIN_TEXT_FILE_RSAL, 'r')
                dataToEncrypt = dataToEncryptFile.read()
                msgSize = len(dataToEncrypt)
                dataToEncryptBytes = dataToEncrypt.encode('utf-8')
                dataToEncryptFile.close()
                public_key = key.publickey()
                encryptionStartTime = time.time()
                encryptedData = public_key.encrypt(dataToEncryptBytes, 32)
                encryptionTime = round((time.time() - encryptionStartTime)*1000, 2)
                self.ENCRYPTED_DATA = encryptedData
                encryptedDataFile = open(self.ENCRYPTED_TEXT_FILE_RSAL, 'w')
                encryptedDataFile.write(str(list(encryptedData)))
                encryptedDataFile.close()
                pathEncryptedFile = os.getcwd()+'/'+self.ENCRYPTED_TEXT_FILE_RSAL
                if os.path.isfile(pathEncryptedFile):
                    showinfo(title='Encryption successful!', message='Input Message Size : '+str(msgSize)+'\nEncryption Time : '+str(encryptionTime))
                    ENCRYPTION_TIME_LIST[1] = encryptionTime
                    INPUT_LEN_LIST[1] = msgSize
                else:
                    showerror(title='ERROR', message='Some ERROR occured!')

        #---------------   Function to decrypt unsing RSA Lib.
        def runRSADecryptionLib(self):
            fo_pub = open(self.PUBLIC_KEY_FILE_RSAL,'r')
            key = RSA.importKey(fo_pub.read())
            fo_pub.close()
            private_key = self.RSALKEY
            pathEncryptedFile = os.getcwd()+'/'+self.ENCRYPTED_TEXT_FILE_RSAL
            pathDecryptedFile = os.getcwd()+'/'+self.DECRYPTED_TEXT_FILE_RSAL
            if not os.path.isfile(pathEncryptedFile):
                showerror(title='ERROR', message='No Encrypted file found to Decrypt!')
            elif os.path.isfile(pathDecryptedFile):
                showerror(title='ERROR', message='Decrypted file already exists!')
            else:
                encryptedDataFile = open(self.ENCRYPTED_TEXT_FILE_RSAL, 'r')
                encryptedData = tuple(encryptedDataFile.read())
                encryptedDataFile.close()
                encryptedData = self.ENCRYPTED_DATA
                decryptionStartTime = time.time()
                decryptedData = private_key.decrypt(encryptedData)
                decryptionTime = round((time.time() - decryptionStartTime)*1000, 2)
                decryptedDataFile = open(self.DECRYPTED_TEXT_FILE_RSAL, 'w')
                decryptedDataFile.write(decryptedData.decode('utf-8'))
                decryptedDataFile.close()
                if os.path.isfile(os.getcwd()+'/'+self.DECRYPTED_TEXT_FILE_RSAL):
                    showinfo(title='Decryption successful!', message='Decryption Time : '+str(decryptionTime))
                    DECRYPTION_TIME_LIST[1] = decryptionTime
                else:
                    showerror(title='ERROR', message='Some ERROR occured!')




#---------------   RSA Lib Class : Main function
        def __init__(self, parent, controller):
            tk.Frame.__init__(self, parent)
            labelTitle = tk.Label(self, text="RSA Lib.", font=LARGE_FONT)
            labelTitle.pack(pady=10,padx=10, side=PACK_SIDE)
            labelTitle.place(relx=0.5, rely=1*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)
            
            button2 = ttk.Button(self, text="RSA", command=lambda: controller.show_frame(PageRSA))
            button2.pack(side=PACK_SIDE)
            button2.place(relx=5*PLACE_HORIZONTAL_SPACING, rely=2*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

            button4 = ttk.Button(self, text="Generate RSA Lib. Keys", command=self.initializeRSAKeyLib)
            button4.pack(side=PACK_SIDE)
            button4.place(relx=5*PLACE_HORIZONTAL_SPACING, rely=6*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)
        
            button5 = ttk.Button(self, text="RSA Lib. Encryption", command=self.runRSAEncryptionLib)
            button5.pack(side=PACK_SIDE)
            button5.place(relx=5*PLACE_HORIZONTAL_SPACING, rely=8*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)
            
            button6 = ttk.Button(self, text="RSA Lib. Decryption", command=self.runRSADecryptionLib)
            button6.pack(side=PACK_SIDE)
            button6.place(relx=5*PLACE_HORIZONTAL_SPACING, rely=10*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

            paButton = ttk.Button(self, text="Performance Analysis", command=lambda: controller.show_frame(PagePerformanceAnalysis))
            paButton.pack(side=PACK_SIDE)
            paButton.place(relx=5*PLACE_HORIZONTAL_SPACING, rely=15*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)



################################################################################
#---------------   DES Page
################################################################################
class PageDES(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        labelTitle = tk.Label(self, text="DES", font=LARGE_FONT)
        labelTitle.pack(pady=10,padx=10, side=PACK_SIDE)
        labelTitle.place(relx=0.5, rely=1*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        button1 = ttk.Button(self, text="Main Menu", command=lambda: controller.show_frame(PageMainMenu))
        button1.pack(side=PACK_SIDE)
        button1.place(relx=0.5, rely=2*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        button2 = ttk.Button(self, text="DES Function", command=lambda: controller.show_frame(PageDESFunction))
        button2.pack(side=PACK_SIDE)
        button2.place(relx=0.5, rely=6*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        button3 = ttk.Button(self, text="DES Lib.", command=lambda: controller.show_frame(PageDESLib))
        button3.pack(side=PACK_SIDE)
        button3.place(relx=0.5, rely=8*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        paButton = ttk.Button(self, text="Performance Analysis", command=lambda: controller.show_frame(PagePerformanceAnalysis))
        paButton.pack(side=PACK_SIDE)
        paButton.place(relx=0.5, rely=15*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)


class PageDESFunction(tk.Frame):
    PLAIN_TEXT_FILE_DESF = PLAIN_TEXT_FILE
    ENCRYPTED_TEXT_FILE_DESF = 'DESF_'+ENCRYPTED_TEXT_FILE
    DECRYPTED_TEXT_FILE_DESF = 'DESF_'+DECRYPTED_TEXT_FILE
    DES_INSTANCE = ''
    DES_INSTANCE_FLAG = False
    DES_KEY = ''
    
    #---------------   Function to call makeRsaKeys.py main function
    def getDesKey(self):
        if len(self.entry1.get()) == 8:
            self.keyDes = self.entry1.get()
            self.keyDesBytes = self.keyDes.encode('UTF-8')
            self.keyDesString = self.keyDesBytes.decode('UTF-8')
            self.DES_KEY = self.keyDesBytes
            showinfo(title='Key Validated Sucessfully!', message='The value entered for the key has been accepted!')
            showwarning(title='Remember your Key!', message='Please make sure to remember or securely store your key, since it will be cleared from the entry box once you click "OK"!\nEntered Key : "%s"'% self.keyDes)
            self.entry1.delete(0,len(self.keyDes))
        else:
            showerror(title='ERROR', message='Length of key entered must be 8 characters only! Please enter again.')

#---------------   Function to call pyDes.des(b'key', pyDes.CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5) to initialize class
    def instantiateClasspyDes(self):
            if self.DES_KEY == '':
                showerror(title='ERROR', message='No Key! Please enter the DES Key first.')
            else:
                self.DES_INSTANCE = pyDes.des(self.DES_KEY, pyDes.CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5)
                self.DES_INSTANCE_FLAG = True


#---------------   Function to Encrypt using DES Function Class
    def runDESFunctionEncryption(self):
        encryptionStartTime = time.time()
        if self.DES_INSTANCE_FLAG == False:
            self.instantiateClasspyDes()
        if self.DES_KEY == '':
            showerror(title='ERROR', message='No Key! Please enter the DES Key first.')
        pathPlaintTextFile = os.getcwd()+'/'+self.PLAIN_TEXT_FILE_DESF
        pathEncryptedFile = os.getcwd()+'/'+self.ENCRYPTED_TEXT_FILE_DESF
        if not os.path.isfile(pathPlaintTextFile):
            showerror(title='ERROR', message='Plain Text file is missing!')
        elif os.path.isfile(pathEncryptedFile):
            showerror(title='ERROR', message='Encrypted file already exists!')
        else:
            dataToEncryptFile = open(CURRENT_DIRECTORY+'/'+self.PLAIN_TEXT_FILE_DESF, 'r')
            dataToEncrypt = dataToEncryptFile.read()
            dataToEncryptFile.close()
            msgSize = len(dataToEncrypt)
            encryptedData = self.DES_INSTANCE.encrypt(dataToEncrypt)
            # write encrypted content to file.
            encryptedDataFile = open(CURRENT_DIRECTORY+'/'+self.ENCRYPTED_TEXT_FILE_DESF, 'wb')
            encryptedDataFile.write(encryptedData)
            encryptedDataFile.close()
            pathEncryptedFile = os.getcwd()+'/'+self.ENCRYPTED_TEXT_FILE_DESF
            if os.path.isfile(pathEncryptedFile):
                encryptionTime = round((time.time() - encryptionStartTime)*1000, 2)
                showinfo(title='Encryption successful!', message='Input Message Size : '+str(msgSize)+'\nEncryption Time : '+str(encryptionTime))
                ENCRYPTION_TIME_LIST[2] = encryptionTime
                INPUT_LEN_LIST[2] = msgSize
            else:
                showerror(title='ERROR', message='Some ERROR occured!')


#---------------   Function to Decrypt using DES Function Class
    def runDESFunctionDecryption(self):
        decryptionStartTime = time.time()
        if self.DES_INSTANCE_FLAG == False:
            self.instantiateClasspyDes()
        if self.DES_KEY == '':
            showerror(title='ERROR', message='No Key! Please enter the DES Key first.')
        pathEncryptedFile = os.getcwd()+'/'+self.ENCRYPTED_TEXT_FILE_DESF
        pathDecryptedFile = os.getcwd()+'/'+self.DECRYPTED_TEXT_FILE_DESF
        if not os.path.isfile(pathEncryptedFile):
            showerror(title='ERROR', message='No Encrypted file found to Decrypt!')
        elif os.path.isfile(pathDecryptedFile):
            showerror(title='ERROR', message='Decrypted file already exists!')
        else:
            dataToDecryptFile = open(CURRENT_DIRECTORY+'/'+self.ENCRYPTED_TEXT_FILE_DESF, 'rb')
            dataToDecrypt = dataToDecryptFile.read()
            dataToDecryptFile.close()
            decryptedDataBytes = self.DES_INSTANCE.decrypt(dataToDecrypt)
            decryptedData = decryptedDataBytes.decode('utf-8')
            # write encrypted content to file.
            decryptedDataFile = open(CURRENT_DIRECTORY+'/'+self.DECRYPTED_TEXT_FILE_DESF, 'w')
            decryptedDataFile.write(decryptedData)
            decryptedDataFile.close()
            pathDecryptedFile = os.getcwd()+'/'+self.DECRYPTED_TEXT_FILE_DESF
            if os.path.isfile(pathDecryptedFile):
                decryptionTime = round((time.time() - decryptionStartTime)*1000, 2)
                showinfo(title='Decryption successful!', message='Decryption Time : '+str(decryptionTime))
                DECRYPTION_TIME_LIST[2] = decryptionTime
            else:
                showerror(title='ERROR', message='Some ERROR occured!')



#---------------   DES Function Class : Main function
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        labelTitle = tk.Label(self, text="DES Function", font=LARGE_FONT)
        labelTitle.pack(pady=10,padx=10, side=PACK_SIDE)
        labelTitle.place(relx=0.5, rely=1*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        buttonDESHome = ttk.Button(self, text="DES", command=lambda: controller.show_frame(PageDES))
        buttonDESHome.pack(side=PACK_SIDE)
        buttonDESHome.place(relx=5*PLACE_HORIZONTAL_SPACING, rely=2*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        labelKey = ttk.Label(self, text="Enter DES Key", font=LARGE_FONT)
        labelKey.pack(pady=10,padx=10, side=PACK_SIDE)
        labelKey.place(relx=4*PLACE_HORIZONTAL_SPACING, rely=6*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        self.entry1 = tk.Entry(self, width=8)
        self.entry1.pack(pady=10,padx=10, side=PACK_SIDE)
        self.entry1.place(relx=5*PLACE_HORIZONTAL_SPACING, rely=6*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)
        
        self.button3 = ttk.Button(self, text="Submit", command=self.getDesKey)
        self.button3.pack(side=PACK_SIDE)
        self.button3.place(relx=6*PLACE_HORIZONTAL_SPACING, rely=6*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        buttonEnFunc = ttk.Button(self, text="DES Function Encryption", command=self.runDESFunctionEncryption)
        buttonEnFunc.pack(side=PACK_SIDE)
        buttonEnFunc.place(relx=5*PLACE_HORIZONTAL_SPACING, rely=8*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        buttonDeFunc = ttk.Button(self, text="DES Function Encryption", command=self.runDESFunctionDecryption)
        buttonDeFunc.pack(side=PACK_SIDE)
        buttonDeFunc.place(relx=5*PLACE_HORIZONTAL_SPACING, rely=10*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        paButton = ttk.Button(self, text="Performance Analysis", command=lambda: controller.show_frame(PagePerformanceAnalysis))
        paButton.pack(side=PACK_SIDE)
        paButton.place(relx=5*PLACE_HORIZONTAL_SPACING, rely=15*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)


class PageDESLib(tk.Frame): #-------- DES CFB mode.
    PLAIN_TEXT_FILE_DESL = PLAIN_TEXT_FILE
    ENCRYPTED_TEXT_FILE_DESL = 'DESL_'+ENCRYPTED_TEXT_FILE
    DECRYPTED_TEXT_FILE_DESL = 'DESL_'+DECRYPTED_TEXT_FILE
    DES_INSTANCE1 = ''
    DES_INSTANCE2 = ''
    DES_INSTANCE_FLAG = False
    DES_KEY = ''

    #---------------   Function to get the DES key from the user
    def getDesKey(self):
        if len(self.entry1.get()) == 8:
            self.keyDes = self.entry1.get()
            self.keyDesBytes = self.keyDes.encode('UTF-8')
            self.keyDesString = self.keyDesBytes.decode('UTF-8')
            self.DES_KEY = self.keyDesBytes
            showinfo(title='Key Validated Sucessfully!', message='The value entered for the key has been accepted!')
            showwarning(title='Remember your Key!', message='Please make sure to remember or securely store your key, since it will be cleared from the entry box once you click "OK"!\nEntered Key : "%s"'% self.keyDes)
            self.entry1.delete(0,len(self.keyDes))
        else:
            showerror(title='ERROR', message='Length of key entered must be 8 characters only! Please enter again.')

    #---------------   Function to create instances od DES for CFB mode.
    def instantiateClassDesLib(self):
        if self.DES_KEY == '':
            showerror(title='ERROR', message='No Key! Please enter the DES Key first.')
        else:
            iv = Random.get_random_bytes(8)
            self.DES_INSTANCE1 = DES.new(self.DES_KEY, DES.MODE_CFB, iv)
            self.DES_INSTANCE2 = DES.new(self.DES_KEY, DES.MODE_CFB, iv)
            self.DES_INSTANCE_FLAG = True


    #---------------   Function to Encrypt using DES Lib. Class
    def runDESLibEncryption(self):
        encryptionStartTime = time.time()
        if self.DES_INSTANCE_FLAG == False:
            self.instantiateClassDesLib()
        if self.DES_KEY == '':
            showerror(title='ERROR', message='No Key! Please enter the DES Key first.')
        pathPlaintTextFile = os.getcwd()+'/'+self.PLAIN_TEXT_FILE_DESL
        pathEncryptedFile = os.getcwd()+'/'+self.ENCRYPTED_TEXT_FILE_DESL
        if not os.path.isfile(pathPlaintTextFile):
            showerror(title='ERROR', message='Plain Text file is missing!')
        elif os.path.isfile(pathEncryptedFile):
            showerror(title='ERROR', message='Encrypted file already exists!')
        else:
            dataToEncryptFile = open(CURRENT_DIRECTORY+'/'+self.PLAIN_TEXT_FILE_DESL, 'r')
            dataToEncrypt = dataToEncryptFile.read()
            dataToEncryptFile.close()
            msgSize = len(dataToEncrypt)
            encryptedData = self.DES_INSTANCE1.encrypt(dataToEncrypt)
            encryptedDataFile = open(CURRENT_DIRECTORY+'/'+self.ENCRYPTED_TEXT_FILE_DESL, 'wb')
            encryptedDataFile.write(encryptedData)
            encryptedDataFile.close()
            pathEncryptedFile = os.getcwd()+'/'+self.ENCRYPTED_TEXT_FILE_DESL
            if os.path.isfile(pathEncryptedFile):
                encryptionTime = round((time.time() - encryptionStartTime)*1000, 2)
                showinfo(title='Encryption successful!', message='Input Message Size : '+str(msgSize)+'\nEncryption Time : '+str(encryptionTime))
                ENCRYPTION_TIME_LIST[3] = encryptionTime
                INPUT_LEN_LIST[3] = msgSize
            else:
                showerror(title='ERROR', message='Some ERROR occured!')


    #---------------   Function to Decrypt using DES Lib Class
    def runDESLibDecryption(self):
        decryptionStartTime = time.time()
        if self.DES_INSTANCE_FLAG == False:
            self.instantiateClassDesLib()
        if self.DES_KEY == '':
            showerror(title='ERROR', message='No Key! Please enter the DES Key first.')
        pathEncryptedFile = os.getcwd()+'/'+self.ENCRYPTED_TEXT_FILE_DESL
        pathDecryptedFile = os.getcwd()+'/'+self.DECRYPTED_TEXT_FILE_DESL
        if not os.path.isfile(pathEncryptedFile):
            showerror(title='ERROR', message='No Encrypted file found to Decrypt!')
        elif os.path.isfile(pathDecryptedFile):
            showerror(title='ERROR', message='Decrypted file already exists!')
        else:
            dataToDecryptFile = open(CURRENT_DIRECTORY+'/'+self.ENCRYPTED_TEXT_FILE_DESL, 'rb')
            dataToDecrypt = dataToDecryptFile.read()
            dataToDecryptFile.close()
            decryptedDataBytes = self.DES_INSTANCE2.decrypt(dataToDecrypt)
            decryptedData = decryptedDataBytes.decode('utf-8')
            decryptedDataFile = open(CURRENT_DIRECTORY+'/'+self.DECRYPTED_TEXT_FILE_DESL, 'w')
            decryptedDataFile.write(decryptedData)
            decryptedDataFile.close()
            pathDecryptedFile = os.getcwd()+'/'+self.DECRYPTED_TEXT_FILE_DESL
            if os.path.isfile(pathDecryptedFile):
                decryptionTime = round((time.time() - decryptionStartTime)*1000, 2)
                showinfo(title='Decryption successful!', message='Decryption Time : '+str(decryptionTime))
                DECRYPTION_TIME_LIST[3] = decryptionTime
            else:
                showerror(title='ERROR', message='Some ERROR occured!')


#---------------   DES Lib Class : Main function
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        labelTitle = tk.Label(self, text="DES Lib.", font=LARGE_FONT)
        labelTitle.pack(pady=10,padx=10, side=PACK_SIDE)
        labelTitle.place(relx=0.5, rely=1*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        buttonDESHome = ttk.Button(self, text="DES", command=lambda: controller.show_frame(PageDES))
        buttonDESHome.pack(side=PACK_SIDE)
        buttonDESHome.place(relx=5*PLACE_HORIZONTAL_SPACING, rely=2*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        labelKey = ttk.Label(self, text="Enter DES Key", font=LARGE_FONT)
        labelKey.pack(pady=10,padx=10, side=PACK_SIDE)
        labelKey.place(relx=4*PLACE_HORIZONTAL_SPACING, rely=6*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)
        
        self.entry1 = tk.Entry(self, width=8)
        self.entry1.pack(pady=10,padx=10, side=PACK_SIDE)
        self.entry1.place(relx=5*PLACE_HORIZONTAL_SPACING, rely=6*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)
        
        self.button3 = ttk.Button(self, text="Submit", command=self.getDesKey)
        self.button3.pack(side=PACK_SIDE)
        self.button3.place(relx=6*PLACE_HORIZONTAL_SPACING, rely=6*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)
        
        buttonEnFunc = ttk.Button(self, text="DES Lib. Encryption", command=self.runDESLibEncryption)
        buttonEnFunc.pack(side=PACK_SIDE)
        buttonEnFunc.place(relx=5*PLACE_HORIZONTAL_SPACING, rely=8*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)
        
        buttonDeFunc = ttk.Button(self, text="DES Lib. Encryption", command=self.runDESLibDecryption)
        buttonDeFunc.pack(side=PACK_SIDE)
        buttonDeFunc.place(relx=5*PLACE_HORIZONTAL_SPACING, rely=10*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        paButton = ttk.Button(self, text="Performance Analysis", command=lambda: controller.show_frame(PagePerformanceAnalysis))
        paButton.pack(side=PACK_SIDE)
        paButton.place(relx=5*PLACE_HORIZONTAL_SPACING, rely=15*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)




################################################################################
#---------------   Performance Analysis Page
################################################################################

class PagePerformanceAnalysis(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        labelTitle = tk.Label(self, text="Performance Analysis", font=LARGE_FONT)
        labelTitle.pack(pady=10,padx=10, side=PACK_SIDE)

        buttonMainMenu = ttk.Button(self, text="Main Menu", command=lambda: controller.show_frame(PageMainMenu))
        buttonMainMenu.pack(side=PACK_SIDE)

        canvas = FigureCanvasTkAgg(f, self)
        canvas.show()
        canvas.get_tk_widget().pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)

        toolbar = NavigationToolbar2TkAgg(canvas, self)
        toolbar.update()
        canvas._tkcanvas.pack(side=tk.TOP, fill=tk.BOTH, expand=True)


################################################################################
#---------------   Main
################################################################################


def main():
    app = Cryptanalysis()
    app.geometry("1280x720")
    ani = animation.FuncAnimation(f, animate, interval=1000)
    app.mainloop()

if __name__ == '__main__':
    main()



