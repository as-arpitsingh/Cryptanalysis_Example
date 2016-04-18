# The code for changing pages was derived from: http://stackoverflow.com/questions/7546050/switch-between-two-frames-in-tkinter
# License: http://creativecommons.org/licenses/by-sa/3.0/
# Referenced from: https://pythonprogramming.net/tkinter-depth-tutorial-making-actual-program/	

################################################################################
#---------------   importing dependencies
################################################################################
#-------- get Bytes --> 'Sting'.encode('UTF-8')
#-------- get String --> 'Bytes'.decode('UTF-8')

import matplotlib, os, re, time, pdb
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2TkAgg
from matplotlib.figure import Figure
import matplotlib.animation as animation
from matplotlib import style
import tkinter as tk
from tkinter import ttk
#import json
from matplotlib import pyplot as plt
import makeRsaKeys, rsaCipher, pyDes
from tkinter.messagebox import *


################################################################################
#---------------   initializing global variables
################################################################################

CURRENT_DIRECTORY = os.getcwd()
print (CURRENT_DIRECTORY)
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



f = Figure()
a = f.add_subplot(111)

################################################################################
#---------------   Functions
################################################################################

#---------------   Animation function
def animate(i):
    pullData = open("performanceAnalysis.text","r").read()
    dataList = pullData.split('\n')
    xList = []
    yList = []
    for eachLine in dataList:
        if len(eachLine) > 1:
            x, y = eachLine.split(',')
            xList.append(int(x))
            yList.append(int(y))

    a.clear()
    a.plot(xList, yList)


################################################################################
#---------------   Main Class
################################################################################

class Cryptanalysis(tk.Tk):

    def __init__(self, *args, **kwargs):
        
        tk.Tk.__init__(self, *args, **kwargs)

        #tk.Tk.iconbitmap(self, default="clienticon.ico")
        tk.Tk.wm_title(self, PROJECT_NAME)
        
        
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand = True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}

        for F in (PageMainMenu, PageRSA, PageDES, PageRSAFunction, PageRSALib, PageDESFunction, PageDESLib, PagePerformanceAnalysis):

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
        label1 = tk.Label(self, text=INTRO_TEXT, font=LARGE_FONT)
        label1.pack(pady=10,padx=10, side=PACK_SIDE)
        label1.place(relx=0.5, rely=1*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)
        
        label2 = tk.Label(self, text="Main Menu", font=LARGE_FONT)
        label2.pack(pady=10,padx=10, side=PACK_SIDE)
        label2.place(relx=0.5, rely=2*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)
        
        button1 = ttk.Button(self, text="RSA", command=lambda: controller.show_frame(PageRSA))
        button1.pack(side=PACK_SIDE)
        button1.place(relx=0.5, rely=3*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        button2 = ttk.Button(self, text="DES", command=lambda: controller.show_frame(PageDES))
        button2.pack(side=PACK_SIDE)
        button2.place(relx=0.5, rely=4*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        paButton = ttk.Button(self, text="Performance Analysis", command=lambda: controller.show_frame(PagePerformanceAnalysis))
        paButton.pack(side=PACK_SIDE)
        paButton.place(relx=0.5, rely=5*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        quitButton = ttk.Button(self, text="Quit", command=quit)
        quitButton.pack(side=PACK_SIDE)
        quitButton.place(relx=0.5, rely=6*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

################################################################################
#---------------   RSA Page
################################################################################

class PageRSA(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label1 = tk.Label(self, text="RSA", font=LARGE_FONT)
        label1.pack(pady=10,padx=10, side=PACK_SIDE)
        label1.place(relx=0.5, rely=1*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        button1 = ttk.Button(self, text="Main Menu", command=lambda: controller.show_frame(PageMainMenu))
        button1.pack(side=PACK_SIDE)
        button1.place(relx=0.5, rely=2*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        button2 = ttk.Button(self, text="RSA Function", command=lambda: controller.show_frame(PageRSAFunction))
        button2.pack(side=PACK_SIDE)
        button2.place(relx=0.5, rely=3*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)
        
        button3 = ttk.Button(self, text="RSA Lib.", command=lambda: controller.show_frame(PageRSALib))
        button3.pack(side=PACK_SIDE)
        button3.place(relx=0.5, rely=4*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        paButton = ttk.Button(self, text="Performance Analysis", command=lambda: controller.show_frame(PagePerformanceAnalysis))
        paButton.pack(side=PACK_SIDE)
        paButton.place(relx=0.5, rely=5*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)



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
            print ('Keys already exist!')
            #askokcancel("Warning", "This will delete stuff")
            showerror(title='ERROR', message='Keys already exist!')
        else:
            makeRsaKeys.main()
            pathRSAPubKey = os.getcwd()+'/'+self.PUBLIC_KEY_FILE_RSAF
            pathRSAPrivKey = os.getcwd()+'/'+self.PRIVATE_KEY_FILE_RSAF
            if os.path.isfile(pathRSAPubKey) or os.path.isfile(pathRSAPrivKey):
                showinfo(title='Done', message='Created keys successfully!')

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
            if os.path.isfile(pathEncryptedFile):
                showinfo(title='Encryption successful!', message='Input Message Size : '+str(msgSize)+'\nEncryption Time : '+str(encryptionTime))
                print ('encryption time: '+str(encryptionTime))

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
            if os.path.isfile(pathDecryptedFile):
                showinfo(title='Decryption successful!', message='Decryption Time : '+str(decryptionTime))

#---------------   RSA Function Class : Main function
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label1 = tk.Label(self, text="RSA Function", font=LARGE_FONT)
        label1.pack(pady=10,padx=10, side=PACK_SIDE)
        label1.place(relx=0.5, rely=1*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        button1 = ttk.Button(self, text="Main Menu", command=lambda: controller.show_frame(PageMainMenu))
        button1.pack(side=PACK_SIDE)
        button1.place(relx=2*PLACE_HORIZONTAL_SPACING, rely=2*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        button2 = ttk.Button(self, text="RSA", command=lambda: controller.show_frame(PageRSA))
        button2.pack(side=PACK_SIDE)
        button2.place(relx=4*PLACE_HORIZONTAL_SPACING, rely=2*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        paButton = ttk.Button(self, text="Performance Analysis", command=lambda: controller.show_frame(PagePerformanceAnalysis))
        paButton.pack(side=PACK_SIDE)
        paButton.place(relx=6*PLACE_HORIZONTAL_SPACING, rely=2*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        button4 = ttk.Button(self, text="Make RSA Keys", command=self.runRSAKeyFunction)
        button4.pack(side=PACK_SIDE)
        button4.place(relx=2*PLACE_HORIZONTAL_SPACING, rely=3*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)
        
        button5 = ttk.Button(self, text="RSA Function Encryption", command=self.runRSAEncryptionFunction)
        button5.pack(side=PACK_SIDE)
        button5.place(relx=4*PLACE_HORIZONTAL_SPACING, rely=3*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)
        
        button6 = ttk.Button(self, text="RSA Function Decryption", command=self.runRSADecryptionFunction)
        button6.pack(side=PACK_SIDE)
        button6.place(relx=6*PLACE_HORIZONTAL_SPACING, rely=3*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)



class PageRSALib(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label1 = tk.Label(self, text="RSA Lib.", font=LARGE_FONT)
        label1.pack(pady=10,padx=10, side=PACK_SIDE)
        label1.place(relx=0.5, rely=1*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        button1 = ttk.Button(self, text="Main Menu", command=lambda: controller.show_frame(PageMainMenu))
        button1.pack(side=PACK_SIDE)
        button1.place(relx=2*PLACE_HORIZONTAL_SPACING, rely=2*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        button2 = ttk.Button(self, text="RSA", command=lambda: controller.show_frame(PageRSA))
        button2.pack(side=PACK_SIDE)
        button2.place(relx=4*PLACE_HORIZONTAL_SPACING, rely=2*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        paButton = ttk.Button(self, text="Performance Analysis", command=lambda: controller.show_frame(PagePerformanceAnalysis))
        paButton.pack(side=PACK_SIDE)
        paButton.place(relx=6*PLACE_HORIZONTAL_SPACING, rely=2*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)



################################################################################
#---------------   DES Page
################################################################################
class PageDES(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label1 = tk.Label(self, text="DES", font=LARGE_FONT)
        label1.pack(pady=10,padx=10, side=PACK_SIDE)
        label1.place(relx=0.5, rely=1*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        button1 = ttk.Button(self, text="Main Menu", command=lambda: controller.show_frame(PageMainMenu))
        button1.pack(side=PACK_SIDE)
        button1.place(relx=0.5, rely=2*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        button2 = ttk.Button(self, text="DES Function", command=lambda: controller.show_frame(PageDESFunction))
        button2.pack(side=PACK_SIDE)
        button2.place(relx=0.5, rely=3*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        button3 = ttk.Button(self, text="DES Lib.", command=lambda: controller.show_frame(PageDESLib))
        button3.pack(side=PACK_SIDE)
        button3.place(relx=0.5, rely=4*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)
        
        paButton = ttk.Button(self, text="Performance Analysis", command=lambda: controller.show_frame(PagePerformanceAnalysis))
        paButton.pack(side=PACK_SIDE)
        paButton.place(relx=0.5, rely=5*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)


class PageDESFunction(tk.Frame):
    PLAIN_TEXT_FILE_DESF = PLAIN_TEXT_FILE
    ENCRYPTED_TEXT_FILE_DESF = 'DESF_'+ENCRYPTED_TEXT_FILE
    DECRYPTED_TEXT_FILE_DESF = 'DESF_'+DECRYPTED_TEXT_FILE
    DES_INSTANCE_FLAG = False
    DES_KEY = ''
    
    #---------------   Function to call makeRsaKeys.py main function
    def getDesKey(self):
        if len(self.entry1.get()) == 8:
            self.keyDes = self.entry1.get()
            self.keyDesBytes = self.keyDes.encode('UTF-8')
            self.keyDesString = self.keyDesBytes.decode('UTF-8')
            self.DES_KEY = self.keyDesBytes
            print (self.DES_KEY)
            showinfo(title='Key Validated Sucessfully!', message='The value entered for the key has been accepted!')
            showwarning(title='Remember your Key!', message='Please make sure to remember or securely store your key, since it will be cleared from the entry box once you click "OK"!\nEntered Key : "%s"'% self.keyDes)
            self.entry1.delete(0,len(self.keyDes))
        else:
            showerror(title='ERROR', message='Length of key entered must be 8 characters only! Please enter again.')

#---------------   Function to call pyDes.des(b'key', pyDes.CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5) to initialize class
    def instantiateClasspyDes(self):
        pathPlaintTextFile = os.getcwd()+'/'+self.PLAIN_TEXT_FILE_DESF
        pathEncryptedFile = os.getcwd()+'/'+self.ENCRYPTED_TEXT_FILE_DESF
        if not os.path.isfile(pathPlaintTextFile):
            showerror(title='ERROR', message='Plain Text file is missing!')
        elif os.path.isfile(pathEncryptedFile):
            showerror(title='ERROR', message='Encrypted file already exists!')
        else: #get size and time
            if self.DES_KEY == '':
                print ('No Key!')
            else:
                desInstance = pyDes.des(self.DES_KEY, pyDes.CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5)
                self.DES_INSTANCE_FLAG = True
        print (self.DES_KEY, self.DES_INSTANCE_FLAG)


#---------------   Function to Encrypt using DES Function Class
    def runDESFunctionEncryption(self):
        encryptionStartTime = time.time()
        if self.DES_INSTANCE_FLAG == False:
            self.instantiateClasspyDes()
        if self.DES_KEY == '':
            print ('No Key!')
        else:
            print ('its encryption time')
            #get size and time
            pdb.set_trace()
            dataToEncryptFile = open(CURRENT_DIRECTORY+'/'+self.PLAIN_TEXT_FILE_DESF, 'r')
            dataToEncrypt = dataToEncryptFile.read()
            msgSize = len(dataToEncrypt)
            encryptedData = self.desInstance.encrypt(dataToEncrypt)
            dataToEncryptFile.close()
            # write encrypted content to file.
            encryptedDataFile = open(CURRENT_DIRECTORY+'/'+self.ENCRYPTED_TEXT_FILE_DESF, 'w')
            self.encryptedDataFile.write(self.encryptedData)
            self.encryptedDataFile.close()
            pathEncryptedFile = os.getcwd()+'/'+self.ENCRYPTED_TEXT_FILE_DESF
            if os.path.isfile(self.pathEncryptedFile):
                encryptionTime = time.time() - self.encryptionStartTime
                showinfo(title='Encryption successful!', message='Input Message Size : '+str(self.msgSize)+'\nEncryption Time : '+str(self.encryptionTime))
            else:
                showerror(title='ERROR', message='Some ERROR occured!')


#---------------   Function to Decrypt using DES Function Class
    def runDESFunctionDecryption(self):
        print ('Lets decrypt now')


#---------------   DES Function Class : Main function
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label1 = tk.Label(self, text="DES Function", font=LARGE_FONT)
        label1.pack(pady=10,padx=10, side=PACK_SIDE)
        label1.place(relx=0.5, rely=1*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)


        button1 = ttk.Button(self, text="Main Menu", command=lambda: controller.show_frame(PageMainMenu))
        button1.pack(side=PACK_SIDE)
        button1.place(relx=2*PLACE_HORIZONTAL_SPACING, rely=2*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        button2 = ttk.Button(self, text="DES", command=lambda: controller.show_frame(PageDES))
        button2.pack(side=PACK_SIDE)
        button2.place(relx=4*PLACE_HORIZONTAL_SPACING, rely=2*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        paButton = ttk.Button(self, text="Performance Analysis", command=lambda: controller.show_frame(PagePerformanceAnalysis))
        paButton.pack(side=PACK_SIDE)
        paButton.place(relx=6*PLACE_HORIZONTAL_SPACING, rely=2*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)


        label2 = ttk.Label(self, text="Enter DES Key", font=LARGE_FONT)
        label2.pack(pady=10,padx=10, side=PACK_SIDE)
        label2.place(relx=2*PLACE_HORIZONTAL_SPACING, rely=4*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        self.entry1 = tk.Entry(self, width=8)
        self.entry1.pack(pady=10,padx=10, side=PACK_SIDE)
        self.entry1.place(relx=4*PLACE_HORIZONTAL_SPACING, rely=4*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)
        
        self.button3 = ttk.Button(self, text="Submit", command=self.getDesKey)
        self.button3.pack(side=PACK_SIDE)
        self.button3.place(relx=6*PLACE_HORIZONTAL_SPACING, rely=4*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)


        button2 = ttk.Button(self, text="DES Function Encryption", command=self.runDESFunctionEncryption)
        button2.pack(side=PACK_SIDE)
        button2.place(relx=2*PLACE_HORIZONTAL_SPACING, rely=6*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        paButton = ttk.Button(self, text="DES Function Encryption", command=self.runDESFunctionDecryption)
        paButton.pack(side=PACK_SIDE)
        paButton.place(relx=6*PLACE_HORIZONTAL_SPACING, rely=6*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)






class PageDESLib(tk.Frame):
    
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label1 = tk.Label(self, text="DES Lib.", font=LARGE_FONT)
        label1.pack(pady=10,padx=10, side=PACK_SIDE)
        label1.place(relx=0.5, rely=1*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)
        
        button1 = ttk.Button(self, text="Main Menu", command=lambda: controller.show_frame(PageMainMenu))
        button1.pack(side=PACK_SIDE)
        button1.place(relx=2*PLACE_HORIZONTAL_SPACING, rely=2*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        button2 = ttk.Button(self, text="DES", command=lambda: controller.show_frame(PageDES))
        button2.pack(side=PACK_SIDE)
        button2.place(relx=4*PLACE_HORIZONTAL_SPACING, rely=2*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)

        paButton = ttk.Button(self, text="Performance Analysis", command=lambda: controller.show_frame(PagePerformanceAnalysis))
        paButton.pack(side=PACK_SIDE)
        paButton.place(relx=6*PLACE_HORIZONTAL_SPACING, rely=2*PLACE_VERTICAL_SPACING, anchor=PLACE_ANCHOR)




################################################################################
#---------------   Performance Analysis Page
################################################################################

class PagePerformanceAnalysis(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="Performance Analysis", font=LARGE_FONT)
        label.pack(pady=10,padx=10, side=PACK_SIDE)

        button1 = ttk.Button(self, text="Main Menu", command=lambda: controller.show_frame(PageMainMenu))
        button1.pack(side=PACK_SIDE)

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



