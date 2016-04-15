# The code for changing pages was derived from: http://stackoverflow.com/questions/7546050/switch-between-two-frames-in-tkinter
# License: http://creativecommons.org/licenses/by-sa/3.0/
# Referenced from: https://pythonprogramming.net/tkinter-depth-tutorial-making-actual-program/	

################################################################################
#---------------   importing dependencies
################################################################################

import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2TkAgg
from matplotlib.figure import Figure
import matplotlib.animation as animation
from matplotlib import style
import tkinter as tk
from tkinter import ttk
import urllib
import json
import pandas as pd
from matplotlib import pyplot as plt
import numpy as np
import makeRsaKeys, rsaCipher

################################################################################
#---------------   initializing global variables
################################################################################

INTRO_TEXT = 'CS685 Computer Security'
PROJECT_NAME = 'Cryptanalysis'
LARGE_FONT = ("Helvetica", 16)
MID_FONT= ("Verdana", 12)
NORM_FONT= ("Verdana", 10)
SMALL_FONT= ("Verdana", 8)

style.use("ggplot")
#f = Figure(figsize=(12,6), dpi=100)
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

        for F in (PageHome, PageRSAHome, PageDESHome, PageRSA, PageRSALib, PageDES, PageDESLib, PagePerformanceAnalysis):

            frame = F(container, self)

            self.frames[F] = frame

            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame(PageHome)

    def show_frame(self, cont):

        frame = self.frames[cont]
        frame.tkraise()

################################################################################
#---------------   Launch/Home Page
################################################################################

class PageHome(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self,parent)
        label1 = tk.Label(self, text=INTRO_TEXT, font=MID_FONT)
        label1.pack(pady=10,padx=10, side='top')
        
        label2 = tk.Label(self, text="HOME", font=MID_FONT)
        label2.pack(pady=10,padx=10, side='top')
        
        button1 = ttk.Button(self, text="RSA Home", command=lambda: controller.show_frame(PageRSAHome))
        button1.pack()

        button2 = ttk.Button(self, text="DES Home", command=lambda: controller.show_frame(PageDESHome))
        button2.pack()

        paButton = ttk.Button(self, text="Performance Analysis", command=lambda: controller.show_frame(PagePerformanceAnalysis))
        paButton.pack()

        quitButton = ttk.Button(self, text="Quit", command=quit)
        quitButton.pack()

################################################################################
#---------------   RSA Page
################################################################################

class PageRSAHome(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="RSA Home", font=LARGE_FONT)
        label.pack(pady=10,padx=10)

        button1 = ttk.Button(self, text="Back to Home", command=lambda: controller.show_frame(PageHome))
        button1.pack()

        button2 = ttk.Button(self, text="RSA", command=lambda: controller.show_frame(PageRSA))
        button2.pack()
        
        button3 = ttk.Button(self, text="RSA Lib.", command=lambda: controller.show_frame(PageRSALib))
        button3.pack()
    

        paButton = ttk.Button(self, text="Performance Analysis", command=lambda: controller.show_frame(PagePerformanceAnalysis))
        paButton.pack()



class PageRSA(tk.Frame):

    #---------------   Function to call makeRsaKeys.py main function
    def runRSAKeyFunction():
        makeRsaKeys.main()

    #---------------   Function to call rsaCipher.py Encryption function
    def runRSAEncryptionFunction():
        pass

    #---------------   Function to call rsaCipher.py Decryption function
    def runRSADecryptionFunction():
        pass

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="RSA", font=LARGE_FONT)
        label.pack(pady=10,padx=10)

        button1 = ttk.Button(self, text="Back to Home", command=lambda: controller.show_frame(PageHome))
        button1.pack()

        button2 = ttk.Button(self, text="RSA Home", command=lambda: controller.show_frame(PageRSAHome))
        button2.pack()

        paButton = ttk.Button(self, text="Performance Analysis", command=lambda: controller.show_frame(PagePerformanceAnalysis))
        paButton.pack()


class PageRSALib(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="RSA Lib.", font=LARGE_FONT)
        label.pack(pady=10,padx=10)

        button1 = ttk.Button(self, text="Back to Home", command=lambda: controller.show_frame(PageHome))
        button1.pack()

        button2 = ttk.Button(self, text="RSA Home", command=lambda: controller.show_frame(PageRSAHome))
        button2.pack()

        paButton = ttk.Button(self, text="Performance Analysis", command=lambda: controller.show_frame(PagePerformanceAnalysis))
        paButton.pack()



################################################################################
#---------------   DES Page
################################################################################
class PageDESHome(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="DES Home", font=LARGE_FONT)
        label.pack(pady=10,padx=10)

        button1 = ttk.Button(self, text="Back to Home", command=lambda: controller.show_frame(PageHome))
        button1.pack()

        button2 = ttk.Button(self, text="DES", command=lambda: controller.show_frame(PageDES))
        button2.pack()

        button3 = ttk.Button(self, text="DES Lib.", command=lambda: controller.show_frame(PageDESLib))
        button3.pack()
        
        paButton = ttk.Button(self, text="Performance Analysis", command=lambda: controller.show_frame(PagePerformanceAnalysis))
        paButton.pack()


class PageDES(tk.Frame):
    
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="DES", font=LARGE_FONT)
        label.pack(pady=10,padx=10)

        button1 = ttk.Button(self, text="Back to Home", command=lambda: controller.show_frame(PageHome))
        button1.pack()

        button2 = ttk.Button(self, text="DES Home", command=lambda: controller.show_frame(PageDESHome))
        button2.pack()

        paButton = ttk.Button(self, text="Performance Analysis", command=lambda: controller.show_frame(PagePerformanceAnalysis))
        paButton.pack()


class PageDESLib(tk.Frame):
    
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="DES Lib.", font=LARGE_FONT)
        label.pack(pady=10,padx=10)
        
        button1 = ttk.Button(self, text="Back to Home", command=lambda: controller.show_frame(PageHome))
        button1.pack()

        button2 = ttk.Button(self, text="DES Home", command=lambda: controller.show_frame(PageDESHome))
        button2.pack()

        paButton = ttk.Button(self, text="Performance Analysis", command=lambda: controller.show_frame(PagePerformanceAnalysis))
        paButton.pack()




################################################################################
#---------------   Performance Analysis Page
################################################################################

class PagePerformanceAnalysis(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="Performance Analysis", font=LARGE_FONT)
        label.pack(pady=10,padx=10)

        button1 = ttk.Button(self, text="Back to Home", command=lambda: controller.show_frame(PageHome))
        button1.pack()

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



