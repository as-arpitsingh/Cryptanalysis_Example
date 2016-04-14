# The code for changing pages was derived from: http://stackoverflow.com/questions/7546050/switch-between-two-frames-in-tkinter
# License: http://creativecommons.org/licenses/by-sa/3.0/
# Referenced from: https://pythonprogramming.net/tkinter-depth-tutorial-making-actual-program/	

import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2TkAgg
from matplotlib.figure import Figure
import matplotlib.animation as animation
from matplotlib import style
from RSA import makeRsaKeys, rsaCipher


import tkinter as tk
from tkinter import ttk

INTRO_TEXT='Replace with the Intro Text'
PROJECT_NAME='Cryptanalysis'
LARGE_FONT= ("Verdana", 12)
style.use("ggplot")

f = Figure(figsize=(12,6), dpi=100)
a = f.add_subplot(111)


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

    
def runRSAKeyFunction():
    makeRsaKeys.main()

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

        for F in (PageHome, PageRSA, PageDES, PagePerformanceAnalysis):

            frame = F(container, self)

            self.frames[F] = frame

            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame(PageHome)

    def show_frame(self, cont):

        frame = self.frames[cont]
        frame.tkraise()

        
class PageHome(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self,parent)
        label1 = tk.Label(self, text=INTRO_TEXT, font=LARGE_FONT)
        label1.pack(pady=10,padx=10)

        label2 = tk.Label(self, text="HOME", font=("Helvetica", 16))
        label2.pack(pady=50,padx=30)

        button = ttk.Button(self, text="RSA",
                            command=lambda: controller.show_frame(PageRSA))
        button.pack()

        button2 = ttk.Button(self, text="DES",
                            command=lambda: controller.show_frame(PageDES))
        button2.pack()

        button3 = ttk.Button(self, text="Performance Analysis",
                            command=lambda: controller.show_frame(PagePerformanceAnalysis))
        button3.pack()


class PageRSA(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="RSA", font=LARGE_FONT)
        label.pack(pady=10,padx=10)

        button1 = ttk.Button(self, text="Back to Home",
                            command=lambda: controller.show_frame(PageHome))
        button1.pack()

        button2 = ttk.Button(self, text="DES",
                            command=lambda: controller.show_frame(PageDES))
        button2.pack()
          
        button3 = ttk.Button(self, text="Performance Analysis",
                             command=lambda: controller.show_frame(PagePerformanceAnalysis))
        button3.pack()


class PageDES(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="DES", font=LARGE_FONT)
        label.pack(pady=10,padx=10)

        button1 = ttk.Button(self, text="Back to Home",
                            command=lambda: controller.show_frame(PageHome))
        button1.pack()

        button2 = ttk.Button(self, text="RSA",
                            command=lambda: controller.show_frame(PageRSA))
        button2.pack()
          
        button3 = ttk.Button(self, text="Performance Analysis",
                               command=lambda: controller.show_frame(PagePerformanceAnalysis))
        button3.pack()


class PagePerformanceAnalysis(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="Performance Analysis", font=LARGE_FONT)
        label.pack(pady=10,padx=10)

        button1 = ttk.Button(self, text="Back to Home",
                            command=lambda: controller.show_frame(PageHome))
        button1.pack()

        canvas = FigureCanvasTkAgg(f, self)
        canvas.show()
        canvas.get_tk_widget().pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)

        toolbar = NavigationToolbar2TkAgg(canvas, self)
        toolbar.update()
        canvas._tkcanvas.pack(side=tk.TOP, fill=tk.BOTH, expand=True)


app = Cryptanalysis()
ani = animation.FuncAnimation(f, animate, interval=1000)
app.mainloop()