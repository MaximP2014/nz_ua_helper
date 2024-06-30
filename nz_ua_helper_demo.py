#!/usr/bin/python3
# NZ.UA HELPER
# GUI demo
#
#
# Copyright (C) 2022 Maksim Petrenko



# Standard library
import concurrent.futures
#import datetime
import time
import tkinter
from tkinter import ttk


# Constants
FONT_NORM = ("DejaVu Sans", 10, "normal")
FONT_HEAD = ("DejaVu Sans", 10, "bold")
FONT_CAPT = ("DejaVu Sans", 12, "bold")
TITLE = "Помічник NZ.UA demo"
COPYRIGHT="Максим Петренко \u00A9 2022"
LOGINWARNING = "Неправильне\nім'я користувача або пароль!"
LOGINERROR = "Сталася помилка.\nДетальніше див. error.log."
START = "\n{} Запуск...\n> {}, стор. {}\n"
OUTPUT = "{0} Готово!\n> {1[0]} уроків з {1[1]} за {1[2]}\n"
FORMSWARNING = "Деякі уроки не відвантажилися, спробуйте ще раз.\n"
FORMSERROR = "{} Помилка.\nДетальніше див. error.log.\n"

# Global
user = ""
journals = {}
files = ["Хімія 7.csv", "Захист України (Основи медичних знань) 11.csv"]


########################################################################
# BACKEND
# Wrapper functions

# Login window
def login_subproc(arg):
    """Run login subprocess (thread)."""
    future = subproc.submit(login_test, arg)
    future.add_done_callback(login_callback)

def login_test(arg):
    """Login test function."""
    time.sleep(2)
    user = "Петренко Максим Леонідович"
    journals = {"Хімія 7-А": "https://nz.ua",
                "Захист України (Основи медичних знань) 11-Б": "https://nz.ua"}
    return user, journals

def login_callback(future):
    """Login subprocess (thread) callback."""
    global user, journals
    (user, journals) = future.result()
    login_win.stop()

# Forms window
def forms_subproc(arg):
    """Run forms subprocess (thread)."""
    future = subproc.submit(forms_test, arg)
    future.add_done_callback(forms_callback)

def forms_test(arg):
    """Forms test function."""
    start = time.time() # datetime.datetime.now()
    time.sleep(5)
    stop = time.time() # datetime.datetime.now()
    # timedelta = "{} хв. {} сек.".format(*divmod((stop-start).seconds, 60))
    timedelta = time.strftime("%M хв. %S сек.", time.gmtime(stop-start))
    return 20, 20, timedelta

def forms_callback(future):
    """Forms subprocess (thread) callback."""
    result = future.result()
    forms_win.stop(result)


########################################################################
# FRONTEND


class FormsWindow(tkinter.Tk):
    """Forms main window."""

    def __init__(self):
        super().__init__()
        # Window manager
        self.title(TITLE)
        self.geometry("+{}+{}".format(self.winfo_screenwidth() // 2 - 200,
                                      self.winfo_screenheight() // 2 - 250))
        self.resizable(False, False)
        # Data
        self.journ_var = tkinter.StringVar()
        self.journ_var.trace_add("write",
            lambda *args: self.journcombo.config(style="RO.TCombobox"))
        self.page_var = tkinter.IntVar()
        self.page_var.trace_add("write",
            lambda *args: self.pagecombo.config(style="RO.TCombobox"))
        self.file_var = tkinter.StringVar()
        self.file_var.trace_add("write",
            lambda *args: self.filecombo.config(style="RO.TCombobox"))
        self.lesson_var = tkinter.StringVar()
        self.lesson_var.trace_add("write",
            lambda *args: self.lessonentry.config(style="TEntry"))
        # Style
        self.style = ttk.Style()
        self.style.theme_use("clam") # !
        ## compatability
        self.config(bg=self.style.lookup("TFrame", "background"))
        self.style.configure("TLabelframe.Label", font=FONT_NORM)
        self.style.configure("TLabel", font=FONT_NORM)
        self.option_add("*TCombobox*Listbox.font", FONT_NORM)
        ##
        self.style.configure("Warning.TEntry", fieldbackground="pink")
        self.style.configure("TButton", padding=8, font=FONT_CAPT)
        self.style.configure("TProgressbar", background="#4a6984")
        # self.style.map("TCombobox") !
        self.style.map("RO.TCombobox",
                       fieldbackground=[("readonly", "focus", "#4a6984")],
                       foreground=[("readonly", "focus", "#ffffff"),
                                   ("disabled", "#999999")])
        self.style.map("WarningRO.TCombobox",
                       fieldbackground=[("focus", "#4a6984"),
                                        ("readonly", "pink")])
        # Widgets
        self.frame = ttk.Frame(self)
        self.frame.pack(padx=8, pady=8)
        # User section
        self.userfrm = ttk.Labelframe(self.frame, text="Користувач")
        self.userfrm.pack(pady=4, fill="both")
        self.userlbl = ttk.Label(self.userfrm, text="Користувач",
                                 font=FONT_HEAD, justify="left")
        self.userlbl.pack(side="left", padx=4)
        # Journal section
        self.journfrm = ttk.Labelframe(self.frame, text="Журнал")
        self.journfrm.pack(pady=4, fill="both")
        self.journcombo = ttk.Combobox(self.journfrm, values=[],
            textvariable=self.journ_var, width=44, state="readonly",
            style="RO.TCombobox", font=FONT_NORM)            
        self.journcombo.pack(padx=4, pady=4, fill="both")
        self.pagefrm = ttk.Frame(self.journfrm)
        self.pagefrm.pack(padx=4, pady=4, fill="both")
        self.pagelbl = ttk.Label(self.pagefrm,
            text="Номер сторінки електронного журналу")
        self.pagelbl.pack(side="left", anchor="w")
        self.pagecombo = ttk.Combobox(self.pagefrm, values=(1, 2, 3, 4, 5),
            textvariable=self.page_var, width=3, state="readonly",
            style="RO.TCombobox", font=FONT_NORM)
        self.pagecombo.pack(side="right")
        # Schedule section
        self.filefrm = ttk.Labelframe(self.frame, text="Тематичний план")
        self.filefrm.pack(pady=4, fill="both")
        self.filecombo = ttk.Combobox(self.filefrm, values=[],
            textvariable=self.file_var, width=44, state="readonly",
            style="RO.TCombobox", font=FONT_NORM)
        self.filecombo.pack(padx=4, pady=4, fill="both")
        self.lessonfrm = ttk.Frame(self.filefrm)
        self.lessonfrm.pack(padx=4, pady=4, fill="both")
        self.lessonlbl = ttk.Label(self.lessonfrm,
            text="Номер стартового уроку сторінки за планом")
        self.lessonlbl.pack(side="left", anchor="w")
        self.lessonvalid = self.register(
            lambda act, char: act=="0" or (char.isdigit() and len(char)<=3))
        self.lessonentry = ttk.Entry(self.lessonfrm, width=5, validate="key",
            validatecommand=(self.lessonvalid, "%d", "%P"),
            textvariable=self.lesson_var, font=FONT_NORM)
        self.lessonentry.pack(side="right")
        # Button
        self.button = ttk.Button(self.frame, text="Відвантажити на NZ.UA",
                                 command=self.start)
        self.button.pack(pady=8)
        # Status section
        self.statusfrm = ttk.Labelframe(self.frame, text="Статус виконання")
        self.statusfrm.pack(pady=4, fill="both")
        self.progress = ttk.Progressbar(self.statusfrm, mode="indeterminate")
        self.progress.pack(padx=4, pady=4, fill="both")
        self.scrollfrm = ttk.Frame(self.statusfrm)
        self.scrollfrm.pack(padx=4, fill="both")
        self.text = tkinter.Text(self.scrollfrm, width=44, height=7,
                                 wrap="word", takefocus=0, insertontime=0,
                                 font=("DejaVu Sans Mono", 10, "normal"))
        self.text.tag_configure("error", foreground="red")
        self.text.tag_configure("warning", foreground="purple")
        self.text.pack(side="left", fill="both", expand=True)
        self.text.bind("<KeyPress>", lambda e: "break")
        self.scroll = ttk.Scrollbar(self.scrollfrm)
        self.scroll.pack(side="right", fill="y")
        self.text.config(yscrollcommand=self.scroll.set)
        self.scroll.config(command=self.text.yview)

    def set(self):
        """Set initial values."""
        self.userlbl.config(text=user)
        self.journcombo.config(values=[*journals.keys()])
        self.filecombo.config(values=files)

    def start(self):
        """Get data and start processing."""
        data = (journals.get(self.journ_var.get()), self.page_var.get(),
                self.file_var.get(), self.lesson_var.get())
        if all(data):
            if int(self.lesson_var.get()) in range(1, 176):
                self.journcombo.config(state="disabled")
                self.pagecombo.config(state="disabled")
                self.filecombo.config(state="disabled")
                self.lessonentry.config(state="disabled")
                self.button.config(state="disabled")
                self.progress.start()
                self.text.insert("end", START.format(
                    time.strftime("%d.%m.%Y %H:%M:%S"), self.journ_var.get(),
                    self.page_var.get()))
                self.text.see("end")
                # Run subprocess
                forms_subproc(data)
            else:
                self.lessonentry.config(style="Warning.TEntry")
        else:
            if not self.journ_var.get():
                self.journcombo.config(style="WarningRO.TCombobox")
            if not self.page_var.get():
                self.pagecombo.config(style="WarningRO.TCombobox")
            if not self.file_var.get():
                self.filecombo.config(style="WarningRO.TCombobox")
            if not self.lesson_var.get():
                self.lessonentry.config(style="Warning.TEntry")
            elif int(self.lesson_var.get()) not in range(1, 176):
                self.lessonentry.config(style="Warning.TEntry")

    def stop(self, output):
        """Stop processing and show result."""
        self.progress.stop()
        self.text.insert("end", OUTPUT.format(
            time.strftime("%d.%m.%Y %H:%M:%S"), output))
        self.text.see("end")
        self.journ_var.set("")
        self.page_var.set(0)
        self.file_var.set("")
        self.lesson_var.set("")
        self.journcombo.config(state="readonly")
        self.pagecombo.config(state="readonly")
        self.filecombo.config(state="readonly")
        self.lessonentry.config(state="normal")
        self.button.config(state="normal")

    def showwarning(self):
        """Show warning."""
        self.text.insert("end", FORMSWARNING, ("warning"))
        self.text.see("end")

    def showerror(self):
        """Show error."""
        self.progress.stop()
        self.text.insert("end", FORMSERROR.format(
            time.strftime("%d.%m.%Y %H:%M:%S")), ("error"))
        self.text.see("end")
        self.journcombo.config(state="readonly")
        self.pagecombo.config(state="readonly")
        self.filecombo.config(state="readonly")
        self.lessonentry.config(state="normal")
        self.button.config(state="normal")


class LoginWindow(tkinter.Toplevel, FormsWindow):
    """Login dialog window."""

    def __init__(self):
        super().__init__()
        # Window manager
        self.title(TITLE)
        self.geometry("+{}+{}".format(self.winfo_screenwidth() // 2 - 137,
                                      self.winfo_screenheight() // 2 - 114))
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", forms_win.destroy)
        # Data
        self.login = tkinter.StringVar()
        self.login.trace_add("write",
            lambda *args: self.logentry.config(style="TEntry"))
        self.password = tkinter.StringVar()
        self.password.trace_add("write",
            lambda *args: self.passentry.config(style="TEntry"))
        # Style
        self.style = ttk.Style()
        ## compatability
        self.config(bg=self.style.lookup("TFrame", "background"))
        ##
        # Widgets
        self.frame = ttk.Frame(self)
        self.frame.pack(padx=8, pady=8)
        self.label = ttk.Label(self.frame, text="Авторизація\nв NZ.UA",
            font=FONT_CAPT, justify="center", anchor="center")
        self.label.pack(pady=8, fill="both")
        self.entryvalid = self.register(
            lambda act, char: act == "0" or char.isascii())
        # Login section
        self.logframe = ttk.Labelframe(self.frame, text="Логін")
        self.logframe.pack(pady=4)
        self.logentry = ttk.Entry(self.logframe, width=30, validate="key",
            validatecommand=(self.entryvalid, "%d", "%P"),
            textvariable=self.login, font=FONT_NORM)
        self.logentry.pack(padx=4, pady=4)
        # Password section
        self.passframe = ttk.Labelframe(self.frame, text="Пароль")
        self.passframe.pack(pady=4)
        self.passentry = ttk.Entry(self.passframe, width=30, show="\u25CF",
            validate="key", validatecommand=(self.entryvalid, "%d", "%P"),
            textvariable=self.password, font=FONT_NORM)
        self.passentry.pack(padx=4, pady=4)
        self.passentry.bind("<Return>", self.start)
        self.passentry.bind("<KP_Enter>", self.start)
        # Copyright section
        self.copyright = ttk.Label(self.frame, text=COPYRIGHT,
                                   font=("DejaVu Sans", 9, "normal"))
        self.copyright.pack(pady=4, anchor="e")

    def start(self, event):
        """Get data and start processing."""
        data = (self.login.get(), self.password.get())
        if all(data):
            self.logentry.config(state="disabled")
            self.passentry.config(state="disabled")
            # Run subprocess
            login_subproc(data)
        else:
            if not self.login.get():
                self.logentry.config(style="Warning.TEntry")
            if not self.password.get():
                self.passentry.config(style="Warning.TEntry")

    def stop(self):
        """Stop processing and show main window."""
        self.login.set("")
        self.password.set("")
        forms_win.set()
        forms_win.text.insert("end", "{} Очікування...\n".format(
            time.strftime("%d.%m.%Y %H:%M:%S")))
        forms_win.deiconify()
        self.destroy()

    def showwarning(self):
        """Show warning."""
        self.label.config(text=LOGINWARNING, font=FONT_NORM,
                          foreground="red")
        self.logentry.config(state="normal")
        self.passentry.config(state="normal")

    def showerror(self):
        """Show error."""
        self.label.config(text=LOGINERROR, font=FONT_HEAD,
                          foreground="red")
        self.logentry.config(state="normal")
        self.passentry.config(state="normal")


########################################################################
# EXECUTION


if __name__ == "__main__":
    subproc = concurrent.futures.ThreadPoolExecutor()
    forms_win = FormsWindow()
    login_win = LoginWindow()
    forms_win.withdraw()
    forms_win.mainloop()
    subproc.shutdown()


