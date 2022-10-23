#!/usr/bin/python3
# NZ.UA HELPER
#
#
# Copyright (C) 2022 Maksim Petrenko
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
#
# WARNINGS:
# Not work in the interactive interpreter



"""NZ.UA Helper
This application is for topic plans uploading to electronic journals
portal https://nz.ua.
"""


# Standard library
import concurrent.futures
import csv
import html.parser
import http.cookiejar
import json
import os
import time
import tkinter
from tkinter import ttk, messagebox
import traceback
import urllib.error
import urllib.parse
import urllib.request


# Constants
# URLs
BASE_URL = "https://nz.ua"
LOGIN_URL = "https://nz.ua/login"
#LOGOUT_URL = "https://nz.ua/logout"
JOURNAL_LIST_URL = "https://nz.ua/journal/list"
JOURNAL_FILTER = "\
https://nz.ua/journal/list?class_id=all&predmet_id=all&personal_id={}"
JOURNAL_URL = "https://nz.ua/journal/index?journal={}"
SCHEDULE_URL = "\
https://nz.ua/journal/add-edit-home-task?schedule={}&journal={}"
# Parameters
LOGIN = "LoginForm[login]"
PASSWORD = "LoginForm[password]"
LESSON_TOPIC = "OsvitaScheduleReal[lesson_topic]"
LESSON_NUMBER = "OsvitaScheduleReal[lesson_number_in_plan]"
HOMETASK = "OsvitaScheduleReal[hometask]"
HOMETASK_TO = "OsvitaScheduleReal[hometask_to]"
# UI
FONT_NORM = ("DejaVu Sans", 10, "normal")
FONT_HEAD = ("DejaVu Sans", 10, "bold")
FONT_CAPT = ("DejaVu Sans", 12, "bold")
TITLE = "Помічник NZ.UA"
COPYRIGHT="Максим Петренко \u00A9 2022"
LOGINWARNING = "Неправильне\nім'я користувача або пароль!"
LOGINERROR = "Сталася помилка.\nДетальніше див. error.log."
START = "\n{} Запуск...\n> {}, стор. {}\n"
OUTPUT = "{0} Готово!\n> {1[0]} уроків з {1[1]} за {1[2]}\n"
FORMSWARNING = "Деякі уроки не відвантажилися, спробуйте ще раз.\n"
FORMSERROR = "{} Помилка.\nДетальніше див. error.log.\n"
ERROR = "{}: {} \nДетальніше див. error.log."


# Global
user = ""
journals = {}
if "Плани" in os.listdir():
    files = sorted([f for f in os.listdir("Плани") if f.endswith(".csv")])
else:
    files = []


########################################################################
# BACKEND

# HTTP opener
opener = urllib.request.build_opener()
opener.addheaders = [("User-agent", "Mozilla/5.0")]
cookie = http.cookiejar.CookieJar()
opener.add_handler(urllib.request.HTTPCookieProcessor(cookie))


# HTML parsers

class _LinkParser(html.parser.HTMLParser):
    """Internal link parser."""
    def __init__(self, attr=""):
        super().__init__()
        self._attr = attr
        self.links = []
    def handle_starttag(self, tag, attrs):
        attrs_d = dict(attrs)
        if attrs_d.get("href") and self._attr in attrs_d.get("class", ""):
            self.links.append(attrs_d.get("href"))


class _FormParser(html.parser.HTMLParser):
    """Internal form parser."""
    def __init__(self):
        super().__init__()
        self._last_tag = ""
        self._last_name = ""
        self.forms = []
        self.option_val = {}
        self.option_txt = {}
    def handle_starttag(self, tag, attrs):
        self._last_tag = tag
        name = dict(attrs).get("name", "")
        value = dict(attrs).get("value", "")
        if tag == "form":
            self.forms.append({})
        elif tag in ("input", "select"):
            self.forms[-1][name] = value
            if tag == "select":
                self.option_val[name] = []
                self.option_txt[name] = []
                self._last_name = name
        elif tag == "option":
            self.option_val[self._last_name].append(value)
    def handle_data(self, data):
        if self._last_tag == "option" and data.strip():
            self.option_txt[self._last_name].append(data.strip())


class _SpanParser(html.parser.HTMLParser):
    """Internal span parser."""
    def __init__(self, attr=""):
        super().__init__()
        self._attr = attr
        self._last_tag = ""
        self._last_attr = ""
        self.spans = []
    def handle_starttag(self, tag, attrs):
        self._last_tag = tag
        self._last_attr = dict(attrs).get("class", "")
    def handle_data(self, data):
        if data.strip():
            if self._last_tag == "span" and self._attr in self._last_attr:
                self.spans.append(data)


class _TableParser(html.parser.HTMLParser):
    """Internal table parser."""
    def __init__(self):
        super().__init__()
        self._last_tag = ""
        self._last_attr = ""
        self._last_data = ""
        self.subjects = []
        self.hrefs = []
    def handle_starttag(self, tag, attrs):
        self._last_tag = tag
        self._last_attr = dict(attrs).get("class")
        if self._last_tag == "table":
            self.subjects.append([])
            self.hrefs.append([])
        elif self._last_attr == "gray-button-2":
            self.hrefs[-1].append(dict(attrs).get("href"))
    def handle_data(self, data):
        if data.strip():
            if self._last_tag == "td":
                self._last_data = data
            elif self._last_attr == "gray-button-2":
                self.subjects[-1].append(f"{self._last_data} {data}")


# Functions

def write_log():
    """Write error log."""
    with open("error.log", "a") as LOG:
        LOG.write("{}\n{}\n".format("#"*72,
                                    time.strftime("%Y-%m-%d %H:%M:%S")))
        traceback.print_exc(file=LOG)


def log_into(login="", password=""):
    """Log into NZ.UA and return user name and journals dict."""
    try:
        # GET
        login_page = opener.open(LOGIN_URL)
        login_parser = _FormParser()
        login_parser.feed(login_page.read().decode("utf-8"))
        login_form = login_parser.forms[0].copy()
        login_form[LOGIN] = login
        login_form[PASSWORD] = password
        login_data = urllib.parse.urlencode(login_form).encode("ascii")
        # POST
        login_resp = opener.open(LOGIN_URL, login_data)
        user_parser = _SpanParser("ui-title")
        user_parser.feed(login_resp.read().decode("utf-8"))
        name = user_parser.spans[0] if user_parser.spans else ""
        # GET
        journlst_resp = opener.open(JOURNAL_LIST_URL)
        journlst_page = journlst_resp.read().decode("utf-8")
        filter_parser = _FormParser()
        filter_parser.feed(journlst_page)
        if "personal_id" in filter_parser.forms[1]:
            short_name = " ".join(name.split()[:2])
            teacher_dict = dict(zip(filter_parser.option_txt["personal_id"],
                                    filter_parser.option_val["personal_id"]))
            url = JOURNAL_FILTER.format(teacher_dict[short_name])
            # GET
            journlst_resp = opener.open(url)
            journlst_page = journlst_resp.read().decode("utf-8")
        journlst_parser = _TableParser()
        journlst_parser.feed(journlst_page)
        return name, dict(zip(journlst_parser.subjects[0],
                              journlst_parser.hrefs[0]))
    except Exception as error:
        write_log()
        if isinstance(error, urllib.error.HTTPError):
            return Exception(str(error))
        return error


def submit_form(url="", data={}):
    """Submit one form and return status."""
    try:
        # GET
        schedule_page = opener.open(BASE_URL+url)
        # Form
        schedule_parser = _FormParser()
        schedule_parser.feed(schedule_page.read().decode("utf-8"))
        schedule_form = schedule_parser.forms[0].copy()
        schedule_form[LESSON_TOPIC] = data["ТЕМА УРОКУ"]
        schedule_form[LESSON_NUMBER] = data["№ УРОКУ"]
        schedule_form[HOMETASK] = data["ДОМАШНЄ ЗАВДАННЯ"]
        schedule_form[HOMETASK_TO] = schedule_parser.option_val[HOMETASK_TO][0]
        schedule_data = urllib.parse.urlencode(schedule_form).encode("ascii")
        # POST
        schedule_resp = opener.open(BASE_URL+url, schedule_data)
        # Status
        status = json.load(schedule_resp).get("status")
        return status
    except Exception as error:
        write_log()
        if isinstance(error, urllib.error.HTTPError):
            return Exception(str(error))
        return error


def submit_multiforms(url="", page=0, filename="", lesson="1"):
    """Submit multiple forms and return results."""
    try:
        start = time.time()
        # GET
        journ_page = opener.open(BASE_URL+url+"&page="+str(page))
        journ_parser = _LinkParser("dz-edit modal-box")
        journ_parser.feed(journ_page.read().decode("utf-8"))
        task_links = journ_parser.links
        with open("Плани"+os.sep+filename, encoding="utf-8",
                  newline="") as FILE:
            schedule_csv = [*csv.DictReader(FILE)]
        home_tasks = schedule_csv[int(lesson)-1:]
        # Concurrent execution
        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
            status = [*executor.map(submit_form, task_links, home_tasks)]
        stop = time.time()
        timedelta = time.strftime("%M хв. %S сек.", time.gmtime(stop-start))
        return status.count("success"), len(task_links), timedelta
    except Exception as error:
        write_log()
        if isinstance(error, urllib.error.HTTPError):
            return Exception(str(error))
        return error


# Wrapper functions

def login_subproc(arg):
    """Run login subprocess."""
    future = subproc.submit(log_into, *arg)
    future.add_done_callback(login_callback)


def login_callback(future):
    """Login subprocess callback."""
    global user, journals
    result = future.result()
    if isinstance(result, Exception):
        login_win.showerror()
    else:
        (user, journals) = result
        if user:
            login_win.stop()
        else:
            login_win.showwarning()


def forms_subproc(arg):
    """Run forms subprocess."""
    future = subproc.submit(submit_multiforms, *arg)
    future.add_done_callback(forms_callback)


def forms_callback(future):
    """Forms subprocess callback."""
    result = future.result()
    if isinstance(result, Exception):
        forms_win.showerror()
    else:
        forms_win.stop(result)
        if result[0] < result[1]:
            forms_win.showwarning()


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
        self.style.configure("TButton", font="TkCaptionFont",
                             padding=8)
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

    try:
        subproc = concurrent.futures.ProcessPoolExecutor(max_workers=1)
        forms_win = FormsWindow()
        login_win = LoginWindow()
        forms_win.withdraw()
        forms_win.mainloop()

    except Exception as error:
        write_log()
        messagebox.showerror("Помилка", ERROR.format(type(error), error))

##    finally: # ?
##        subproc.shutdown()


