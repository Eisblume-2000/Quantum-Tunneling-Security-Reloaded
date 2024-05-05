import base64
import pathlib
import random
import tkinter as tk
from tkinter import filedialog
import hashlib
import os
from time import sleep
import cryptography.fernet
import zipfile as zf
import requests
import json
from datetime import datetime
from cryptography.fernet import Fernet
import webbrowser
from random import shuffle
from screeninfo import get_monitors

#TODO holy shit add fuzcking lines it has been 6 months how am i supposed to know what these todos mean?

#TODO: Encrypted Local Chat
#TODO: error handling like no salt or pwd
#TODO: get file name
#TODO: text encryption realtime
#TODO make it so main menu doesnt go in foreground when selecting file, maybe minimize and maximize when opening new window or closing, use global vari to stop min max switch
#TODO switch kill buttons to command kill maybe?

class SettinsGUI:

    def __init__(self):
        self.SettinsGUI = tk.Tk()
        self.SettinsGUI.geometry("500x700")
        self.SettinsGUI.resizable(0, 0)
        self.SettinsGUI.title("Settings")
        self.SettinsGUI['background'] = '#202124'

        self.welcomelabel = tk.Label(self.SettinsGUI, text="Here you can change your settings", fg="#c7c6c3", font=("Arial", 20), bg="#202124")
        self.welcomelabel.place(y=50, relx=0.5, anchor="center", width=700)

        r = open(r"C:\ProgramData\Quantum-Tunneling-Security-Reloaded\config.json", "r")
        self.config = r.read()
        r.close()

        self.config = json.loads(self.config)
        self.outputdir = self.config["Outputdir"]
        self.Apikey = self.config["QApiKey"]

        self.currentoutput = tk.Label(self.SettinsGUI, text="Current output directory", fg="#c7c6c3", font=("Arial", 15), bg="#202124")
        self.currentoutput.place(y=150, relx=0.5, anchor="center", width=700)

        self.currentoutput_entry = tk.Entry(self.SettinsGUI, fg="#c7c6c3", bg="#3c3d42", font=("Arial", 15), width=30)
        self.currentoutput_entry.insert(0, self.outputdir)
        self.currentoutput_entry.place(y=225, relx=0.5, anchor="center", width=400)

        self.apikey_label = tk.Label(self.SettinsGUI, text="API Key for Quantum Passwords", fg="#c7c6c3", font=("Arial", 15), bg="#202124")
        self.apikey_label.place(y=300, relx=0.5, anchor="center", width=700)

        self.apikey_entry = tk.Entry(self.SettinsGUI, fg="#c7c6c3", bg="#3c3d42", font=("Arial", 20), width=30)
        self.apikey_entry.insert(0, self.Apikey)
        self.apikey_entry.place(y=375, relx=0.5, anchor="center", width=400)

        self.buttonframe1 = tk.Frame(self.SettinsGUI)
        self.buttonframe1.columnconfigure(0, weight=1)
        self.buttonframe1.columnconfigure(1, weight=1)

        self.buttonsave = tk.Button(self.buttonframe1, text="Save", fg="#c7c6c3", font=("Arial", 15), width=20, height=2, bg="#3c3d42", command=self.save)
        self.buttonsave.grid(row=0, column=0)

        self.buttonback = tk.Button(self.buttonframe1, text="Back", fg="#c7c6c3", font=("Arial", 15), width=20, height=2, bg="#3c3d42", command=self.back)
        self.buttonback.grid(row=0, column=1)

        self.buttonframe1.place(y=650, relx=0.5, anchor="center")

        self.SettinsGUI.mainloop()

    def back(self):
        self.SettinsGUI.destroy()

    def save(self):
        self.outputdir = str(self.currentoutput_entry.get())
        self.Apikey = str(self.apikey_entry.get())

        self.config["Outputdir"] = self.outputdir
        self.config["QApiKey"] = self.Apikey

        self.config = json.dumps(self.config)

        r = open(r"C:\ProgramData\Quantum-Tunneling-Security-Reloaded\config.json","w")
        r.write(self.config)
        r.close()

class OperationGUI:

    def __init__(self, currentoperation, label1text, prompt1text, filedialog_or_text_input, filedialog_button_text, second_input_row, numofbutton,button1, button2, button1_command, button2_command):

        self.OperationGUI = tk.Tk()
        if "DISPLAY2" in str(get_monitors()):
            self.OperationGUI.geometry("900x800+" + str(random.randint(1940, 2900)) + "+" + str(random.randint(0, 200)))
        else:
             self.OperationGUI.geometry("900x800+900+" + str(random.randint(0,200)))
        self.OperationGUI.resizable(0, 0)
        self.OperationGUI.title(currentoperation)
        self.OperationGUI['background'] = '#202124'

        self.welcomelabel = tk.Label(self.OperationGUI, text=label1text, fg="#c7c6c3", font=("Arial", 20), bg="#202124")
        self.welcomelabel.place(y=50, relx=0.5, anchor="center", width=700)

        self.prompt1 = tk.Label(self.OperationGUI, text=prompt1text, fg="#c7c6c3", font=("Arial", 20), bg="#202124")
        self.prompt1.place(y=150, relx=0.5, anchor="center", width=700)

        if filedialog_or_text_input == "textinput":
            self.inputentry = tk.Entry(self.OperationGUI, fg="#c7c6c3", bg="#3c3d42", font=("Arial", 20))
            self.inputentry.place(y=200, relx=0.5, anchor="center", height=50, width=700)

            if second_input_row == True:
                self.prompt3 = tk.Label(self.OperationGUI, text="Password", fg="#c7c6c3", font=("Arial", 15), bg="#202124")
                self.prompt3.place(y=275, relx=0.5, anchor="center", width=700)

                self.encrypt_decrypt_password = self.encrypt_decrypt_password_entry = tk.Entry(self.OperationGUI, fg="#c7c6c3", bg="#3c3d42", font=("Arial", 20))
                self.encrypt_decrypt_password_entry.place(y=305, relx=0.5, anchor="center", width=700)

                self.prompt4 = tk.Label(self.OperationGUI, text="Salt", fg="#c7c6c3", font=("Arial", 15), bg="#202124")
                self.prompt4.place(y=345, relx=0.5, anchor="center", width=700)

                self.encrypt_decrypt_salt = self.encrypt_decrypt_salt_entry = tk.Entry(self.OperationGUI, fg="#c7c6c3", bg="#3c3d42", font=("Arial", 20))
                self.encrypt_decrypt_salt_entry.place(y=375, relx=0.5, anchor="center", width=700)

        if filedialog_or_text_input == "fileinput":
            self.buttonfileinput = tk.Button(self.OperationGUI, text=filedialog_button_text, fg="#c7c6c3", font=("Arial", 15), width=20, height=2, bg="#3c3d42", command=self.filegraber)
            self.buttonfileinput.place(y=200, relx=0.5, anchor="center")

            self.prompt2 = tk.Label(self.OperationGUI, text="Selected File: ", fg="#c7c6c3", font=("Arial", 15), bg="#202124")
            self.prompt2.place(y=275, relx=0.5, anchor="center", width=700)

            if second_input_row == True:
                self.prompt3 = tk.Label(self.OperationGUI, text="Password", fg="#c7c6c3", font=("Arial", 15), bg="#202124")
                self.prompt3.place(y=350, relx=0.5, anchor="center", width=700)

                self.encrypt_decrypt_password = self.encrypt_decrypt_password_entry = tk.Entry(self.OperationGUI, fg="#c7c6c3", bg="#3c3d42", font=("Arial", 20))
                self.encrypt_decrypt_password_entry.place(y=380, relx=0.5, anchor="center", width=700)

                self.prompt4 = tk.Label(self.OperationGUI, text="Salt", fg="#c7c6c3", font=("Arial", 15), bg="#202124")
                self.prompt4.place(y=410, relx=0.5, anchor="center", width=700)

                self.encrypt_decrypt_salt = self.encrypt_decrypt_salt_entry = tk.Entry(self.OperationGUI, fg="#c7c6c3", bg="#3c3d42", font=("Arial", 20))
                self.encrypt_decrypt_salt_entry.place(y=440, relx=0.5, anchor="center", width=700)

        self.buttonframe1 = tk.Frame(self.OperationGUI)
        self.buttonframe1.columnconfigure(0, weight=1)
        self.buttonframe1.columnconfigure(1, weight=1)

        button1_command = "self." + button1_command

        self.buttonvar1 = tk.Button(self.buttonframe1, text=button1, fg="#c7c6c3", font=("Arial", 15), width=20, height=2, bg="#3c3d42", command=eval(button1_command))
        self.buttonvar1.grid(row=0, column=0)

        if numofbutton == 2:
            button2_command = "self." + button2_command

            self.buttonvar2 = tk.Button(self.buttonframe1, text=button2, fg="#c7c6c3", font=("Arial", 15), width=20, height=2, bg="#3c3d42", command=eval(button2_command))
            self.buttonvar2.grid(row=0, column=1)

        if filedialog_or_text_input == "fileinput":
            if second_input_row == True:
                self.buttonframe1.place(y=510, relx=0.5, anchor="center")

            elif second_input_row == False:
                self.buttonframe1.place(y=435, relx=0.5, anchor="center")

        if filedialog_or_text_input == "textinput":
            self.buttonframe1.place(y=435, relx=0.5, anchor="center")

        self.buttonframe2 = tk.Frame(self.OperationGUI)
        self.buttonframe2.columnconfigure(0, weight=1)
        self.buttonframe2.columnconfigure(1, weight=1)

        self.buttonclose = tk.Button(self.buttonframe2, text="Close", fg="#c7c6c3", font=("Arial", 15), width=20, height=2, bg="#3c3d42", command=self.close)
        self.buttonclose.grid(row=0, column=0)

        self.buttonback = tk.Button(self.buttonframe2, text="Back", fg="#c7c6c3", font=("Arial", 15), width=20, height=2, bg="#3c3d42", command=self.back)
        self.buttonback.grid(row=0, column=1)

        self.buttonframe2.place(y=750, relx=0.5, anchor="center")

        self.OperationGUI.mainloop()

    def filegraber(self):
        self.filepath = tk.filedialog.askopenfilename()
        self.prompt2 = tk.Label(self.OperationGUI, text="Selected File: \n" + self.filepath, fg="#c7c6c3", font=("Arial", 15), bg="#202124")
        self.prompt2.place(y=275, relx=0.5, anchor="center", width=700)

    def text_encryption(self):
        salt = str(self.encrypt_decrypt_salt.get())
        salt = salt.encode()

        pwd = str(self.encrypt_decrypt_password.get())

        key = base64.urlsafe_b64encode(hashlib.pbkdf2_hmac("sha256", pwd.encode("utf-8"), salt, 10000))
        f = Fernet(key)

        message = str(self.inputentry.get())

        if message != "":
            encryptedmesage = f.encrypt(message.encode())
            encryptedmesage = encryptedmesage.decode()

            self.outputprompt = tk.Text(self.OperationGUI, height=10, borderwidth=0, fg="#c7c6c3", font=("Arial", 15), bg="#202124")
            self.outputprompt.insert(1.0, encryptedmesage)
            self.outputprompt.place(y=585, relx=0.5, anchor="center")

        elif message == "":
            self.outputprompt = tk.Text(self.OperationGUI, height=10, borderwidth=0, fg="#c7c6c3", font=("Arial", 15), bg="#202124")
            self.outputprompt.insert(1.0, "Pls insert a message")
            self.outputprompt.place(y=585, relx=0.5, anchor="center")

    def text_decryption(self):
        salt = str(self.encrypt_decrypt_salt.get())
        salt = salt.encode()

        pwd = str(self.encrypt_decrypt_password.get())

        key = base64.urlsafe_b64encode(hashlib.pbkdf2_hmac('sha256', pwd.encode('utf-8'), salt, 10000))
        f = Fernet(key)

        message = str(self.inputentry.get())

        if message != "":
            try:
                decryptedmesage = f.decrypt(message.encode())
                decryptedmesage = decryptedmesage.decode()

                self.outputprompt = tk.Text(self.OperationGUI, height=10, borderwidth=0, fg="#c7c6c3", font=("Arial", 15), bg="#202124")
                self.outputprompt.insert(1.0, decryptedmesage)
                self.outputprompt.place(y=585, relx=0.5, anchor="center")

            except cryptography.fernet.InvalidToken or cryptography.fernet.InvalidSignature:
                self.prompterror = tk.Label(self.OperationGUI, text="Password or salt is wrong", fg="#c7c6c3",font=("Arial", 15), bg="#202124")
                self.prompterror.place(y=585, relx=0.5, anchor="center", width=700)

        elif message == "":
            self.outputprompt = tk.Text(self.OperationGUI, height=10, borderwidth=0, fg="#c7c6c3", font=("Arial", 15), bg="#202124")
            self.outputprompt.insert(1.0, "Pls insert a message")
            self.outputprompt.place(y=585, relx=0.5, anchor="center")

    def atmospheric_noise(self):
        characters = [char for char in '0123456789ABCDEFSTUVWXYZabcdefghijtuvwxyz!"$%&/)(=?\ß@€+*#-_.:,;']

        url = "https://www.random.org/quota/?format=plain"
        quota = int(requests.get(url).text)

        if quota > 1000:
            def get_random_numbers(length):
                numbers = requests.get("https://www.random.org/integers/?num={}&min=1&max={}&col=1&base=10&format=plain&rnd=new".format(length, len(characters) - 1)).text.split('\n')
                numbers.remove("")
                return numbers

            length = str(self.inputentry.get())

            if length.isnumeric() == True:
                length = int(self.inputentry.get())
                pwd = ''
                shuffle(characters)
                numbers = get_random_numbers(length)

                for number in numbers:
                    pwd += characters[int(number)]

                characters1 = '0123456789'
                characters2 = 'ABCDEFSTUVWXYZ'
                characters3 = 'abcdefghijtuvwxyz'
                characters4 = '!"$%&/)(=?\ß@€+*#-_.:,;'

                if any(char in pwd for char in characters1):
                    if any(char in pwd for char in characters2):
                        if any(char in pwd for char in characters3):
                            if any(char in pwd for char in characters4):
                                self.outputprompt = tk.Text(self.OperationGUI, height=10, borderwidth=0, fg="#c7c6c3", font=("Arial", 15), bg="#202124")
                                self.outputprompt.insert(1.0, pwd)
                                self.outputprompt.place(y=585, relx=0.5, anchor="center")
                            else:
                                self.atmospheric_noise()
                        else:
                            self.atmospheric_noise()
                    else:
                        self.atmospheric_noise()
                else:
                    self.atmospheric_noise()

            elif length.isnumeric() == False:
                self.outputprompt = tk.Label(self.OperationGUI, text= "Pls select a correct number", fg="#c7c6c3", font=("Arial", 15), bg="#202124")
                self.outputprompt.place(y=585, relx=0.5, anchor="center")

        elif quota <= 1000:
            self.outputprompt = tk.Label(self.OperationGUI, text= "Your ip adress got throttled, pls select another methode", fg="#c7c6c3", font=("Arial", 15), bg="#202124")
            self.outputprompt.place(y=585, relx=0.5, anchor="center")

    def quantum_fluctuations(self):
        characters = [char for char in '0123456789ABCDEFSTUVWXYZabcdefghijtuvwxyz!"$%&/)(=?\ß@€+*#-_.:,;']
        characters *= 1024

        def get_random_numbers(length, Apikey):
            params = {"length": length, "type": "uint16"}
            respons = requests.get("https://api.quantumnumbers.anu.edu.au/", headers={"x-api-key": Apikey}, params=params).text

            try:
                errormsg = json.loads(respons)["message"]
                if errormsg == "Forbidden":
                    self.outputprompt = self.outputprompt = tk.Label(self.OperationGUI, text="Invalid ApiKey", fg="#c7c6c3", font=("Arial", 15), bg="#202124")
                    self.outputprompt.place(y=585, relx=0.5, anchor="center")
            except:
                pass

            return json.loads(respons)['data']


        length = str(self.inputentry.get())

        r = open(r"C:\ProgramData\Quantum-Tunneling-Security-Reloaded\config.json","r")
        self.config = r.read()
        r.close()

        self.config = json.loads(self.config)
        Apikey = self.config["QApiKey"]

        if length.isnumeric() == True:
            self.length = int(self.inputentry.get())
            self.pwd = ''
            shuffle(characters)
            numbers = get_random_numbers(length, Apikey)

            for number in numbers:
                self.pwd += characters[number]

            characters1 = '0123456789'
            characters2 = 'ABCDEFSTUVWXYZ'
            characters3 = 'abcdefghijtuvwxyz'
            characters4 = '!"$%&/)(=?\ß@€+*#-_.:,;'

            if any(char in self.pwd for char in characters1):
                if any(char in self.pwd for char in characters2):
                    if any(char in self.pwd for char in characters3):
                        if any(char in self.pwd for char in characters4):
                            self.outputprompt = tk.Text(self.OperationGUI, height=10, borderwidth=0, fg="#c7c6c3", font=("Arial", 15), bg="#202124")
                            self.outputprompt.insert(1.0, self.pwd)
                            self.outputprompt.place(y=585, relx=0.5, anchor="center")
                        else:
                            self.quantum_fluctuations()
                    else:
                        self.quantum_fluctuations()
                else:
                    self.quantum_fluctuations()
            else:
                self.quantum_fluctuations()

        elif length.isnumeric() == False:
            self.outputprompt = self.outputprompt = tk.Label(self.OperationGUI, text= "Pls select a correct number", fg="#c7c6c3", font=("Arial", 15), bg="#202124")
            self.outputprompt.place(y=585, relx=0.5, anchor="center")

    def file_encryption(self):
        salt = str(self.encrypt_decrypt_salt.get())
        salt = salt.encode()

        pwd = str(self.encrypt_decrypt_password.get())

        key = base64.urlsafe_b64encode(hashlib.pbkdf2_hmac("sha256", pwd.encode("utf-8"), salt, 10000))
        f = Fernet(key)

        r = open(self.filepath, "r")
        encryptiondata = str(r.read())
        r.close()

        try:
            encrypteddata = f.encrypt(encryptiondata.encode())

            r = open("C:\ProgramData\Quantum-Tunneling-Security-Reloaded\config.json", "r")
            self.config = r.read()
            r.close()

            self.config = json.loads(self.config)
            self.outputpath = self.config["Outputdir"]

            current_time = datetime.now()
            current_time = current_time.strftime("%H_%M_%S")

            self.outputpath = self.outputpath + r"\file" + current_time

            r = open(self.outputpath, "w")
            r.write(str(encrypteddata.decode()))
            r.close()

            self.prompterror = tk.Label(self.OperationGUI, text="File encrypted and save to: " + "\n" + self.outputpath, fg="#c7c6c3", font=("Arial", 15), bg="#202124")
            self.prompterror.place(y=585, relx=0.5, anchor="center", width=700)


        except AttributeError:
            self.prompterror = tk.Label(self.OperationGUI, text="Pls select a file", fg="#c7c6c3", font=("Arial", 15), bg="#202124")
            self.prompterror.place(y=585, relx=0.5, anchor="center", width=700)

    def file_decryption(self):
        salt = str(self.encrypt_decrypt_salt.get())
        salt = salt.encode()
        
        pwd = str(self.encrypt_decrypt_password.get())

        key = base64.urlsafe_b64encode(hashlib.pbkdf2_hmac("sha256", pwd.encode("utf-8"), salt, 10000))
        f = Fernet(key)

        r = open(self.filepath, "r")
        decryptiondata = str(r.read())
        r.close()

        try:
            self.decrypteddata = f.decrypt(decryptiondata.encode())

            r = open("C:\ProgramData\Quantum-Tunneling-Security-Reloaded\config.json", "r")
            self.config = r.read()
            r.close()

            self.config = json.loads(self.config)
            self.outputpath = self.config["Outputdir"]

            current_time = datetime.now()
            current_time = current_time.strftime("%H_%M_%S")

            self.outputpath = self.outputpath + r"\file" + current_time

            r = open(self.outputpath, "w")
            r.write(str(self.decrypteddata.decode()))
            r.close()

            self.prompterror = tk.Label(self.OperationGUI, text="File encrypted and save to: " + "\n" + self.outputpath, fg="#c7c6c3", font=("Arial", 15), bg="#202124")
            self.prompterror.place(y=585, relx=0.5, anchor="center", width=700)

        except cryptography.fernet.InvalidToken or cryptography.fernet.InvalidSignature:
            self.prompterror = tk.Label(self.OperationGUI, text="Password or salt is wrong", fg="#c7c6c3", font=("Arial", 15),bg="#202124")
            self.prompterror.place(y=585, relx=0.5, anchor="center", width=700)
            
        except AttributeError:
            self.prompterror = tk.Label(self.OperationGUI, text="Pls select a file", fg="#c7c6c3", font=("Arial", 15), bg="#202124")
            self.prompterror.place(y=585, relx=0.5, anchor="center", width=700)

    def zip_file_scanner(self):
        zip_or_not = pathlib.Path(self.filepath).suffix

        if zip_or_not == ".zip":
            zip = zf.ZipFile(self.filepath)
            zip_unpacked_size = sum(file.file_size for file in zip.filelist) /1024 ** 3
            zip_file_size = os.path.getsize(self.filepath) / 1024 ** 3
            ratio = int(round(zip_unpacked_size / zip_file_size, 0))

            self.prompterror = tk.Label(self.OperationGUI, text=f"Zip file is {zip_file_size}GB big \n Unpacked files are {zip_unpacked_size}GB big \n The ratio of file size to unpacked size is {ratio}", fg="#c7c6c3", font=("Arial", 15),bg="#202124")
            self.prompterror.place(y=585, relx=0.5, anchor="center", width=700)

            if ratio >= 200 or zip_unpacked_size >= 10:
                self.prompterror = tk.Label(self.OperationGUI, text="Zip file is likely a Zip bomb", fg="#c7c6c3",font=("Arial", 15), bg="#202124")
                self.prompterror.place(y=650, relx=0.5, anchor="center", width=700)

            else:
                self.prompterror = tk.Label(self.OperationGUI, text="Zip file is probably safe", fg="#c7c6c3",font=("Arial", 15), bg="#202124")
                self.prompterror.place(y=650, relx=0.5, anchor="center", width=700)

        elif zip_or_not != ".zip":
            self.prompterror = tk.Label(self.OperationGUI, text="File is not a zip file", fg="#c7c6c3", font=("Arial", 15),bg="#202124")
            self.prompterror.place(y=585, relx=0.5, anchor="center", width=700)

    def one_time_decryption(self):
        salt = str(self.encrypt_decrypt_salt.get())
        salt = salt.encode()

        pwd = str(self.encrypt_decrypt_password.get())

        key = base64.urlsafe_b64encode(hashlib.pbkdf2_hmac("sha256", pwd.encode("utf-8"), salt, 10000))
        f = Fernet(key)

        r = open(self.filepath, "r")
        decryptiondata = str(r.read())
        r.close()

        try:
            decrypteddata = f.decrypt(decryptiondata.encode())
            decrypteddata = decrypteddata.decode()

            self.outputprompt = tk.Text(self.OperationGUI, height=5, borderwidth=0, fg="#c7c6c3", font=("Arial", 15), bg="#202124")
            self.outputprompt.insert(1.0, decrypteddata)
            self.outputprompt.place(y=600, relx=0.5, anchor="center")

        except cryptography.fernet.InvalidToken or cryptography.fernet.InvalidSignature:
            self.prompterror = tk.Label(self.OperationGUI, text="Password or salt is wrong", fg="#c7c6c3", font=("Arial", 15),bg="#202124")
            self.prompterror.place(y=585, relx=0.5, anchor="center", width=700)

        except AttributeError:
            self.prompterror = tk.Label(self.OperationGUI, text="Pls select a file", fg="#c7c6c3", font=("Arial", 15), bg="#202124")
            self.prompterror.place(y=585, relx=0.5, anchor="center", width=700)

    def close(self):
        quit()

    def back(self):
        self.OperationGUI.destroy()


class StartGUI:

    def __init__(self):
        self.StartGUI = tk.Tk()
        self.StartGUI.geometry("1200x800+0+0")
        self.StartGUI.resizable(0, 0)
        self.StartGUI.title("Quantum-Tunneling-Security-Reloaded")
        self.StartGUI['background'] = '#202124'

        self.welcomelabel = tk.Label(self.StartGUI, text="Welcome to Quantum-Tunneling-Security-Reloaded \n designed by Eisblume2000#5142", fg="#c7c6c3", font=("Arial", 20), bg="#202124")
        self.welcomelabel.place(y=100, relx=0.5, anchor="center", width=700)

        self.promptlabel = tk.Label(self.StartGUI, text="Pls select an option", fg="#c7c6c3", font=("Arial", 20), bg="#202124")
        self.promptlabel.place(y=250, relx=0.5, anchor="center", width=700)

        self.buttonframe1 = tk.Frame(self.StartGUI)
        self.buttonframe1.columnconfigure(0, weight=1)
        self.buttonframe1.columnconfigure(1, weight=1)
        self.buttonframe1.columnconfigure(2, weight=1)

        # Button for text encryption/decryption
        self.buttontxt = tk.Button(self.buttonframe1, text="Text-Encryption/Decryption", fg="#c7c6c3", font=("Arial", 15), width=30, height=2, bg="#3c3d42", 
        command=lambda: OperationGUI("Text-Encryption/Decryption", "Text-Encryption/Decryption", "Pls enter text: ", "textinput", None, True, 2, "Encrypt", "Decrypt", "text_encryption", "text_decryption"))
        self.buttontxt.grid(row=0, column=0)

        # Button for password generator
        self.buttonpwd = tk.Button(self.buttonframe1, text="Password-Generator", fg="#c7c6c3", font=("Arial", 15), width=30, height=2, bg="#3c3d42", 
        command=lambda: OperationGUI("Password-Generator", "Password-Generator", "Pls enter desired password length", "textinput", None, False, 2, "Atmospheric noise", "Quantum fluctuations", "atmospheric_noise", "quantum_fluctuations"))
        self.buttonpwd.grid(row=0, column=1)

        # Button for file encryption/decryption
        self.buttonfile = tk.Button(self.buttonframe1, text="File-Encryption/Decryption", fg="#c7c6c3", font=("Arial", 15), width=30, height=2, bg="#3c3d42", 
        command=lambda: OperationGUI("File-Encryption/Decryption", "File-Encryption/Decryption", "Pls select a file", "fileinput", "Select file", True, 2, "Encrypt", "Decrypt", "file_encryption", "file_decryption"))
        self.buttonfile.grid(row=0, column=2)

        # Button for zip file scanner
        self.buttonzip = tk.Button(self.buttonframe1, text="Zip-File-Scanner", fg="#c7c6c3", font=("Arial", 15), width=30, height=2, bg="#3c3d42",
        command=lambda: OperationGUI("Zip-File-Scanner", "Zip-File-Scanner", "Pls select zip-file", "fileinput", "Select file", False, 1, "Scan", None, "zip_file_scanner", None))
        self.buttonzip.grid(row=1, column=0)

        # Button for one time decryption
        self.buttononetimedecrypt = tk.Button(self.buttonframe1, text="One-Time-Decryption", fg="#c7c6c3", font=("Arial", 15), width=30, height=2, bg="#3c3d42",
        command=lambda: OperationGUI("One-Time-Decryption", "One-Time-Decryption", "Pls select a file to decrypt", "fileinput", "Select file", True, 1, "Decrypt", None, "one_time_decryption", None))
        self.buttononetimedecrypt.grid(row=1, column=1)

        # Button for secure local chat
        self.buttonchat = tk.Button(self.buttonframe1, text="Encrypted-Local-Chat", fg="#c7c6c3", font=("Arial", 15), width=30, height=2, bg="#3c3d42")
        self.buttonchat.grid(row=1, column=2)

        self.buttonframe1.place(y=475, relx=0.5, anchor="center")

        self.buttonframe2 = tk.Frame(self.StartGUI)
        self.buttonframe2.columnconfigure(0, weight=1)
        self.buttonframe2.columnconfigure(1, weight=1)
        self.buttonframe2.columnconfigure(2, weight=1)

        # Button to close the programm
        self.buttonclose = tk.Button(self.buttonframe2, text="Close", fg="#c7c6c3", font=("Arial", 15), width=30, height=2, bg="#3c3d42", command=self.close)
        self.buttonclose.grid(row=0, column=0)

        # Button for settings menu
        self.buttonsettings = tk.Button(self.buttonframe2, text="Settings", fg="#c7c6c3", font=("Arial", 15), width=30, height=2, bg="#3c3d42", command=SettinsGUI)
        self.buttonsettings.grid(row=0, column=1)

        # Button to github page
        self.buttonabout = tk.Button(self.buttonframe2, text="About", fg="#c7c6c3", font=("Arial", 15), width=30, height=2, bg="#3c3d42", command=self.about)
        self.buttonabout.grid(row=0, column=2)

        self.buttonframe2.place(y=700, relx=0.5, anchor="center")

        self.StartGUI.mainloop()

    def close(self):
        self.StartGUI.destroy()
        exit()

    def about(self):
        url="https://github.com/Eisblume-2000/Quantum-Tunneling-Security-Reloaded"
        webbrowser.open(url)

if os.path.exists(r"C:\ProgramData\Quantum-Tunneling-Security-Reloaded") == False:
    os.mkdir(r"C:\ProgramData\Quantum-Tunneling-Security-Reloaded")
    os.mkdir(r"C:\ProgramData\Quantum-Tunneling-Security-Reloaded\Output")

if os.path.exists(r"C:\ProgramData\Quantum-Tunneling-Security-Reloaded\config.json") == False:
    c = open(r"C:\ProgramData\Quantum-Tunneling-Security-Reloaded\config.json", "w")
    c.write("{\"Outputdir\": \"C:/ProgramData/Quantum-Tunneling-Security-Reloaded/Output\", \"QApiKey\": \"\", \"Version\": \"1\"}")
    c.close()
else:
    r = open(r"C:\ProgramData\Quantum-Tunneling-Security-Reloaded\config.json","r")
    config = r.read()
    r.close()

    config = json.loads(config)
    version = config["Version"]

    if version != 1:
        c = open(r"C:\ProgramData\Quantum-Tunneling-Security-Reloaded\config.json", "w")
        c.write(
            "{\"Outputdir\": \"C:/ProgramData/Quantum-Tunneling-Security-Reloaded/Output\", \"QApiKey\": \"\", \"Version\": \"1\"}")
        c.close()

StartGUI()