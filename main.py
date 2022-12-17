import base64
import pathlib
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

#TODO: Zipfile scanner
#TODO: make pwd gen single function
#TODO: FIle encryption/decryption
#TODO: Encrypted Local Chat
#TODO: error handling like no salt or pwd
#TODO: get file name
#TODO: fix code so no spaces are in pwds

class SettinsGUI:

    def __init__(self):
        self.SettinsGUI = tk.Tk()
        self.SettinsGUI.geometry("500x700")
        self.SettinsGUI.resizable(0, 0)
        self.SettinsGUI.title("Settings")
        self.SettinsGUI['background'] = '#202124'

        self.welcomelabel = tk.Label(self.SettinsGUI, text="Here you can change your settings", fg="#c7c6c3", font=("Arial", 20), bg="#202124")
        self.welcomelabel.place(y=50, relx=0.5, anchor="center", width=700)

        self.settingslabel1 = tk.Label(self.SettinsGUI, text="Output Directory for files", fg="#c7c6c3", font=("Arial", 15), bg="#202124")
        self.settingslabel1.place(y=125, relx=0.5, anchor="center", width=700)

        r = open(r"C:\ProgramData\Quantum-Tunneling-Security-Reloaded\config.json", "r")
        self.currentoutput = r.read()
        r.read()

        self.currentoutput = tk.Label(self.SettinsGUI, text="Current output directory : \n" + self.currentoutput, fg="#c7c6c3", font=("Arial", 12), bg="#202124")
        self.currentoutput.place(y=175, relx=0.5, anchor="center", width=700)

        self.outputentry = tk.Button(self.SettinsGUI, text="New Directory", fg="#c7c6c3", font=("Arial", 12), width=30, height=2, bg="#3c3d42", command=self.new_directory)
        self.outputentry.place(y=235, relx=0.5, anchor="center", width=250)

        self.newoutput = tk.Label(self.SettinsGUI, text="New output directory : \n", fg="#c7c6c3", font=("Arial", 12), bg="#202124")
        self.newoutput.place(y=295, relx=0.5, anchor="center", width=700)

        self.buttonframe1 = tk.Frame(self.SettinsGUI)
        self.buttonframe1.columnconfigure(0, weight=1)
        self.buttonframe1.columnconfigure(1, weight=1)

        self.buttonsave = tk.Button(self.buttonframe1, text="Save", fg="#c7c6c3", font=("Arial", 15), width=20, height=2, bg="#3c3d42", command=self.save)
        self.buttonsave.grid(row=0, column=0)

        self.buttonback = tk.Button(self.buttonframe1, text="Back", fg="#c7c6c3", font=("Arial", 15), width=20, height=2, bg="#3c3d42", command=self.back)
        self.buttonback.grid(row=0, column=1)

        self.buttonframe1.place(y=650, relx=0.5, anchor="center")

        self.SettinsGUI.mainloop()

    def new_directory(self):
        self.nnew_directory = tk.filedialog.askdirectory()
        self.newoutput = tk.Label(self.SettinsGUI, text="New output directory : \n" + str(self.nnew_directory), fg="#c7c6c3", font=("Arial", 12), bg="#202124")
        self.newoutput.place(y=295, relx=0.5, anchor="center", width=700)

    def back(self):
        self.SettinsGUI.destroy()

    def save(self):
        r = open(r"C:\ProgramData\Quantum-Tunneling-Security-Reloaded\config.json", "w")
        r.write(self.nnew_directory)
        r.close()


class OperationGUI:

    def __init__(self, currentoperation, label1text, prompt1text, filedialog_or_text_input, filedialog_button_text, second_input_row, numofbutton,button1, button2, button1_command, button2_command):
        self.OperationGUI = tk.Tk()
        self.OperationGUI.geometry("900x800")
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

        self.buttonvar1 = tk.Button(self.buttonframe1, text=button1, fg="#c7c6c3", font=("Arial", 15), width=20, height=2, bg="#3c3d42", command=eval(button1_command) )
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
        characters = [char for char in '0123456789ABCDEFSTUVWXYZabcdefghijtuvwxyz!"$%&/)(=?\ß@€ + *#-_.:, ;']

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
                characters4 = '!"$%&/)(=?\ß@€ + *#-_.:, ;'

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
                self.outputprompt = tk.Text(self.OperationGUI, height=10, borderwidth=0, fg="#c7c6c3", font=("Arial", 15), bg="#202124")
                self.outputprompt.insert(1.0, "Pls select a correct number")
                self.outputprompt.place(y=585, relx=0.5, anchor="center")

        elif quota <= 1000:
            self.outputprompt = tk.Text(self.OperationGUI, height=10, borderwidth=0, fg="#c7c6c3", font=("Arial", 15), bg="#202124")
            self.outputprompt.insert(1.0, "Your ip adress got throttled, pls select another methode")
            self.outputprompt.place(y=585, relx=0.5, anchor="center")

    def quantum_fluctuations(self):
        characters = [char for char in '0123456789ABCDEFSTUVWXYZabcdefghijtuvwxyz!"$%&/)(=?\ß@€ + *#-_.:, ;']
        characters *= 1024

        def get_random_numbers(length):
            respons = requests.get(f'https://qrng.anu.edu.au/API/jsonI.php?length={length}&type=uint16').text
            return json.loads(respons)['data']

        length = str(self.inputentry.get())

        if length.isnumeric() == True:
            length = int(self.inputentry.get())
            pwd = ''
            shuffle(characters)
            numbers = get_random_numbers(length)

            for number in numbers:
                pwd += characters[number]

            characters1 = '0123456789'
            characters2 = 'ABCDEFSTUVWXYZ'
            characters3 = 'abcdefghijtuvwxyz'
            characters4 = '!"$%&/)(=?\ß@€ + *#-_.:, ;'

            if any(char in pwd for char in characters1):
                if any(char in pwd for char in characters2):
                    if any(char in pwd for char in characters3):
                        if any(char in pwd for char in characters4):
                            self.outputprompt = tk.Text(self.OperationGUI, height=10, borderwidth=0, fg="#c7c6c3", font=("Arial", 15), bg="#202124")
                            self.outputprompt.insert(1.0, pwd)
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
            self.outputprompt = tk.Text(self.OperationGUI, height=10, borderwidth=0, fg="#c7c6c3", font=("Arial", 15), bg="#202124")
            self.outputprompt.insert(1.0, "Pls select a correct number")
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
            output_path = r.read()
            r.close()

            current_time = datetime.now()
            current_time = current_time.strftime("%H_%M_%S")

            output_path = output_path + r"\file" + current_time

            r = open(output_path, "w")
            r.write(str(encrypteddata.decode()))
            r.close()

            self.prompterror = tk.Label(self.OperationGUI, text="File encrypted and save to: " + "\n" + output_path, fg="#c7c6c3", font=("Arial", 15), bg="#202124")
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
            decrypteddata = f.decrypt(decryptiondata.encode())
    
            r = open("C:\ProgramData\Quantum-Tunneling-Security-Reloaded\config.json", "r")
            output_path = r.read()
            r.close()
    
            current_time = datetime.now()
            current_time = current_time.strftime("%H_%M_%S")
    
            output_path = output_path + r"\file" + current_time
    
            r = open(output_path, "w")
            r.write(str(decrypteddata.decode()))
            r.close()

            self.prompterror = tk.Label(self.OperationGUI, text="File encrypted and save to: " + "\n" + output_path, fg="#c7c6c3", font=("Arial", 15), bg="#202124")
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
        exit()

    def back(self):
        self.OperationGUI.destroy()


class StartGUI:

    def __init__(self):
        self.StartGUI = tk.Tk()
        self.StartGUI.geometry("1200x800")
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
        command=lambda: OperationGUI("Password-Generator", "Password-Generator", "Pls enter desired password length", "textinput", None, False, 2, "atmospheric noise", "quantum fluctuations", "atmospheric_noise", "quantum_fluctuations"))
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
        self.buttononetimedecrypt = tk.Button(self.buttonframe1, text="One time decryption", fg="#c7c6c3", font=("Arial", 15), width=30, height=2, bg="#3c3d42",
        command=lambda: OperationGUI("One time decryption", "One time decryption", "Pls select a file to decrypt", "fileinput", "Select file", True, 1, "Decrypt", None, "one_time_decryption", None))
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
    c.write(r"C:\ProgramData\Quantum-Tunneling-Security-Reloaded\Output")
    c.close()

StartGUI()