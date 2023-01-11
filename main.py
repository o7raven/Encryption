import os
import sys
import time
import threading
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from termcolor import colored

import random

_defaultKey = 'decryption_key.key'

class Crypto:
    def __init__(self, key=None):
        self.key = key or self.generate_key()
        self.fernet = Fernet(self.key)

    def generate_key(self):
        """
        Generates a new key, writes it to the "decryption_key.key" file,
        and returns the key
        """
        pwd = random.randbytes(16)
        salt = random.randbytes(16)
        password = pwd
        salt = salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256,
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        with open("decryption_key.key", "wb") as key_file:
            key_file.write(key)
        return key
        
    def load_key(self, key_path):
        """
        Loads the key from the specified file and sets it as the current key
        """
        with open(key_path, "rb") as key_file:
            self.key = key_file.read()
        self.fernet = Fernet(self.key)


    def encrypt_file(self, file_path):
        """
        Encrypts the specified file and overwrites the original file
        """
        with open(file_path, "rb") as f:
            data = f.read()
        encrypted_data = self.fernet.encrypt(data)
        with open(file_path, "wb") as f:
            f.write(encrypted_data)
        print(colored(f"[+] {file_path} was encrypted.", "green"))

    def decrypt_file(self, file_path):
        """
        Decrypts the specified file and overwrites the original file
        """
        with open(file_path, "rb") as f:
            encrypted_data = f.read()
        decrypted_data = self.fernet.decrypt(encrypted_data)
        with open(file_path, "wb") as f:
            f.write(decrypted_data)
        print(colored(f"[+] {file_path} was decrypted.", "green"))


def loading():
    chars = "/—\|" 
    for char in chars:
        sys.stdout.write(colored('\r'+'loading...'+char, "magenta"))
        time.sleep(.1)
        sys.stdout.flush() 
    print(colored('\n\nLoaded! \n\n', "magenta"))
    menu()

def menu():
    logo = '''v.1

            8b,dPPYba, ,adPPYYba, 8b       d8  ,adPPYba, 8b,dPPYba,   
            88P'   "Y8 ""     `Y8 `8b     d8' a8P_____88 88P'   `"8a  
            88         ,adPPPPP88  `8b   d8'  8PP""""""" 88       88  
            88         88,    ,88   `8b,d8'   "8b,   ,aa 88       88  
            88         `"8bbdP"Y8     "8"      `"Ybbd8"' 88       88  

    '''
    """
    Displays a menu and handles user input to perform different actions
    """
    print(colored(logo, "magenta"))
    print(colored("\nWelcome to the File Encryption/Decryption Tool\n", "cyan"))
    
    crypto = Crypto()
    while True:
        try:
            print(colored("[1] Generate key and encrypt a file", "magenta"))
            print(colored("[2] Load key and decrypt a file", "magenta"))
            print(colored("[3] Exit \n", "magenta"))

            choice = input(colored("Enter your choice: ", "cyan"))
            if choice == "1":
                file_path = input(colored("Enter the path of the file to encrypt: ", "cyan"))
                crypto.encrypt_file(file_path)
            elif choice == "2":
                key_path = input(colored("Enter the path of the decryption key file (default: 'decryption_key.key'): ", "cyan"))
                if not key_path:
                    crypto.load_key(_defaultKey)
                else:
                    crypto.load_key(key_path)
                file_path = input(colored("Enter the path of the file to decrypt: ", "cyan"))
                crypto.decrypt_file(file_path)

            elif choice == "3":
                print(colored("\nThank you for using the File Encryption/Decryption Tool", "green"))
                break
            else:
                print(colored("\nInvalid choice. Please try again. \n", "red"))
        except:
            print(colored("\n\nAn error has occured. Please try again. \n", "red"))
    

if __name__ == "__main__":
    clear = lambda: os.system('cls')
    clear()
    loading()
