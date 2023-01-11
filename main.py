import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from termcolor import colored

class Crypto:
    def __init__(self, key=None):
        self.key = key or self.generate_key()
        self.fernet = Fernet(self.key)

    def generate_key(self):
        """
        Generates a new key, writes it to the "decryption_key.key" file,
        and returns the key
        """
        password = b"my_secret_password"
        salt = b"my_secret_salt"
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

def menu():
    """
    Displays a menu and handles user input to perform different actions
    """
    print(colored("\nWelcome to the File Encryption/Decryption Tool\n", "cyan"))
    crypto = Crypto()
    while True:
        print(colored("[1] Generate key and encrypt a file", "yellow"))
        print(colored("[2] Load key and decrypt a file", "yellow"))
        print(colored("[3] Exit", "yellow"))

        choice = input(colored("Enter your choice: ", "cyan"))
        if choice == "1":
            file_path = input(colored("Enter the path of the file to encrypt: ", "cyan"))
            crypto.encrypt_file(file_path)
        elif choice == "2":
            key_path = input(colored("Enter the path of the decryption key file: ", "cyan"))
            crypto.load_key(key_path)
            file_path = input(colored("Enter the path of the file to decrypt: ", "cyan"))
            crypto.decrypt_file(file_path)

        elif choice == "3":
            print(colored("Thank you for using the File Encryption/Decryption Tool", "green"))
            break
        else:
            print(colored("Invalid choice. Please try again.", "red"))

if __name__ == "__main__":
    menu()
