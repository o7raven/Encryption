# File Encryption/Decryption Tool

This tool allows you to easily encrypt and decrypt files using the Advanced Encryption Standard (AES) algorithm. The encryption key is generated using the PBKDF2 key derivation function and the key is stored in a file called "decryption_key.key". 

The script is written in python and uses the `pycryptodomex` library for the AES encryption and decryption operations, and the `getpass` library to hide the password input.

## Features

- AES encryption using the Pycryptodome library in CBC mode
- PBKDF2 key derivation with SHA256 hash and 100000 iterations
- Key generation and storage in a separate file
- File encryption and decryption using user input
- Interactive menu and ability to handle user's choices
- Input Validation
- Ability to encrypt/decrypt large files

## How to use

1. Clone the repository to your local machine or download the script to your computer.
2. Run the script using the command `python main.py` or run the `main.exe`
3. Select the desired option from the menu:
    - Generate key and encrypt a file
    - Load key and decrypt a file
4. If you chose to generate the key, you will be prompted to enter a password which will be used to encrypt the key
5. After that enter the path of the file to encrypt/decrypt
6. Wait for the encryption/decryption to finish.
7. Enjoy your secure files

## Note
- This script is just an example, you should use better way of storing the key and password, like using environment variable or using a service like Hashicorp's Vault.
- It is recommended to use AES-GCM which is authenticated encryption mode and also encrypt in a streaming fashion.
- This repository is only for testing artificial intelligence. While this script works for basic functions, it would be better to use more complex encryption to ensure full security. Note that if you delete a key, you will no longer be able to decrypt files that have been encrypted with that key without cracking

## Contact

- Twitter: [@o7ravenxd](https://twitter.com/o7ravenxd)
- Twitter: [@OpenAI](https://twitter.com/openai)

## Credits

- Code by [@Assistant](https://openai.com/), improved by [@o7ravenxd](https://twitter.com/o7ravenxd)

