# Mercury Ransomware

![GitHub](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.7%2B-blue)

**Mercury Ransomware** is a Python-based tool designed for educational and research purposes to demonstrate the functionality of ransomware. It provides a command-line interface (CLI) for encrypting and decrypting files within a specified directory using AES encryption. The tool also generates a ransom note to simulate real-world ransomware behavior.

**Disclaimer**: This tool is intended for educational and ethical use only. Misuse of this software is strictly prohibited. The author is not responsible for any illegal or unethical activities conducted using this tool.

---

## Features

- **File Encryption**: Encrypts files recursively within a specified directory using AES-256 encryption.
- **File Decryption**: Decrypts files using a provided passkey.
- **Multi-threading**: Utilizes multi-threading for efficient file processing.
- **Ransom Note Generation**: Creates a `README.mercury` file with instructions for the victim.
- **Interactive Menu**: Provides a CLI menu for ease of use.
- **Custom Passkey**: Allows users to specify a custom encryption/decryption passkey.

---

## Prerequisites

- Python 3.7 or higher
- `cryptography` library (`pip install cryptography`)
- `colorama` library (`pip install colorama`)

---

## Usage

### Command-Line Interface

#### Encrypt Files
```bash
./mercury.py lock /path/to/directory your_passkey [ransom@email.com]
```
- `/path/to/directory`: The directory to encrypt.
- `your_passkey`: The encryption passkey.
- `ransom@email.com` (optional): Email address to include in the ransom note.

#### Decrypt Files
```bash
./mercury.py unlock /path/to/directory your_passkey
```
- `/path/to/directory`: The directory to decrypt.
- `your_passkey`: The decryption passkey.

#### Interactive Menu
```bash
./mercury.py menu
```
Launches an interactive CLI menu for encrypting, decrypting, and viewing help.

---

## Example

### Encrypting Files
```bash
./mercury.py lock /home/user/documents my_secure_passkey ransom@example.com
```
This command will:
1. Encrypt all files in `/home/user/documents` and its subdirectories.
2. Generate a `README.mercury` file with instructions for the victim.

### Decrypting Files
```bash
./mercury.py unlock /home/user/documents my_secure_passkey
```
This command will:
1. Decrypt all files in `/home/user/documents` and its subdirectories.
2. Remove the `README.mercury` file.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Disclaimer

This tool is for **educational purposes only**. Do not use it for illegal or unethical activities. The author is not responsible for any misuse of this software. Always ensure you have proper authorization before using this tool in any environment.

Use this tool responsibly and only in environments where you have explicit permission to perform testing. Unauthorized use of this tool may violate laws and regulations.
