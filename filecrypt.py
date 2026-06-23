# filecrypt.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import argparse
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import secrets

# ANSI colors
COLORS = {
    'green': '\033[92m',
    'red': '\033[91m',
    'yellow': '\033[93m',
    'blue': '\033[94m',
    'reset': '\033[0m'
}

def colorize(text, color):
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"

SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32
ITERATIONS = 100000
CHUNK_SIZE = 64 * 1024  # 64 KB

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_file(input_file, output_file, password):
    # Generate salt and nonce
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    with open(input_file, 'rb') as fin, open(output_file, 'wb') as fout:
        # Write salt, nonce
        fout.write(salt)
        fout.write(nonce)

        # Encrypt and write in chunks
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            # For GCM, we need to encrypt all at once; but we can split,
            # however GCM is not streamable. We'll encrypt whole file at once.
            # To support large files, we'd need to use incremental AEAD, but Python's AESGCM doesn't support it easily.
            # We'll read all data into memory for simplicity (but this limits file size).
            # For a real implementation, we could use a streaming mode like AES-CTR + HMAC.
            # To keep it consistent, we'll do full-file encryption.
        # Actually, let's read entire file content (if too large, may fail).
        # Better: Use a streaming approach with AES-GCM using chunks? Not trivial.
        # We'll implement simple full-load for demonstration.
    # Re-open and read all content
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    # ciphertext includes tag at the end (16 bytes)
    with open(output_file, 'wb') as f:
        f.write(salt)
        f.write(nonce)
        f.write(ciphertext)
    print(colorize(f"File encrypted successfully: {output_file}", 'green'))

def decrypt_file(input_file, output_file, password):
    with open(input_file, 'rb') as f:
        salt = f.read(SALT_LEN)
        nonce = f.read(NONCE_LEN)
        ciphertext = f.read()  # includes tag
    if len(salt) != SALT_LEN or len(nonce) != NONCE_LEN:
        raise ValueError("Invalid file format")
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    with open(output_file, 'wb') as f:
        f.write(plaintext)
    print(colorize(f"File decrypted successfully: {output_file}", 'green'))

def main():
    parser = argparse.ArgumentParser(description="FileCrypt – шифратор файлов AES-256-GCM")
    parser.add_argument('mode', choices=['encrypt', 'decrypt'], help='Режим работы')
    parser.add_argument('input', help='Входной файл')
    parser.add_argument('output', help='Выходной файл')
    parser.add_argument('password', help='Пароль для шифрования')
    args = parser.parse_args()

    try:
        if args.mode == 'encrypt':
            encrypt_file(args.input, args.output, args.password)
        else:
            decrypt_file(args.input, args.output, args.password)
    except Exception as e:
        print(colorize(f"Ошибка: {e}", 'red'))
        sys.exit(1)

if __name__ == '__main__':
    main()
