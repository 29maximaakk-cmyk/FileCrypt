// filecrypt.js
#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');

// ANSI colors
const COLORS = {
    green: '\x1b[92m',
    red: '\x1b[91m',
    yellow: '\x1b[93m',
    reset: '\x1b[0m'
};

function colorize(text, color) {
    return COLORS[color] + text + COLORS.reset;
}

const SALT_LEN = 16;
const NONCE_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;
const ITERATIONS = 100000;
const CHUNK_SIZE = 64 * 1024;

function deriveKey(password, salt) {
    return crypto.pbkdf2Sync(password, salt, ITERATIONS, KEY_LEN, 'sha256');
}

function encryptFile(inputPath, outputPath, password) {
    const salt = crypto.randomBytes(SALT_LEN);
    const nonce = crypto.randomBytes(NONCE_LEN);
    const key = deriveKey(password, salt);

    const plaintext = fs.readFileSync(inputPath);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    const out = Buffer.concat([salt, nonce, encrypted, tag]);
    fs.writeFileSync(outputPath, out);
    console.log(colorize(`File encrypted successfully: ${outputPath}`, 'green'));
}

function decryptFile(inputPath, outputPath, password) {
    const data = fs.readFileSync(inputPath);
    const salt = data.slice(0, SALT_LEN);
    const nonce = data.slice(SALT_LEN, SALT_LEN + NONCE_LEN);
    const encrypted = data.slice(SALT_LEN + NONCE_LEN, -TAG_LEN);
    const tag = data.slice(-TAG_LEN);
    const key = deriveKey(password, salt);

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    fs.writeFileSync(outputPath, plaintext);
    console.log(colorize(`File decrypted successfully: ${outputPath}`, 'green'));
}

function main() {
    const args = process.argv.slice(2);
    if (args.length < 4) {
        console.log(colorize('Usage: node filecrypt.js encrypt|decrypt <input> <output> <password>', 'yellow'));
        process.exit(1);
    }
    const mode = args[0];
    const input = args[1];
    const output = args[2];
    const password = args[3];

    try {
        if (mode === 'encrypt') encryptFile(input, output, password);
        else if (mode === 'decrypt') decryptFile(input, output, password);
        else {
            console.log(colorize('Invalid mode. Use encrypt or decrypt.', 'red'));
            process.exit(1);
        }
    } catch (err) {
        console.log(colorize(`Error: ${err.message}`, 'red'));
        process.exit(1);
    }
}

main();
