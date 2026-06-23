#!/usr/bin/env ruby
# filecrypt.rb
# encoding: UTF-8

require 'openssl'
require 'base64'
require 'fileutils'

# ANSI colors
COLORS = {
  green: "\e[92m",
  red: "\e[91m",
  yellow: "\e[93m",
  reset: "\e[0m"
}

def colorize(text, color)
  "#{COLORS[color]}#{text}#{COLORS[:reset]}"
end

SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32
ITERATIONS = 100000
CHUNK_SIZE = 64 * 1024

def derive_key(password, salt)
  OpenSSL::PKCS5.pbkdf2_hmac(password, salt, ITERATIONS, KEY_LEN, 'sha256')
end

def encrypt_file(input_path, output_path, password)
  salt = OpenSSL::Random.random_bytes(SALT_LEN)
  nonce = OpenSSL::Random.random_bytes(NONCE_LEN)
  key = derive_key(password, salt)

  cipher = OpenSSL::Cipher.new('aes-256-gcm')
  cipher.encrypt
  cipher.key = key
  cipher.iv = nonce

  plaintext = File.binread(input_path)
  ciphertext = cipher.update(plaintext) + cipher.final
  tag = cipher.auth_tag

  File.open(output_path, 'wb') do |f|
    f.write(salt)
    f.write(nonce)
    f.write(ciphertext)
    f.write(tag)
  end
  puts colorize("File encrypted successfully: #{output_path}", :green)
end

def decrypt_file(input_path, output_path, password)
  data = File.binread(input_path)
  if data.bytesize < SALT_LEN + NONCE_LEN + TAG_LEN
    raise "Invalid file format"
  end

  salt = data.byteslice(0, SALT_LEN)
  nonce = data.byteslice(SALT_LEN, NONCE_LEN)
  ciphertext = data.byteslice(SALT_LEN + NONCE_LEN, data.bytesize - SALT_LEN - NONCE_LEN - TAG_LEN)
  tag = data.byteslice(-TAG_LEN, TAG_LEN)

  key = derive_key(password, salt)
  decipher = OpenSSL::Cipher.new('aes-256-gcm')
  decipher.decrypt
  decipher.key = key
  decipher.iv = nonce
  decipher.auth_tag = tag

  plaintext = decipher.update(ciphertext) + decipher.final
  File.binwrite(output_path, plaintext)
  puts colorize("File decrypted successfully: #{output_path}", :green)
end

def main
  if ARGV.size < 4
    puts colorize("Usage: ruby filecrypt.rb encrypt|decrypt <input> <output> <password>", :yellow)
    exit 1
  end

  mode, input, output, password = ARGV[0], ARGV[1], ARGV[2], ARGV[3]

  begin
    if mode == 'encrypt'
      encrypt_file(input, output, password)
    elsif mode == 'decrypt'
      decrypt_file(input, output, password)
    else
      puts colorize("Invalid mode. Use encrypt or decrypt.", :red)
      exit 1
    end
  rescue => e
    puts colorize("Error: #{e.message}", :red)
    exit 1
  end
end

if __FILE__ == $0
  main
end
