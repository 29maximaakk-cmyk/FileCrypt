// filecrypt.go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"golang.org/x/crypto/pbkdf2"
)

// ANSI colors
const (
	reset  = "\033[0m"
	green  = "\033[92m"
	red    = "\033[91m"
	yellow = "\033[93m"
)

func colorize(text, color string) string {
	return color + text + reset
}

const (
	saltLen   = 16
	nonceLen  = 12
	tagLen    = 16
	keyLen    = 32
	iterations = 100000
	chunkSize = 64 * 1024
)

func deriveKey(password, salt []byte) []byte {
	return pbkdf2.Key(password, salt, iterations, keyLen, sha256.New)
}

func encryptFile(inputPath, outputPath, password string) error {
	// Generate salt and nonce
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	key := deriveKey([]byte(password), salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	inFile, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	// Write salt and nonce
	if _, err := outFile.Write(salt); err != nil {
		return err
	}
	if _, err := outFile.Write(nonce); err != nil {
		return err
	}

	// Read entire file (for simplicity; for large files use streaming with Seal)
	plaintext, err := io.ReadAll(inFile)
	if err != nil {
		return err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	if _, err := outFile.Write(ciphertext); err != nil {
		return err
	}

	fmt.Println(colorize("File encrypted successfully: " + outputPath, green))
	return nil
}

func decryptFile(inputPath, outputPath, password string) error {
	inFile, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer inFile.Close()

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(inFile, salt); err != nil {
		return err
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(inFile, nonce); err != nil {
		return err
	}

	key := deriveKey([]byte(password), salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	ciphertext, err := io.ReadAll(inFile)
	if err != nil {
		return err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return errors.New("decryption failed (wrong password or corrupted file)")
	}

	outFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outFile.Close()
	if _, err := outFile.Write(plaintext); err != nil {
		return err
	}

	fmt.Println(colorize("File decrypted successfully: " + outputPath, green))
	return nil
}

func main() {
	if len(os.Args) < 5 {
		fmt.Println(colorize("Usage: filecrypt encrypt|decrypt <input> <output> <password>", yellow))
		os.Exit(1)
	}
	mode := os.Args[1]
	input := os.Args[2]
	output := os.Args[3]
	password := os.Args[4]

	var err error
	switch mode {
	case "encrypt":
		err = encryptFile(input, output, password)
	case "decrypt":
		err = decryptFile(input, output, password)
	default:
		fmt.Println(colorize("Invalid mode. Use encrypt or decrypt.", red))
		os.Exit(1)
	}
	if err != nil {
		fmt.Println(colorize("Error: "+err.Error(), red))
		os.Exit(1)
	}
}
