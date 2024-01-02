package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ssh"
)

// Loads ssh public key as a rsa.PublicKey
func parseRSAPublicKey(publicKey []byte) (*rsa.PublicKey, error) {
	parsed, _, _, _, err := ssh.ParseAuthorizedKey(publicKey)
	if err != nil {
		return nil, err
	}
	// ssh.PublicKey to ssh.CryptoPublicKey interface
	parsedCryptoKey := parsed.(ssh.CryptoPublicKey)
	cryptoPub := parsedCryptoKey.CryptoPublicKey()
	// crypto.PublicKey to *rsa.PublicKey interface
	pub, ok := cryptoPub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("provided key is not a RSA public key")
	}
	return pub, nil
}

// Loads ssh private key as a rsa.PrivateKey
func parseRSAPrivateKey(privKey []byte) (*rsa.PrivateKey, error) {
	// https://stackoverflow.com/a/71602731
	parsed, err := ssh.ParseRawPrivateKey(privKey)
	if err != nil {
		return nil, err
	}
	priv, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("provided key is not a RSA private key")
	}
	return priv, nil
}

// Encrypt any string with rsa.PublicKey
func encryptString(text string, pub *rsa.PublicKey) ([]byte, error) {
	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(), rand.Reader, pub, []byte(text), nil,
	)
	if err != nil {
		return nil, err
	}
	return encryptedBytes, nil
}

// Decrypt byte array with rsa.PrivateKey
func decryptBytes(data []byte, priv *rsa.PrivateKey) (string, error) {
	decryptedBytes, err := rsa.DecryptOAEP(
		sha256.New(), rand.Reader, priv, data, nil,
	)
	if err != nil {
		return "", err
	}
	return string(decryptedBytes), nil
}

// Get key for `openssl enc -aes-256-cbc -pbkdf2`
func getKeyPbkdf2(passw string, salt []byte) (key []byte, iv []byte) {
	iter := 10000 // default iterations for -pbkdf2
	keyLen := 32
	ivLen := 16
	md := sha256.New // default algorithm https://www.openssl.org/docs/man1.1.1/man1/enc.html
	// iv https://github.com/Luzifer/go-openssl/blob/09f71957dadea1cd288accd53bbe1a5bf9824a83/keys.go#L87
	dat := pbkdf2.Key([]byte(passw), salt, iter, keyLen+ivLen, md)
	key = dat[0:keyLen]
	iv = dat[keyLen:]
	return
}

// Reads a file encrypted with `openssl enc -aes-256-cbc -pbkdf2`
// Returns encrypted data and salt
func readAESFile(path string) (data []byte, salt []byte, err error) {
	data, err = os.ReadFile(path)
	if err != nil {
		return
	}
	if string(data[:8]) == "Salted__" {
		salt = data[8:16]
		data = data[16:]
	}
	return
}

func decryptAES(encdata, key, iv []byte) (data []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	blockmode := cipher.NewCBCDecrypter(block, iv)
	data = make([]byte, len(encdata))
	blockmode.CryptBlocks(data, encdata)
	padLen := int(data[len(data)-1])
	data = data[:len(data)-padLen]
	return
}

func main() {
	fmt.Println("### RSA encryption test ###")
	msg := `Привет, мир!`

	pubKeyBytes, err := os.ReadFile("./keys/client/ssh_key.pub")
	if err != nil {
		fmt.Printf("Failed to read file: %v\n", err)
		return
	}
	pubKey, err := parseRSAPublicKey(pubKeyBytes)
	if err != nil {
		fmt.Printf("Failed to parse key: %v\n", err)
		return
	}
	// fmt.Println("Public key length:", len(string(pubKeyBytes)))
	encryptedMsg, err := encryptString(msg, pubKey)
	if err != nil {
		fmt.Printf("Failed to encrypt string: %v\n", err)
		return
	}
	// print(base64.StdEncoding.EncodeToString(encryptedMsg))

	privKeyBytes, err := os.ReadFile("./keys/client/ssh_key")
	if err != nil {
		fmt.Printf("Failed to read file: %v\n", err)
		return
	}
	// fmt.Println("Private key length:", len(string(privKeyBytes)))
	privKey, err := parseRSAPrivateKey(privKeyBytes)
	if err != nil {
		fmt.Printf("Failed to parse key: %v\n", err)
		return
	}
	// print(string(privKey))
	decryptedMsg, err := decryptBytes(encryptedMsg, privKey)
	if err != nil {
		fmt.Printf("Failed to decrypt data: %v\n", err)
		return
	}
	fmt.Println("Decrypted message:", decryptedMsg)

	//----------------------------------------------------------
	fmt.Println("### AES decryption test ###")
	passwordBytes, err := os.ReadFile("./rsa-output/password")
	if err != nil {
		fmt.Printf("Failed to read password file: %v\n", err)
		return
	}
	password := strings.TrimSpace(string(passwordBytes))
	fmt.Println("Password:", password)

	encBytes, salt, err := readAESFile("./rsa-output/image.png.enc")
	if err != nil {
		fmt.Printf("Failed to read encrypted file: %v\n", err)
		return
	}
	aesKey, aesIV := getKeyPbkdf2(password, salt)
	fmt.Println("Key:", hex.EncodeToString(aesKey))
	fmt.Println("IV:", hex.EncodeToString(aesIV))

	decBytes, err := decryptAES(encBytes, aesKey, aesIV)
	if err != nil {
		fmt.Printf("Failed to decrypt data: %v\n", err)
		return
	}
	os.WriteFile("image-dec.png", decBytes, 0644)
}
