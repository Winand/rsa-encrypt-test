package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"

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

func main() {
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
	print(len(string(pubKeyBytes)))
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
	print(len(string(privKeyBytes)))
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
	print(decryptedMsg)
}
