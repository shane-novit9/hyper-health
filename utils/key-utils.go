package utils

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

// MakeSSHKeyPair make a pair of public and private keys for SSH access.
// Public key is encoded in the format for inclusion in an OpenSSH authorized_keys file.
// Private Key generated is PEM encoded
func MakeSSHKeyPair(pubKeyPath, privateKeyPath string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return err
	}

	// generate and write private key as PEM
	privateKeyFile, err := os.Create(privateKeyPath)
	if err != nil {
		return err
	}
	defer privateKeyFile.Close()

	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return err
	}

	// generate and write public key
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}
	return os.WriteFile(pubKeyPath, ssh.MarshalAuthorizedKey(pub), 0655)
}

func GetPublicKey(pubKeyPath string) (*rsa.PublicKey, error) {
	pubPem, err := GetPublicKeyBlock(pubKeyPath)

	parsedKey, err := x509.ParsePKCS1PublicKey(pubPem.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error - failed to parse public key")
	}
	return parsedKey, nil
}

func GetPublicKeyBlock(pubKeyPath string) (*pem.Block, error) {
	pub, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return nil, err
	}

	pubPem, _ := pem.Decode(pub)
	if pubPem == nil {
		return nil, fmt.Errorf("error - failed to decode key")
	}

	return pubPem, nil
}

func SignTransaction(privKeyPath string, msg []byte) ([]byte, error) {
	hashed := sha256.Sum256(msg)

	pemBytes, err := os.ReadFile(privKeyPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemBytes)
	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	signature, err := rsa.SignPKCS1v15(nil, rsaPrivateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, err
	}
	return signature, nil
}
