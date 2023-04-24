package utils

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
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

func GetPublicKeyValues(privateKeyPath string) (*big.Int, int, error) {
	priv, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, -1, err
	}

	pubPem, _ := pem.Decode(priv)
	if pubPem == nil {
		return nil, -1, fmt.Errorf("error - failed to decode key")
	}
	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(pubPem.Bytes)
	if err != nil {
		return nil, -1, err
	}

	public := rsaPrivateKey.PublicKey
	fmt.Println(public)
	return public.N, public.E, nil
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
