package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/shane-novit9/hyper-health/utils"
)

const (
	serverPort  = 8080
	addr        = "http://localhost:8080"
	pubKeyPath  = "./id_rsa_test"
	privKeyPath = "./id_rsa_test.pub"
)

func main() {
	fmt.Print("Welcome to Hyper-Health, a blockchain solution for electronic health record transactions!\n")
	fmt.Print("\nHere is a list of valid commands:\n")

	command := flag.String("command", "help", "Enter the command you want to perform.")
	id := flag.String("id", "1", "Enter your user id.")
	policy := flag.String("policy", "", "Enter your records access policy.")
	//request := flag.String("request", "", "Enter your record request.")
	flag.Parse()
	fmt.Printf("Command: %s\n", *command)

	switch {
	case *command == "InitLedger":
		initLedger()
	case *command == "Register":
		registerIdentity(*id)
	case *command == "CreatePolicy":
		createPolicy(*id, *policy)
	}

}

func initLedger() {
	reqURL := fmt.Sprintf("http://localhost:%d/invoke/function=InitLedger", serverPort)
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		log.Fatalln(err)
	}

	resp, err := http.DefaultClient.Do(req)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	sb := string(body)
	fmt.Print(sb)
}

func generateKeys() {
	fmt.Print("\nMaking RSA Key Pair...\n")
	utils.MakeSSHKeyPair(pubKeyPath, privKeyPath)
	fmt.Print("Done.\n")
}

func registerIdentity(id string) {
	generateKeys()

	fmt.Print("\nGetting public key...\n")
	n, e, err := utils.GetPublicKeyValues(privKeyPath)
	if err != nil {
		log.Fatalln(err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://localhost:8080/invoke/function=Register", nil)
	if err != nil {
		log.Fatalln(err)
	}

	req.Header.Add("n", string(n))
	req.Header.Add("e", string(e))
	req.Header.Add("id", id)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalln(err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	sb := string(body)
	fmt.Println(sb)
}

func createPolicy(id, policy string) {
	msgStr := id + policy
	msgBytes := []byte(msgStr)
	signature, err := utils.SignTransaction(privKeyPath, msgBytes)
	if err != nil {
		log.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodPost, "http://localhost:8080/invoke/function=CreatePolicy", nil)
	if err != nil {
		log.Fatalln(err)
	}

	req.Header.Add("signature", string(signature))
	req.Header.Add("id", id)
	req.Header.Add("policy", policy)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalln(err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	sb := string(body)
	fmt.Println(sb)
}
