package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/shane-novit9/hyper-health/utils"
)

const (
	pubKeyPath  = "./id_rsa_test"
	privKeyPath = "./id_rsa_test.pub"
)

func main() {
	command := flag.String("command", "help", "Enter the command you want to perform.")
	requestorId := flag.String("id", "1", "Enter your user id.")
	policyPath := flag.String("pp", "", "Enter the path to your access policy.")
	requestId := flag.String("rid", "", "Enter the id of the request you want to view.")
	flag.Parse()

	fmt.Printf("\nCommand: %s\n", *command)

	switch {
	case *command == "Register":
		registerIdentity(*requestorId)
	case *command == "CreatePolicy":
		policyBytes, err := os.ReadFile(*policyPath)
		if err != nil {
			fmt.Println("Error reading policy")
		} else {
			createPolicy(*requestorId, string(policyBytes))
		}
	case *command == "UpdatePolicy":
		policyBytes, err := os.ReadFile(*policyPath)
		if err != nil {
			fmt.Println("Error reading policy")
		} else {
			updatePolicy(*requestorId, string(policyBytes))
		}
	case *command == "ReadRequest":
		readRequest(*requestorId, *requestId)
	case *command == "ReadPolicy":
		readPolicy(*requestorId)
	case *command == "ViewPatientRequests":
		viewPatientRequests(*requestorId)
	default:
		help()
	}
}

func help() {
	fmt.Print("Welcome to Hyper-Health, a blockchain solution for electronic health record transactions!\n")
	fmt.Print("\nHere is a list of valid commands:\n")
	fmt.Print("\nRegister identitiy: ./patient -command Register -id userIdentity\n")
	fmt.Print("Create policy: ./patient -command CreatePolicy -id userIdentity -pp pathToPolicy\n")
	fmt.Print("Update policy: ./patient -command UpdatePolicy -id userIdentity -pp pathToPolicy\n")
	fmt.Print("Read policy: ./patient -command ReadPolicy -id userIdentity\n")
	fmt.Print("View patient requests: ./patient -command ViewPatientRequests -id userIdentity\n\n")
}

func generateKeys() {
	fmt.Print("\nMaking RSA Key Pair...\n")
	utils.MakeSSHKeyPair(pubKeyPath, privKeyPath)
	fmt.Print("Done.\n")
}

func registerIdentity(id string) {
	generateKeys()

	fmt.Print("\nGetting public key...\n")
	pub, err := utils.GetPublicKey(privKeyPath)
	if err != nil {
		log.Fatalln(err)
	}

	// Create HTTP Request
	req, err := http.NewRequest(http.MethodPost, "http://localhost:8080/invoke?function=Register", nil)
	if err != nil {
		log.Fatalln(err)
	}

	// Add Public Key data and User ID to the request header
	req.Header.Add("n", pub.N.String())
	req.Header.Add("e", strconv.Itoa(pub.E))
	req.Header.Add("id", id)

	// Execute the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalln(err)
	}

	// Read Response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	// Display Response
	sb := string(body)
	fmt.Println(sb + "\n")
}

func createPolicy(id, policy string) {
	// Package and sign transaction attributes
	msgStr := id + policy
	msgBytes := []byte(msgStr)
	signature, err := utils.SignTransaction(privKeyPath, msgBytes)
	if err != nil {
		log.Fatal(err)
	}

	// Encode signature, so it can be added to the HTTP Req Header
	signEncoding := base64.StdEncoding.EncodeToString(signature)

	// Create policy reader
	policyRead := strings.NewReader(policy)

	// Create HTTP Request
	req, err := http.NewRequest(http.MethodPost, "http://localhost:8080/invoke?function=CreatePolicy", policyRead)
	if err != nil {
		log.Fatalln(err)
	}

	// Add transaction attributes to Req Header
	req.Header.Add("id", id)
	req.Header.Add("signature", signEncoding)

	// Execute Request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalln(err)
	}

	// Read Response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	//Display Response
	sb := string(body)
	fmt.Println(sb)
}

func updatePolicy(id, policy string) {
	// Package and sign transaction attributes
	msgStr := id + policy
	msgBytes := []byte(msgStr)
	signature, err := utils.SignTransaction(privKeyPath, msgBytes)
	if err != nil {
		log.Fatal(err)
	}

	// Encode signature
	signEncoding := base64.StdEncoding.EncodeToString(signature)

	// Create policy reader
	policyRead := strings.NewReader(policy)

	// Create HTTP Request
	req, err := http.NewRequest(http.MethodPost, "http://localhost:8080/invoke?function=UpdatePolicy", policyRead)
	if err != nil {
		log.Fatalln(err)
	}

	// Add transaction attributes to Req Header
	req.Header.Add("id", id)
	req.Header.Add("signature", signEncoding)

	// Execute Request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalln(err)
	}

	// Read Response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	// Display Response
	sb := string(body)
	fmt.Println(sb)
}

func readRequest(reqId, rid string) {
	// Package and sign transaction attributes
	msgStr := reqId + rid
	msgBytes := []byte(msgStr)
	signature, err := utils.SignTransaction(privKeyPath, msgBytes)
	if err != nil {
		log.Fatal(err)
	}

	// Encode signature
	signEncoding := base64.StdEncoding.EncodeToString(signature)

	// Create Request
	req, err := http.NewRequest(http.MethodGet, "http://localhost:8080/invoke?function=ReadResponse", nil)
	if err != nil {
		log.Fatal(err)
	}

	// Add transaction attributes to Req Header
	req.Header.Add("id", reqId)
	req.Header.Add("rid", rid)
	req.Header.Add("signature", signEncoding)

	// Execute Request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	// Read Response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	// Display Response
	sb := string(body)
	fmt.Println(sb)
}

func readPolicy(reqId string) {
	// Create HTTP Request
	req, err := http.NewRequest(http.MethodGet, "http://localhost:8080/invoke?function=ReadPolicy", nil)
	if err != nil {
		log.Fatal(err)
	}

	// Add transaction attributes to the Req Header
	req.Header.Add("id", reqId)

	// Execute Request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	// Read Response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	// Display Response
	sb := string(body)
	fmt.Println(sb)
}

func viewPatientRequests(reqId string) {
	// Package and sign transaction attributes
	signature, err := utils.SignTransaction(privKeyPath, []byte(reqId))
	if err != nil {
		log.Fatal(err)
	}

	// Encode signatute
	signEncoding := base64.StdEncoding.EncodeToString(signature)

	// Create HTTP Request
	req, err := http.NewRequest(http.MethodGet, "http://localhost:8080/invoke?function=GetAllPatientRequests", nil)
	if err != nil {
		log.Fatal(err)
	}

	// Add transaction attributes to Req Header
	req.Header.Add("id", reqId)
	req.Header.Add("signature", signEncoding)

	// Execute Request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	// Read Response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	// Display Response
	sb := string(body)
	fmt.Println(sb)
}
