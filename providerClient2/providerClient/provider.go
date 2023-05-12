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
	serverPort  = 8080
	addr        = "http://localhost:8080"
	pubKeyPath  = "./id_rsa_test"
	privKeyPath = "./id_rsa_test.pub"
)

func main() {
	command := flag.String("command", "help", "Enter the command you want to perform.")
	requestorId := flag.String("id", "1", "Enter your user id.")
	requestPath := flag.String("rp", "", "Enter the path to your access request.")
	patientId := flag.String("patid", "", "Enter the id of the patient whose record is being requested.")
	requestId := flag.String("rid", "", "Enter the id of the request you want to view.")
	providerId := flag.String("proid", "", "Enter the id of the provider whose requests you want to view")
	flag.Parse()

	fmt.Printf("\nCommand: %s\n", *command)

	switch {
	case *command == "Register":
		registerIdentity(*requestorId)
	case *command == "PublicKey":
		getPub(*requestorId)
	case *command == "ReqRecord":
		requestBytes, err := os.ReadFile(*requestPath)
		if err != nil {
			fmt.Println("\nError reading request\n")
		} else {
			requestRecord(*requestorId, *patientId, string(requestBytes))
		}
	case *command == "ReadRequest":
		readRequest(*requestorId, *requestId)
	case *command == "ViewProviderRequests":
		viewProviderRequests(*requestorId, *providerId)
	default:
		help()
	}
}

func help() {
	fmt.Print("Welcome to Hyper-Health, a blockchain solution for electronic health record transactions!\n")
	fmt.Print("\nHere is a list of valid commands:\n")
	fmt.Print("\nRegister identitiy: ./provider -command Register -id userIdentity\n")
	fmt.Print("Request record: ./provider -command ReqRecord -id userIdentity -patid patientId -rp pathToRequest\n")
	fmt.Print("Read request: ./provider -command ReadRequest -id userIdentity -rid requestId\n")
	fmt.Print("View provider requests: ./provider -command ViewProviderRequests -id userIdentity\n")
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

	req, err := http.NewRequest(http.MethodPost, "http://localhost:8080/invoke?function=Register", nil)
	if err != nil {
		log.Fatalln(err)
	}

	req.Header.Add("n", pub.N.String())
	req.Header.Add("e", strconv.Itoa(pub.E))
	req.Header.Add("id", id)

	fmt.Print("\nSubmitting Request...\n")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalln(err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	sb := string(body)
	fmt.Println(sb + "\n")
}

func getPub(id string) {
	req, err := http.NewRequest(http.MethodGet, "http://localhost:8080/invoke?function=GetPub", nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Add("id", id)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	sb := string(body)
	fmt.Println(sb)
}

func requestRecord(reqId, patId, request string) {
	msgStr := reqId + request
	msgBytes := []byte(msgStr)
	signature, err := utils.SignTransaction(privKeyPath, msgBytes)
	if err != nil {
		log.Fatal(err)
	}

	signEncoding := base64.StdEncoding.EncodeToString(signature)
	reqRead := strings.NewReader(request)

	req, err := http.NewRequest(http.MethodPost, "http://localhost:8080/invoke?function=RequestRecord", reqRead)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Add("id", reqId)
	req.Header.Add("pid", patId)
	req.Header.Add("signature", signEncoding)

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

func readRequest(reqId, rid string) {
	msgBytes := []byte(reqId + rid)
	signature, err := utils.SignTransaction(privKeyPath, msgBytes)
	if err != nil {
		log.Fatal(err)
	}

	signEncoding := base64.StdEncoding.EncodeToString(signature)

	req, err := http.NewRequest(http.MethodGet, "http://localhost:8080/invoke?function=ReadResponse", nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Add("id", reqId)
	req.Header.Add("rid", rid)
	req.Header.Add("signature", signEncoding)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	sb := string(body)
	fmt.Println(sb)
}

func viewProviderRequests(reqId, pid string) {
	msgBytes := []byte(reqId + pid)
	signature, err := utils.SignTransaction(privKeyPath, msgBytes)
	if err != nil {
		log.Fatal(err)
	}

	signEncoding := base64.StdEncoding.EncodeToString(signature)

	req, err := http.NewRequest(http.MethodGet, "http://localhost:8080/invoke?function=GetAllProviderRequests", nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Add("id", reqId)
	req.Header.Add("pid", pid)
	req.Header.Add("signature", signEncoding)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	sb := string(body)
	fmt.Println(sb)
}
