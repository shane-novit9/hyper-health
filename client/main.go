package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"

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
	policyPath := flag.String("pp", "", "Enter the path to your access policy.")
	//request := flag.String("request", "", "Enter your record request.")
	flag.Parse()
	fmt.Printf("\nCommand: %s\n", *command)

	switch {
	case *command == "Register":
		registerIdentity(*id)
	case *command == "PublicKey":
		getPub(*id)
	case *command == "CreatePolicy":
		policyBytes, err := os.ReadFile(*policyPath)
		if err != nil {
			fmt.Println("Error reading policy")
		} else {
			createPolicy(*id, string(policyBytes))
		}
	case *command == "UpdatePolicy":
		updatePolicy(*id)
	}
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

func createPolicy(id, policy string) {
	msgStr := id + policy
	msgBytes := []byte(msgStr)
	signature, err := utils.SignTransaction(privKeyPath, msgBytes)
	if err != nil {
		log.Fatal(err)
	}

	reader := bytes.NewReader(signature)
	fmt.Printf("\nSign: %v\n", signature)

	req, err := http.NewRequest(http.MethodPost, "http://localhost:8080/invoke?function=CreatePolicy", reader)
	if err != nil {
		log.Fatalln(err)
	}

	req.Header.Add("id", id)
	//req.Header.Add("policy", policy)

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

func updatePolicy(id string) {
	/*msgStr := id + policy
	signature, err := utils.SignTransaction(privKeyPath, []byte(msgStr))
	if err != nil {
		log.Fatal(err)
	}*/

	req, err := http.NewRequest(http.MethodPost, "http://localhost:8080/invoke?function=UpdatePolicy&patientId="+id+`&xacmlPolicy=<?xml version="1.0" encoding="UTF-8"?><Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17 http://docs.oasis-open.org/xacml/3.0/xacml-core-v3-schema-wd-17.xsd"
	PolicyId="simple-policy"
	Version="1.0"
	RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides">
	<Description>Patient Policy</Description>
	<Target>
	<AnyOf>
	<AllOf>
	<Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
	<AttributeValue DataType="http://www.w3.org/2001/XMLSchema%23string">
	^/record.txt</AttributeValue>
	<AttributeDesignator
	MustBePresent="false"
	Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource"
	AttributeId="urn:oasis:names:tc:xacml:1.0:resource:resource-id"
	DataType="http://www.w3.org/2001/XMLSchema%23string"/>
	</Match>
	</AllOf>
	</AnyOf>
	</Target>
	<Rule
	RuleId="urn:oasis:names:tc:xacml:3.0:example:SimpleRule"
	Effect="Deny">
	<Description>
	Deny record access
	</Description>
	<Target>
	<AnyOf>
	<AllOf>
	<Match
	MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
	<AttributeValue DataType="http://www.w3.org/2001/XMLSchema%23string">
	Carl</AttributeValue>
	<AttributeDesignator
	MustBePresent="false"
	Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"
	AttributeId="urn:oasis:names:tc:xacml:1.0:subject:subject-id"
	DataType="http://www.w3.org/2001/XMLSchema%23string"/>
	</Match>
	<Match
	MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
	<AttributeValue DataType="http://www.w3.org/2001/XMLSchema%23string">
	read</AttributeValue>
	<AttributeDesignator
	MustBePresent="false"
	Category="urn:oasis:names:tc:xacml:1.0:attribute-category:action"
	AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id"
	DataType="http://www.w3.org/2001/XMLSchema%23string"/>
	</Match>
	</AllOf>
	</AnyOf>
	</Target>
	</Rule>
	</Policy>`, nil)
	if err != nil {
		log.Fatalln(err)
	}

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
