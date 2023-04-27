/*
Copyright 2021 IBM All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"time"

	utils "github.com/shane-novit9/hyper-health/utils"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// "google.golang.org/grpc/credentials/insecure"
type Request struct {
	Func string   `json:"func"`
	Args []string `json:"args"`
}

type Response struct {
	Result string `json:"result"`
	Error  string `json:"error"`
}

const (
	mspID         = "Org1MSP"
	cryptoPath    = "../../../../Thesis/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com"
	certPath      = cryptoPath + "/users/User1@org1.example.com/msp/signcerts/cert.pem"
	keyPath       = cryptoPath + "/users/User1@org1.example.com/msp/keystore/"
	tlsCertPath   = cryptoPath + "/peers/peer0.org1.example.com/tls/ca.crt"
	peerEndpoint  = "localhost:7051"
	gatewayPeer   = "peer0.org1.example.com"
	channelName   = "mychannel"
	chaincodeName = "xacml"
	pubKeyPath    = "./id_rsa_test"
	privKeyPath   = "./id_rsa_test.pub"
)

//var now = time.Now()

func main() {
	log.Println("============ application-golang starts ============")

	// The gRPC client connection should be shared by all Gateway connections to this endpoint
	clientConnection := newGrpcConnection()
	defer clientConnection.Close()

	id := newIdentity()
	sign := newSign()

	// Create a Gateway connection for a specific client identity
	gateway, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithClientConnection(clientConnection),
		// Default timeouts for different gRPC calls
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(5*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		panic(err)
	}
	defer gateway.Close()

	//Get the network and smart contract
	network := gateway.GetNetwork(channelName)
	contract := network.GetContract(chaincodeName)

	router := http.NewServeMux()

	router.HandleFunc("/hyper-health", displayWebHome)
	router.HandleFunc("/register", registration)
	router.HandleFunc("/login", login)
	router.HandleFunc("/invoke", func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		r.ParseForm()
		req := Request{Func: r.FormValue("function")}
		signature, _ := io.ReadAll(r.Body)

		log.Printf("sign: %v\n\n", string(signature))
		log.Printf("sign: %v\n\n", signature)

		switch {
		case req.Func == "InitLedger":
			initLedger(contract, w)
		case req.Func == "Register":
			n := r.Header.Get("n")
			e := r.Header.Get("e")
			id := r.Header.Get("id")
			fmt.Printf("\nN: %v\nE: %v\nID:%v\n", n, e, id)
			registerIdentity(contract, w, n, e, id)
		case req.Func == "GetPub":
			id := r.Header.Get("id")
			getPublicKey(contract, w, id)
		case req.Func == "InitLedger":
			initLedger(contract, w)
		case req.Func == "ReadPolicy":
			id := r.FormValue("patientId")
			readPolicy(contract, w, id)
		case req.Func == "CreatePolicy":
			id := r.Header.Get("id")
			xacmlPolicy := `<?xml version="1.0" encoding="UTF-8"?>
			<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" 
					xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
					xsi:schemaLocation="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17 http://docs.oasis-open.org/xacml/3.0/xacml-core-v3-schema-wd-17.xsd" 
					PolicyId="simple-policy" 
					Version="1.0" 
					RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides">
				<Description>Patient Policy</Description>
				<Target>
				  <AnyOf>
					<AllOf>
					  <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
						<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">
						  ^/record.txt</AttributeValue>
						<AttributeDesignator
						  MustBePresent="false"
						  Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource"
						  AttributeId="urn:oasis:names:tc:xacml:1.0:resource:resource-id" 
						  DataType="http://www.w3.org/2001/XMLSchema#string"/>
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
						  <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">
							Carl</AttributeValue>
						  <AttributeDesignator
							MustBePresent="false"
							Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"
							AttributeId="urn:oasis:names:tc:xacml:1.0:subject:subject-id"
							DataType="http://www.w3.org/2001/XMLSchema#string"/>
						</Match>
						<Match
						  MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
						  <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">
							read</AttributeValue>
						  <AttributeDesignator
							MustBePresent="false"
							Category="urn:oasis:names:tc:xacml:1.0:attribute-category:action"
							AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id"
							DataType="http://www.w3.org/2001/XMLSchema#string"/>
						</Match>
					  </AllOf>
					</AnyOf>
				  </Target>
				</Rule>
			</Policy>` //r.Header.Get("policy")
			createPolicy(contract, w, id, xacmlPolicy, signature)
		case req.Func == "UpdatePolicy":
			id := r.FormValue("patientId")
			xacmlPolicy := r.FormValue("xacmlPolicy")
			updatePolicy(contract, id, xacmlPolicy)
		case req.Func == "RequestRecord":
			patient := r.FormValue("patientId")
			provider := r.FormValue("providerId")
			request := r.FormValue("xacmlRequest")
			requestRecord(contract, w, patient, provider, request)
		case req.Func == "GetAllPatientRequests":
			patientId := r.FormValue("patientId")
			getAllPatientRequests(contract, w, patientId)
		case req.Func == "ReadResponse":
			requestId := r.FormValue("requestId")
			readResponse(contract, w, requestId)
		}
	})

	if err := http.ListenAndServe(":8080", router); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	log.Println("============ application-golang ends ============")
}

// newGrpcConnection creates a gRPC connection to the Gateway server.
func newGrpcConnection() *grpc.ClientConn {
	certificate, err := loadCertificate(tlsCertPath)
	if err != nil {
		panic(err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(certificate)
	transportCredentials := credentials.NewClientTLSFromCert(certPool, gatewayPeer)

	connection, err := grpc.Dial(peerEndpoint, grpc.WithTransportCredentials(transportCredentials))
	if err != nil {
		panic(fmt.Errorf("failed to create gRPC connection: %w", err))
	}

	return connection
}

// newIdentity creates a client identity for this Gateway connection using an X.509 certificate.
func newIdentity() *identity.X509Identity {
	certificate, err := loadCertificate(certPath)
	if err != nil {
		panic(err)
	}

	id, err := identity.NewX509Identity(mspID, certificate)
	if err != nil {
		panic(err)
	}

	return id
}

func loadCertificate(filename string) (*x509.Certificate, error) {
	certificatePEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}
	return identity.CertificateFromPEM(certificatePEM)
}

// newSign creates a function that generates a digital signature from a message digest using a private key.
func newSign() identity.Sign {
	files, err := os.ReadDir(keyPath)
	if err != nil {
		panic(fmt.Errorf("failed to read private key directory: %w", err))
	}
	privateKeyPEM, err := os.ReadFile(path.Join(keyPath, files[0].Name()))

	if err != nil {
		panic(fmt.Errorf("failed to read private key file: %w", err))
	}

	privateKey, err := identity.PrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		panic(err)
	}

	sign, err := identity.NewPrivateKeySign(privateKey)
	if err != nil {
		panic(err)
	}

	return sign
}

func displayWebHome(w http.ResponseWriter, r *http.Request) {
	render(w, "templates/SystemHomepage.html", nil)
}

func registration(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		render(w, "templates/Registration.html", nil)
	case http.MethodPost: // Handle account registration
		r.ParseForm()
		webUser := &utils.WebUser{
			Email:           r.FormValue("email"),
			FirstName:       r.FormValue("firstname"),
			LastName:        r.FormValue("lastname"),
			Password:        r.FormValue("password"),
			PasswordConfirm: r.FormValue("passconfirm"),
		}

		// Verify account does not exist (AccountDAO)

		// Validate create user form
		if !webUser.Validate() {
			webUser.Errors = make(map[string]string)
			render(w, "templates/Registration.html", webUser)
		}
		// Write Account to DB (AppService, DAO, and Repository)

		// Generate public/private keys
		err := utils.MakeSSHKeyPair(pubKeyPath, privKeyPath)
		if err != nil {
			http.Error(w, "Failed to generate keys", http.StatusInternalServerError)
		}

		// Redirect to AccountConfirmation.html
		render(w, "templates/AccountConfirmation.html", webUser)
	default:
		http.Error(w, "Not an acceptable method", http.StatusMethodNotAllowed)
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		render(w, "templates/Login.html", nil)
	case http.MethodPost:
		r.ParseForm()
		email := r.FormValue("email")
		pass := r.FormValue("password")

		log.Printf("Login attempt: %v", email+pass)
	}
}

func registerIdentity(contract *client.Contract, w http.ResponseWriter, n, e, id string) {
	result, err := contract.SubmitTransaction("Register", id, n, e)
	if err != nil {
		switch err := err.(type) {
		case *client.EndorseError:
			fmt.Printf("Endorse error with gRPC status %v: %s\n", status.Code(err), err)
		case *client.SubmitError:
			fmt.Printf("Submit error with gRPC status %v: %s\n", status.Code(err), err)
		case *client.CommitStatusError:
			if errors.Is(err, context.DeadlineExceeded) {
				fmt.Printf("Timeout waiting for transaction %s commit status: %s", err.TransactionID, err)
			} else {
				fmt.Printf("Error obtaining commit status with gRPC status %v: %s\n", status.Code(err), err)
			}
		case *client.CommitError:
			fmt.Printf("Transaction %s failed to commit with status %d: %s\n", err.TransactionID, int32(err.Code), err)
		}

		// Any error that originates from a peer or orderer node external to the gateway will have its details
		// embedded within the gRPC status error. The following code shows how to extract that.
		statusErr := status.Convert(err)
		fmt.Printf("\nStatus Error: \n%#v", statusErr)
		panic(fmt.Errorf("failed to submit transaction: %w", err))
	}
	resp := Response{
		Result: string(result),
		Error:  "",
	}
	responseJSON, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(responseJSON); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func getPublicKey(contract *client.Contract, w http.ResponseWriter, id string) {
	result, err := contract.EvaluateTransaction("GetPublicKey", id)
	if err != nil {
		panic(fmt.Errorf("failed to submit transaction: %w", err))
	}
	resp := Response{
		Result: string(result),
		Error:  "",
	}
	responseJSON, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(responseJSON); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// Evaluate a transaction to query ledger state.
func readPolicy(contract *client.Contract, w http.ResponseWriter, id string) {
	fmt.Println("Evaluate Transaction: GetAllAssets, function returns all the current assets on the ledger")

	evaluateResult, err := contract.EvaluateTransaction("ReadPolicy", id)
	if err != nil {
		panic(fmt.Errorf("failed to evaluate transaction: %w", err))
	}
	result := formatJSON(evaluateResult)

	resp := Response{Result: string(result)}
	responseJSON, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(responseJSON); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// This type of transaction would typically only be run once by an application the first time it was started after its
// initial deployment. A new version of the chaincode deployed later would likely not need to run an "init" function.
func initLedger(contract *client.Contract, w http.ResponseWriter) {
	fmt.Printf("Submit Transaction: InitLedger, function creates the initial set of assets on the ledger \n")

	result, err := contract.SubmitTransaction("InitLedger")
	if err != nil {
		panic(fmt.Errorf("failed to submit transaction: %w", err))
	}

	resp := Response{Result: string(result)}
	responseJSON, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(responseJSON); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// Submit a transaction synchronously, blocking until it has been committed to the ledger.
func createPolicy(contract *client.Contract, w http.ResponseWriter, id, policy string, signature []byte) {
	fmt.Printf("Submit Transaction: CreatePolicy, intended for adding a new Patient's Record Access Policy \n")

	result, err := contract.SubmitTransaction("CreatePolicy", id, policy, string(signature))
	if err != nil {
		panic(fmt.Errorf("failed to submit transaction: %w", err))
	}

	resp := Response{Result: string(result)}
	responseJSON, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(responseJSON); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// Evaluate a transaction by assetID to query ledger state.
func updatePolicy(contract *client.Contract, id, policy string) {
	fmt.Printf("Evaluate Transaction: ReadAsset, function returns asset attributes\n")

	_, err := contract.SubmitTransaction("UpdatePolicy", id, policy)
	if err != nil {
		panic(fmt.Errorf("failed to evaluate transaction: %w", err))
	}

	fmt.Printf("*** Transaction committed successfully\n")
}

func requestRecord(contract *client.Contract, w http.ResponseWriter, patientId, providerId, request string) {
	fmt.Printf("Evaluate Transaction: RequestRecord, function requests a response from the channel's XACML Policy Decision Point")

	response, err := contract.SubmitTransaction("RequestRecord", patientId, providerId, request)
	if err != nil {
		switch err := err.(type) {
		case *client.EndorseError:
			fmt.Printf("Endorse error with gRPC status %v: %s\n", status.Code(err), err)
		case *client.SubmitError:
			fmt.Printf("Submit error with gRPC status %v: %s\n", status.Code(err), err)
		case *client.CommitStatusError:
			if errors.Is(err, context.DeadlineExceeded) {
				fmt.Printf("Timeout waiting for transaction %s commit status: %s", err.TransactionID, err)
			} else {
				fmt.Printf("Error obtaining commit status with gRPC status %v: %s\n", status.Code(err), err)
			}
		case *client.CommitError:
			fmt.Printf("Transaction %s failed to commit with status %d: %s\n", err.TransactionID, int32(err.Code), err)
		}

		// Any error that originates from a peer or orderer node external to the gateway will have its details
		// embedded within the gRPC status error. The following code shows how to extract that.
		statusErr := status.Convert(err)
		fmt.Printf("\nStatus Error: \n%#v", statusErr)
	}

	resp := Response{
		Result: string(response),
		Error:  "",
	}
	responseJSON, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(responseJSON); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func getAllPatientRequests(contract *client.Contract, w http.ResponseWriter, patientId string) {
	response, err := contract.EvaluateTransaction("GetAllPatientRequests", patientId)
	if err != nil {
		panic(fmt.Errorf("failed to evaluate transaction: %w", err))
	}
	fmt.Printf("Requests: %+v\n", response)
	result := formatJSON(response)
	resp := Response{
		Result: string(result),
		Error:  "",
	}
	json, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(json); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func readResponse(contract *client.Contract, w http.ResponseWriter, requestId string) {
	response, err := contract.EvaluateTransaction("ReadResponce", requestId)
	if err != nil {
		panic(fmt.Errorf("failed to evaluate transaction: %w", err))
	}

	resp := Response{
		Result: string(response),
		Error:  "",
	}

	respJSON, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(respJSON); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// Submit transaction asynchronously, blocking until the transaction has been sent to the orderer, and allowing
// this thread to process the chaincode response (e.g. update a UI) without waiting for the commit notification
/*func transferAssetAsync(contract *client.Contract) {
	fmt.Printf("Async Submit Transaction: TransferAsset, updates existing asset owner'\n")

	submitResult, commit, err := contract.SubmitAsync("TransferAsset", client.WithArguments(assetId, "Mark"))
	if err != nil {
		panic(fmt.Errorf("failed to submit transaction asynchronously: %w", err))
	}

	fmt.Printf("Successfully submitted transaction to transfer ownership from %s to Mark. \n", string(submitResult))
	fmt.Println("Waiting for transaction commit.")

	if status, err := commit.Status(); err != nil {
		panic(fmt.Errorf("failed to get commit status: %w", err))
	} else if !status.Successful {
		panic(fmt.Errorf("transaction %s failed to commit with status: %d", status.TransactionID, int32(status.Code)))
	}

	fmt.Printf("*** Transaction committed successfully\n")
}

// Submit transaction, passing in the wrong number of arguments ,expected to throw an error containing details of any error responses from the smart contract.
func exampleErrorHandling(contract *client.Contract) {
	fmt.Println("Submit Transaction: UpdateAsset asset70, asset70 does not exist and should return an error")

	_, err := contract.SubmitTransaction("UpdateAsset")
	if err != nil {
		switch err := err.(type) {
		case *client.EndorseError:
			fmt.Printf("Endorse error with gRPC status %v: %s\n", status.Code(err), err)
		case *client.SubmitError:
			fmt.Printf("Submit error with gRPC status %v: %s\n", status.Code(err), err)
		case *client.CommitStatusError:
			if errors.Is(err, context.DeadlineExceeded) {
				fmt.Printf("Timeout waiting for transaction %s commit status: %s", err.TransactionID, err)
			} else {
				fmt.Printf("Error obtaining commit status with gRPC status %v: %s\n", status.Code(err), err)
			}
		case *client.CommitError:
			fmt.Printf("Transaction %s failed to commit with status %d: %s\n", err.TransactionID, int32(err.Code), err)
		}

		// Any error that originates from a peer or orderer node external to the gateway will have its details
		// embedded within the gRPC status error. The following code shows how to extract that.
		statusErr := status.Convert(err)
		for _, detail := range statusErr.Details() {
			switch detail := detail.(type) {
			case *gateway.ErrorDetail:
				fmt.Printf("Error from endpoint: %s, mspId: %s, message: %s\n", detail.Address, detail.MspId, detail.Message)
			}
		}
	}
} */

// Format JSON data
func formatJSON(data []byte) string {
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, data, " ", ""); err != nil {
		panic(fmt.Errorf("failed to parse JSON: %w", err))
	}
	return prettyJSON.String()
}

func render(w http.ResponseWriter, filename string, data interface{}) {
	tmpl, err := template.ParseFiles(filename)
	if err != nil {
		http.Error(w, "Template file not found", http.StatusNotFound)
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "Sorry, something went wrong", http.StatusInternalServerError)
	}
}
