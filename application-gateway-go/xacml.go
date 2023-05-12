/*
Copyright 2021 IBM All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
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

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

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

	router.HandleFunc("/invoke", func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		r.ParseForm()
		req := Request{Func: r.FormValue("function")}

		switch {
		case req.Func == "Register":
			n := r.Header.Get("n")
			e := r.Header.Get("e")
			id := r.Header.Get("id")
			registerIdentity(contract, w, n, e, id)
		case req.Func == "ReadPolicy":
			id := r.Header.Get("id")
			readPolicy(contract, w, id)
		case req.Func == "CreatePolicy":
			policy, err := io.ReadAll(r.Body)
			if err != nil {
				log.Fatal(err)
			}
			id := r.Header.Get("id")
			signature, _ := base64.StdEncoding.DecodeString(r.Header.Get("signature"))
			createPolicy(contract, w, id, string(policy), signature)
		case req.Func == "UpdatePolicy":
			policy, err := io.ReadAll(r.Body)
			if err != nil {
				log.Fatal(err)
			}
			id := r.Header.Get("id")
			signature, _ := base64.StdEncoding.DecodeString(r.Header.Get("signature"))
			updatePolicy(contract, w, id, string(policy), signature)
		case req.Func == "RequestRecord":
			request, err := io.ReadAll(r.Body)
			if err != nil {
				log.Fatal(err)
			}
			patient := r.Header.Get("pid")
			provider := r.Header.Get("id")
			signature, _ := base64.StdEncoding.DecodeString(r.Header.Get("signature"))
			requestRecord(contract, w, patient, provider, string(request), signature)
		case req.Func == "GetAllPatientRequests":
			patientId := r.Header.Get("id")
			signature, _ := base64.StdEncoding.DecodeString(r.Header.Get("signature"))
			getAllPatientRequests(contract, w, patientId, signature)
		case req.Func == "GetAllProviderRequests":
			id := r.Header.Get("id")
			pid := r.Header.Get("pid")
			signature, _ := base64.StdEncoding.DecodeString(r.Header.Get("signature"))
			getAllProviderRequests(contract, w, id, pid, signature)
		case req.Func == "ReadResponse":
			id := r.Header.Get("id")
			requestId := r.Header.Get("rid")
			signature, _ := base64.StdEncoding.DecodeString(r.Header.Get("signature"))
			readResponse(contract, w, requestId, id, signature)
		}
	})

	if err := http.ListenAndServe(":8080", router); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
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

func registerIdentity(contract *client.Contract, w http.ResponseWriter, n, e, id string) {
	_, err := contract.SubmitTransaction("Register", id, n, e)
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
		Result: "Registration successful, welcome!",
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

// Submit a transaction synchronously, blocking until it has been committed to the ledger.
func createPolicy(contract *client.Contract, w http.ResponseWriter, id, policy string, signature []byte) {
	fmt.Printf("Submit Transaction: CreatePolicy, intended for adding a new Patient's Record Access Policy \n")

	_, err := contract.SubmitTransaction("CreatePolicy", id, policy, string(signature))
	if err != nil {
		panic(fmt.Errorf("failed to submit transaction: %w", err))
	}

	resp := Response{Result: "Policy created."}
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
func updatePolicy(contract *client.Contract, w http.ResponseWriter, id, policy string, signature []byte) {
	fmt.Printf("Evaluate Transaction: ReadAsset, function returns asset attributes\n")

	_, err := contract.SubmitTransaction("UpdatePolicy", id, policy, string(signature))
	if err != nil {
		panic(fmt.Errorf("failed to evaluate transaction: %w", err))
	}

	resp := Response{Result: "Policy updated."}
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

func requestRecord(contract *client.Contract, w http.ResponseWriter, patientId, providerId, request string, signature []byte) {
	fmt.Printf("Evaluate Transaction: RequestRecord, function requests a response from the channel's XACML Policy Decision Point\n")
	response, err := contract.SubmitTransaction("RequestRecord", patientId, providerId, request, string(signature))
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

func getAllPatientRequests(contract *client.Contract, w http.ResponseWriter, patientId string, signature []byte) {
	response, err := contract.EvaluateTransaction("GetAllPatientRequests", patientId, string(signature))
	if err != nil {
		panic(fmt.Errorf("failed to evaluate transaction: %w", err))
	}
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

func getAllProviderRequests(contract *client.Contract, w http.ResponseWriter, id, providerId string, signature []byte) {
	response, err := contract.EvaluateTransaction("GetAllProviderRequests", id, providerId, string(signature))
	if err != nil {
		panic(fmt.Errorf("failed to evaluate transaction: %w", err))
	}
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

func readResponse(contract *client.Contract, w http.ResponseWriter, requestId, id string, signature []byte) {
	response, err := contract.EvaluateTransaction("ReadResponce", requestId, id, string(signature))
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
