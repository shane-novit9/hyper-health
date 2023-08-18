package chaincode

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math/big"
	"strconv"

	"github.com/shane-novit9/xacml"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SmartContract provides functions for managing an Asset
type SmartContract struct {
	contractapi.Contract
}

type Policy struct {
	ObjectType string `json:"docType"`
	PatientID  string `json:"PatientID"`
	Xacml      string `json:"Xacml"`
}

type PublicKey struct {
	ObjectType string `json:"docType"`
	E          string `json:"e"`
	N          string `json:"n"`
	UserID     string `json:"userid"`
}

type RecordRequest struct {
	ObjectType         string `json:"docType"`
	PatientId          string `json:"patientid"`
	ProviderId         string `json:"providerid"`
	RequestId          string `json:"requestid"`
	Request            string `json:"Request"`
	RequestingProvider string `json:"RequestingProvider"`
}

const (
	PolicyKeyPrefix   = "/users/policies/"
	PublicKeyPrefix   = "public-key"
	RequestKeyPrefix  = "user-requests"
	ResponseKeyPrefix = "user-responses"
)

func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	id := "123456"
	policy := `<?xml version="1.0" encoding="UTF-8"?>
	<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" 
			xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
			xsi:schemaLocation="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17 http://docs.oasis-open.org/xacml/3.0/xacml-core-v3-schema-wd-17.xsd" 
			PolicyId="httpbin-policy" 
			Version="1.0" 
			RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides">
		<Description>Patient Policy</Description>
		<Target>
			<AnyOf>
				<AllOf>
					<Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-regexp-match">
						<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">^https://api.emc.blue/auth/.*</AttributeValue>
						<AttributeDesignator
								MustBePresent="false"
								Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource"
								AttributeId="urn:oasis:names:tc:xacml:1.0:resource:resource-id" 
								DataType="http://www.w3.org/2001/XMLSchema#string"/>
					</Match>
				</AllOf>
			</AnyOf>
		</Target>
		<Rule RuleId="denyRecordAccess" Effect="Deny">
			<Description>This rule will look for the user to be in a specific tenant and will deny the tenant admin role</Description>
			<Target>
				<AnyOf>
					<AllOf>
						<Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
							<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">https://api.emc.blue/auth/role.tenant_admin</AttributeValue>
							<AttributeDesignator 
								MustBePresent="false"
								Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource"
								AttributeId="urn:oasis:names:tc:xacml:1.0:resource:resource-id"
								DataType="http://www.w3.org/2001/XMLSchema#string"/>
						</Match>
						<Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
							<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">0a56f466-0af7-4521-842b-1f3577a1f0de</AttributeValue>
							<AttributeDesignator 
								MustBePresent="false"
								Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"
								AttributeId="tenant_id"
								DataType="http://www.w3.org/2001/XMLSchema#string"/>
						</Match>
					</AllOf>
				</AnyOf>
			</Target>
		</Rule>
		<Rule RuleId="permitRecordAccess" Effect="Permit">
			<Description>This rule will look for the user to be in any tenant</Description>
			<Target>
				<AnyOf>
					<AllOf>
						<Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
							<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">https://api.emc.blue/auth/role.tenant_admin</AttributeValue>
							<AttributeDesignator 
								MustBePresent="false"
								Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource"
								AttributeId="urn:oasis:names:tc:xacml:1.0:resource:resource-id"
								DataType="http://www.w3.org/2001/XMLSchema#string"/>
						</Match>
						<Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-regexp-match">
							<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}</AttributeValue>
							<AttributeDesignator 
								MustBePresent="false"
								Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"
								AttributeId="tenant_id"
								DataType="http://www.w3.org/2001/XMLSchema#string"/>
						</Match>
					</AllOf>
				</AnyOf>
			</Target>
		</Rule>
		<Rule RuleId="permitSalesOps" Effect="Permit">
			<Description>This rule will look for the user to be in a specific tenant</Description>
			<Target>
				<AnyOf>
					<AllOf>
						<Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
							<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">https://api.emc.blue/auth/role.salesops</AttributeValue>
							<AttributeDesignator 
								MustBePresent="false"
								Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource"
								AttributeId="urn:oasis:names:tc:xacml:1.0:resource:resource-id"
								DataType="http://www.w3.org/2001/XMLSchema#string"/>
						</Match>
						<Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
							<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">0a56f466-0af7-4521-842b-1f3577a1f0de</AttributeValue>
							<AttributeDesignator 
								MustBePresent="false"
								Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"
								AttributeId="tenant_id"
								DataType="http://www.w3.org/2001/XMLSchema#string"/>
						</Match>
					</AllOf>
				</AnyOf>
			</Target>
		</Rule>
		<Rule RuleId="permitTrustedAgent" Effect="Permit">
			<Description>This rule will look for the user/agent to be in a specific tenant</Description>
			<Target>
				<AnyOf>
					<AllOf>
						<Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
							<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">https://api.emc.blue/auth/role.trusted_service</AttributeValue>
							<AttributeDesignator 
								MustBePresent="false"
								Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource"
								AttributeId="urn:oasis:names:tc:xacml:1.0:resource:resource-id"
								DataType="http://www.w3.org/2001/XMLSchema#string"/>
						</Match>
						<Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
							<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">85b281cf-c074-4d08-80d5-4fd98458640f</AttributeValue>
							<AttributeDesignator 
								MustBePresent="false"
								Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"
								AttributeId="tenant_id"
								DataType="http://www.w3.org/2001/XMLSchema#string"/>
						</Match>
					</AllOf>
				</AnyOf>
			</Target>
		</Rule>
		<Rule RuleId="permitAPI" Effect="Permit">
			<Description>This rule will return a permit on any of the api family asks.</Description>
			<Target/>
			<Condition>
				<Apply FunctionId="urn:oasis:names:tc:xacml:3.0:function:string-is-in">
					<AttributeDesignator 
							MustBePresent="false"
							Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource"
							AttributeId="urn:oasis:names:tc:xacml:1.0:resource:resource-id"
							DataType="http://www.w3.org/2001/XMLSchema#string"/>
					<Apply FunctionId="urn:oasis:names:tc:xacml:3.0:function:string-bag">
						<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">https://api.emc.blue/auth/iam</AttributeValue>
						<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">https://api.emc.blue/auth/config</AttributeValue>
						<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">https://api.emc.blue/auth/agent</AttributeValue>
						<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">https://api.emc.blue/auth/storage</AttributeValue>
						<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">https://api.emc.blue/auth/event</AttributeValue>
						<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">https://api.emc.blue/auth/logging</AttributeValue>
						<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">https://api.emc.blue/auth/provision</AttributeValue>
					</Apply>
				</Apply>
			</Condition>
		</Rule>
	</Policy>`

	policyObj := Policy{
		PatientID: id,
		Xacml:     policy,
	}

	policyJSON, err := json.Marshal(policyObj)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(PolicyKeyPrefix+id, []byte(policyJSON))
}

// Mutators alter the blockchain ledger
// ====================================

func (s *SmartContract) Register(ctx contractapi.TransactionContextInterface, id, n, e string) error {
	userid := PublicKeyPrefix + id

	exists, err := s.KeyExists(ctx, userid)
	if err != nil {
		return fmt.Errorf("failed to check if key exists - %w", err)
	}
	if exists {
		return fmt.Errorf("public key for user %v already exists, try another operation", id)
	}

	pubObj := PublicKey{
		UserID: id,
		N:      n,
		E:      e,
	}

	pubJSON, err := json.Marshal(pubObj)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON - %w", err)
	}

	return ctx.GetStub().PutState(userid, pubJSON)
}

// CreatePolicy will be called when a patient initially signs into the system. Rather than taking in the patientID as a parameter,
// the function should generate an ID based on 'NIST SP 800-63B-4 ipd Digital Identity Guidelines' and return it to be stored in this
// Patient's PatientAccount for use in further operations.
func (s *SmartContract) CreatePolicy(ctx contractapi.TransactionContextInterface, patientID string, policy string, signature string) error {
	// Check if a policy exists for this ID
	exists, err := s.PolicyExists(ctx, patientID)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("policy for patient %v already exists, use updatepolicy to overwrite the current value", patientID)
	}

	// Verify the signature submitted
	msgBytes := []byte(patientID + policy)
	if err := s.VerifySignature(ctx, msgBytes, []byte(signature), patientID); err != nil {
		return fmt.Errorf("error during verification - %w", err)
	}

	// Create policy object and write it to the world state
	policyObj := Policy{
		PatientID: PolicyKeyPrefix + patientID,
		Xacml:     policy,
	}

	policyJson, err := json.Marshal(policyObj)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(policyObj.PatientID, []byte(policyJson))
}

func (s *SmartContract) UpdatePolicy(ctx contractapi.TransactionContextInterface, PatientId, policy, signature string) error {
	exists, err := s.PolicyExists(ctx, PatientId)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the asset %s does not exist", PatientId)
	}

	// Verify the signature submitted
	msgBytes := []byte(PatientId + policy)
	if err := s.VerifySignature(ctx, msgBytes, []byte(signature), PatientId); err != nil {
		return fmt.Errorf("error during verification - %w", err)
	}

	policyObj := Policy{
		PatientID: PatientId,
		Xacml:     policy,
	}

	policyJSON, err := json.Marshal(policyObj)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(PolicyKeyPrefix+PatientId, []byte(policyJSON))
}

func (s *SmartContract) RequestRecord(ctx contractapi.TransactionContextInterface, patientID, providerID, request, signature string) (string, error) {
	msgBytes := []byte(providerID + request)
	if err := s.VerifySignature(ctx, msgBytes, []byte(signature), providerID); err != nil {
		return "nil", fmt.Errorf("error during verification of message %v - %w", msgBytes, err)
	}

	shim := ctx.GetStub()
	policy, error := s.ReadPolicy(ctx, patientID)
	if match := policy != nil; !match {
		return "nil", fmt.Errorf("Policy search returned - nil")
	}
	if error != nil {
		return "nil", error
	}

	resp, err := xacml.PolicyDecisionPoint(policy.Xacml, request)
	if err != nil {
		return "nil", err
	}

	Provider := shim.GetTxID()
	requestID := fmt.Sprint(hash(policy.Xacml + request + resp))

	objectType := "response"
	requestResponse := &RecordRequest{
		ObjectType: objectType,
		PatientId:  patientID,
		ProviderId: providerID,
		RequestId:  requestID,
		//Response:           resp,
		Request:            request,
		RequestingProvider: Provider,
	}
	responseJSONasBytes, err := json.Marshal(requestResponse)
	if err != nil {
		return "nil", err
	}

	indexPatient := "patientid~providerid"
	patientProviderIndexKey, err := shim.CreateCompositeKey(indexPatient, []string{requestResponse.PatientId, requestResponse.ProviderId, Provider})
	if err != nil {
		return "nil", err
	}
	err = shim.PutState(patientProviderIndexKey, responseJSONasBytes)
	if err != nil {
		return "nil", err
	}
	indexProvider := "providerid~patientid"
	providerPatientIndexKey, err := shim.CreateCompositeKey(indexProvider, []string{requestResponse.ProviderId, requestResponse.PatientId, Provider})
	if err != nil {
		return "nil", err
	}

	err = shim.PutState(providerPatientIndexKey, responseJSONasBytes)
	if err != nil {
		return "nil", err
	}

	return resp, nil
}

// Accessors retrieve data from the blockchain ledger
// ==================================================

func (s *SmartContract) ReadResponce(ctx contractapi.TransactionContextInterface, id, reqid, signature string) (*RecordRequest, error) {
	msgBytes := []byte(id + reqid)
	if err := s.VerifySignature(ctx, msgBytes, []byte(signature), id); err != nil {
		return nil, fmt.Errorf("error during verification - %w", err)
	}

	responceJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if responceJSON == nil {
		return nil, fmt.Errorf("the asset %s does not exist", id)
	}

	var response RecordRequest
	err = json.Unmarshal(responceJSON, &response)

	if err != nil {
		return nil, err
	}

	return &response, nil
}

// ReadPolicy should only be available to Patients and each Patient should only be able to read their own
// policy. This is done by using the ID generated by this SmartContract which would be inserted into this
// function by the web server. This should eliminating the potential for injection on the client-side.
func (s *SmartContract) ReadPolicy(ctx contractapi.TransactionContextInterface, id string) (*Policy, error) {
	policyJSON, err := ctx.GetStub().GetState(PolicyKeyPrefix + id)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if policyJSON == nil {
		return nil, fmt.Errorf("the asset %s does not exist", id)
	}

	var policy Policy
	err = json.Unmarshal(policyJSON, &policy)

	if err != nil {
		return nil, err
	}

	return &policy, nil
}

// Search for all requests made for this patient's Medical Records (Shouldn't allow other patients or providers to do this)
func (s *SmartContract) GetAllPatientRequests(ctx contractapi.TransactionContextInterface, id, signature string) ([]*RecordRequest, error) {
	if err := s.VerifySignature(ctx, []byte(id), []byte(signature), id); err != nil {
		return nil, fmt.Errorf("error during verification - %w", err)
	}

	requestIterator, err := ctx.GetStub().GetStateByPartialCompositeKey("patientid~providerid", []string{id})
	if err != nil {
		return nil, err
	}
	defer requestIterator.Close()

	var requests []*RecordRequest
	for requestIterator.HasNext() {
		queryResponse, err := requestIterator.Next()
		if err != nil {
			return nil, err
		}

		var request RecordRequest
		err = json.Unmarshal(queryResponse.Value, &request)
		if err != nil {
			return nil, err
		}
		requests = append(requests, &request)
	}

	return requests, nil
}

// Search for all requests made by a certain provider (Any provider can perform this action)
func (s *SmartContract) GetAllProviderRequests(ctx contractapi.TransactionContextInterface, id, pid, signature string) ([]*RecordRequest, error) {
	msgBytes := []byte(id + pid)
	if err := s.VerifySignature(ctx, msgBytes, []byte(signature), id); err != nil {
		return nil, fmt.Errorf("error during verification - %w", err)
	}

	requestIterator, err := ctx.GetStub().GetStateByPartialCompositeKey("providerid~patientid", []string{id})
	if err != nil {
		return nil, err
	}
	defer requestIterator.Close()

	var requests []*RecordRequest
	for requestIterator.HasNext() {
		queryResponse, err := requestIterator.Next()
		if err != nil {
			return nil, err
		}

		var request RecordRequest
		err = json.Unmarshal(queryResponse.Value, &request)
		if err != nil {
			return nil, err
		}
		requests = append(requests, &request)
	}

	return requests, nil
}

// Utility Methods are used by other smart contract functions
// ==========================================================

func (s *SmartContract) VerifySignature(ctx contractapi.TransactionContextInterface, msgBytes, signature []byte, userId string) error {
	hashed := sha256.Sum256(msgBytes)

	// Fetch the public key associated with this ID
	pub, err := s.GetPublicKey(ctx, userId)
	if err != nil {
		return err
	}

	nBig := new(big.Int)
	nBig, ok := nBig.SetString(pub.N, 10)
	if !ok {
		return fmt.Errorf("setstring: error")
	}
	eInt, err := strconv.Atoi(pub.E)
	if err != nil {
		return fmt.Errorf("string conversion error: %w", err)
	}

	pubRSA := rsa.PublicKey{
		N: nBig,
		E: eInt,
	}

	// Verify the signature
	err = rsa.VerifyPKCS1v15(&pubRSA, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return fmt.Errorf("failed to verify signature %v - %v", hashed, err)
	}
	return nil
}

func (s *SmartContract) GetPublicKey(ctx contractapi.TransactionContextInterface, id string) (*PublicKey, error) {
	pubJSON, err := ctx.GetStub().GetState(PublicKeyPrefix + id)
	if err != nil {
		return nil, err
	}
	if pubJSON == nil {
		return nil, fmt.Errorf("the asset %s does not exist", PublicKeyPrefix+id)
	}

	var pub PublicKey
	err = json.Unmarshal(pubJSON, &pub)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal key: %w", err)
	}

	return &pub, nil
}

func (s *SmartContract) PolicyExists(ctx contractapi.TransactionContextInterface, PatientId string) (bool, error) {
	policyJSON, err := ctx.GetStub().GetState(PolicyKeyPrefix + PatientId)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}

	return policyJSON != nil, nil
}

func (s *SmartContract) KeyExists(ctx contractapi.TransactionContextInterface, PatientId string) (bool, error) {
	keyJSON, err := ctx.GetStub().GetState(PatientId)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}

	return keyJSON != nil, nil
}

func hash(target string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(target))
	return h.Sum32()
}
