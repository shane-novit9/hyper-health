# hyper-health

This repository houses the components of my software engineering thesis project completed at the University of Scranton in May of 2023. 

# disclaimer:
This system is meant to serve as proof that a blockchain environment could be used to mediate electronic health record (EHR) transactions and store/retrieve the data resulting from these transactions, in a timely manner. Some elements of the system (specifically smart contract functions) are on par with a production system of this nature but as a whole, it lacks crucial functionalities that would enable deployment in a real-world environment. For more information about the system's limitations and implementation details, follow the link below to read the docs.

Documentation: https://digitalservices.scranton.edu/digital/collection/p15111coll1/id/1372/rec/1

# components

Application Gateway - The gateway server is a rest-api that receives transaction requests from client applications and broadcasts them to Hyperledger Fabric's test network (specifically the network's gateway peer) for evaluation. The layer of abstraction between gateway applications and Fabric networks enables the development of separate services (in multiple languages), that submit the same set of transactions. To demonstrate this, along with a go gateway server (application-gateway-go) and client apps that use RSA Public Key Infrastructure (PKI) to verify user identities, I developed a simple Java gateway application to test transaction interoperability.

Chaincode - Hyperledger Fabric packages smart contracts within chaincodes that can be deployed to Fabric nodes (docker conatainers) that evaluate transactions. Both versions of the smart contracts used in this projects are written in go. The only differece being that signature validation was removed from one version given I did not have time to implement a PKI in Java when conducting my interoperability test.

  Chaincode Functions:

   Create Policy - This function is used when a patient user initially registers with the system. The policy stored in the patient client application is submitted to the network and stored on its ledger for use in record requests.

   Update Policy - Updates the policy stored in this patient's policy index on the ledger. 

   Read Patient Requests - Queries the ledger for all transactions involving a certain patient Id.

   Read Policy - Only available for patients to view their own record access policy.

   Read Provider Requests - Queries the ledger for all transactions involving a certain provider Id.

   Read Response - Queries the ledger for a particular response generated as a result of a record request.

   Register - Registers a RSA Public Key with a user Id. This key is stored on the networks ledger for use verifying transaction signatures.

   Request Record - Provider function that requests to view a patient's EHRs. Uses a XACML engine to generate a response using the provider's request and the patient's policy. The request is stored on the network's ledger twice to allow reading patient/provider requests.

   Verify Signature - Used by every smart contract function besides register to verify transaction signatures.

Go Key Utilities - Used by go patient/provider clients to generate RSA public/private keys and sign transactions.

XACML Engine - Updated https://github.com/murphysean XACML Engine to use go mod instead of go path. The engine is used to evaluate record requests on the Fabric network.
