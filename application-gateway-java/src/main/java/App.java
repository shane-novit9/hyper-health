/*
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParser;
import io.grpc.ManagedChannel;
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import org.hyperledger.fabric.client.CommitException;
import org.hyperledger.fabric.client.CommitStatusException;
import org.hyperledger.fabric.client.Contract;
import org.hyperledger.fabric.client.EndorseException;
import org.hyperledger.fabric.client.Gateway;
import org.hyperledger.fabric.client.GatewayException;
import org.hyperledger.fabric.client.SubmitException;
import org.hyperledger.fabric.client.identity.Identities;
import org.hyperledger.fabric.client.identity.Identity;
import org.hyperledger.fabric.client.identity.Signer;
import org.hyperledger.fabric.client.identity.Signers;
import org.hyperledger.fabric.client.identity.X509Identity;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

public final class App {
	private static final String mspID = "Org1MSP";
	private static final String channelName = "mychannel";
	private static final String chaincodeName = "xacml";
	

	// Path to crypto materials.
	private static final Path cryptoPath = Paths.get("..", "..", "test-network", "organizations", "peerOrganizations", "org1.example.com");
	// Path to user certificate.
	private static final Path certPath = cryptoPath.resolve(Paths.get("users", "User1@org1.example.com", "msp", "signcerts", "cert.pem"));
	// Path to user private key directory.
	private static final Path keyDirPath = cryptoPath.resolve(Paths.get("users", "User1@org1.example.com", "msp", "keystore"));
	// Path to peer tls certificate.
	private static final Path tlsCertPath = cryptoPath.resolve(Paths.get("peers", "peer0.org1.example.com", "tls", "ca.crt"));
	// Path to policy
	Path policyPath = Path.of("./policy.txt");
	// Path to request
	Path requestPath = Path.of("./request.txt");
	private static String policy;
	private static String request;

	// Gateway peer end point.
	private static final String peerEndpoint = "localhost:7051";
	private static final String overrideAuth = "peer0.org1.example.com";

	private final Contract contract;
	private final String assetId = "asset" + Instant.now().toEpochMilli();
	private final Gson gson = new GsonBuilder().setPrettyPrinting().create();

	public static void main(final String[] args) throws Exception {
		// The gRPC client connection should be shared by all Gateway connections to
		// this endpoint.
		var channel = newGrpcConnection();

		try {
			// Get Policy
			policy = new String (Files.readAllBytes(Paths.get(".", "policy.txt")));
			// Get Request
			request = new String (Files.readAllBytes(Paths.get(".", "request.txt")));
		} 
		catch (IOException e) {
			e.printStackTrace();
		}

		var builder = Gateway.newInstance().identity(newIdentity()).signer(newSigner()).connection(channel)
				// Default timeouts for different gRPC calls
				.evaluateOptions(options -> options.withDeadlineAfter(5, TimeUnit.SECONDS))
				.endorseOptions(options -> options.withDeadlineAfter(15, TimeUnit.SECONDS))
				.submitOptions(options -> options.withDeadlineAfter(5, TimeUnit.SECONDS))
				.commitStatusOptions(options -> options.withDeadlineAfter(1, TimeUnit.MINUTES));

		
		try (var gateway = builder.connect()) {
			new App(gateway).run();
		} finally {
			channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
		}
	}

	private static ManagedChannel newGrpcConnection() throws IOException, CertificateException {
		var tlsCertReader = Files.newBufferedReader(tlsCertPath);
		var tlsCert = Identities.readX509Certificate(tlsCertReader);

		return NettyChannelBuilder.forTarget(peerEndpoint)
				.sslContext(GrpcSslContexts.forClient().trustManager(tlsCert).build()).overrideAuthority(overrideAuth)
				.build();
	}

	private static Identity newIdentity() throws IOException, CertificateException {
		var certReader = Files.newBufferedReader(certPath);
		var certificate = Identities.readX509Certificate(certReader);

		return new X509Identity(mspID, certificate);
	}

	private static Signer newSigner() throws IOException, InvalidKeyException {
		var keyReader = Files.newBufferedReader(getPrivateKeyPath());
		var privateKey = Identities.readPrivateKey(keyReader);

		return Signers.newPrivateKeySigner(privateKey);
	}

	private static Path getPrivateKeyPath() throws IOException {
		try (var keyFiles = Files.list(keyDirPath)) {
			return keyFiles.findFirst().orElseThrow();
		}
	}

	public App(final Gateway gateway) {
		// Get a network instance representing the channel where the smart contract is
		// deployed.
		var network = gateway.getNetwork(channelName);

		// Get the smart contract from the network.
		contract = network.getContract(chaincodeName);
	}

	public void run() throws GatewayException, CommitException {

		// Create a new asset on the ledger.
		createPolicy();

		// Update an existing asset asynchronously.
		requestRecord();

		// Get the asset details by assetID.
		readPolicy();

		// Update an asset which does not exist.
		getPatientRequests();
	}

	/**
	 * Submit a transaction synchronously, blocking until it has been committed to
	 * the ledger.
	 */
	private void createPolicy() throws EndorseException, SubmitException, CommitStatusException, CommitException {
		System.out.println("\n--> Submit Transaction: CreateAsset, creates new asset with ID, Color, Size, Owner and AppraisedValue arguments");
		
		try {
			contract.submitTransaction("CreatePolicy", "123456", policy);
		} catch (EndorseException e) {
			e.printStackTrace();
		}

		System.out.println("*** Transaction committed successfully");
	}

	/**
	 * Submit transaction asynchronously, allowing the application to process the
	 * smart contract response (e.g. update a UI) while waiting for the commit
	 * notification.
	 */
	private void requestRecord() throws EndorseException, SubmitException, CommitStatusException {
		System.out.println("\n--> Request Record");
		byte[] resp = {};
		try {
			resp = contract.submitTransaction("RequestRecord", "123456", "654321", request);
		} catch (EndorseException | CommitException e) {
			e.printStackTrace();
		}
		
		System.out.println("*** Result:" + new String(resp));
	}

	private void readPolicy() throws GatewayException {
		System.out.println("\n--> Evaluate Transaction: ReadAsset, function returns asset attributes");
		byte[] evaluateResult = {};
		try {
			evaluateResult = contract.evaluateTransaction("ReadPolicy", "123456");
		} catch (GatewayException e) {
			e.printStackTrace();
		}
		
		System.out.println("*** Result:" + new String (evaluateResult));
	}

	/**
	 * submitTransaction() will throw an error containing details of any error
	 * responses from the smart contract.
	 */
	private void getPatientRequests() {
		System.out.println("\n--> Submit Transaction: Get Patient's Requests");

		byte[] resp = {};
		try {
			resp = contract.evaluateTransaction("GetAllPatientRequests", "123456");
		} catch (GatewayException e) {
			e.printStackTrace();
		}

		System.out.println("*** Result:" + new String (resp));
	}
}
