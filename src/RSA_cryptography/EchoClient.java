package RSA_cryptography;

import java.io.*;
import java.net.*;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Scanner;
import javax.crypto.Cipher;

import RSA_cryptography.Util;

public class EchoClient {
	private static final String CIPHERTYPE = "RSA/ECB/PKCS1Padding";
	private static final String SIGNTYPE = "SHA256withRSA";
	private static final String CERTSFILEPATH = "src/RSA_cryptography/certs.jks";

	private static PublicKey serverPublicKey;
	private static PublicKey myPublicKey; // doesnt accually get used here
	private static PrivateKey myPrivateKey;

	private Socket clientSocket;
	private DataOutputStream out;
	private DataInputStream in;

	/**
	 * Setup the two way streams.
	 *
	 * @param ip   the address of the server
	 * @param port port used by the server
	 *
	 */
	public void startConnection(String ip, int port) {
		try {
			clientSocket = new Socket(ip, port);
			out = new DataOutputStream(clientSocket.getOutputStream());
			in = new DataInputStream(clientSocket.getInputStream());
		} catch (IOException e) {
			System.out.println("Error when initializing connection");
		}
	}

	/**
	 * Send a message to server and receive a reply.
	 *
	 * @param msg the message to send
	 */
	public String sendMessage(String msg) {
		try {
			System.out.println("Client sending cleartext " + msg);
			byte[] data = new byte[256];
			data = msg.getBytes("UTF-8");

			// encrypt
			System.out.println("Encrypting message with " + CIPHERTYPE);
			Cipher cipher = Cipher.getInstance(CIPHERTYPE);
			cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
			byte[] encryptedBytes = cipher.doFinal(data);

			// sign
			System.out.println("Signing message with " + SIGNTYPE);
			Signature signingSignature = Signature.getInstance(SIGNTYPE);
			signingSignature.initSign(myPrivateKey);
			signingSignature.update(data); // singing the plaintext, not ciphertext
			byte[] signatureBytes = signingSignature.sign();

			// concatenate the 2 byte arrays, and send
			byte[] toSend = Util.concatBytes(encryptedBytes, signatureBytes);
			out.write(toSend);
			out.flush();
			System.out.println("Sent message (ciphertext): " + Util.bytesToHex(encryptedBytes));
			System.out.println("");
			
			// receive
			data = new byte[512];
			in.read(data);
			encryptedBytes = Arrays.copyOfRange(data, 0, 256);
			signatureBytes = Arrays.copyOfRange(data, 256, 512);
			System.out.println("data received");

			// decrypt data
			cipher = Cipher.getInstance(CIPHERTYPE);
			cipher.init(Cipher.DECRYPT_MODE, myPrivateKey);
			byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
			System.out.println("Successfully decrypted message");

			// check signature
			Signature verifyingSig = Signature.getInstance(SIGNTYPE);
			verifyingSig.initVerify(serverPublicKey);
			verifyingSig.update(decryptedBytes);
			boolean validSig = verifyingSig.verify(signatureBytes);
			if (validSig)
				System.out.println("Signature verified");
			else
				System.out.println("Invalid signature");

			String reply = new String(decryptedBytes, "UTF-8");
			System.out.println("Received message (plaintext): " + reply);
			
			// add gap for nice formatting
			System.out.println("");
			System.out.println("");
			return reply;
		} catch (Exception e) {
			System.out.println(e.getMessage());
			return null;
		}
	}

	/**
	 * Close down our streams.
	 *
	 */
	public void stopConnection() {
		try {
			in.close();
			out.close();
			clientSocket.close();
		} catch (IOException e) {
			System.out.println("error when closing");
		}
	}

	public static void main(String[] args) throws NoSuchAlgorithmException {
		EchoClient client = new EchoClient();

		// get key information from console input
		String enteredPassword = "";
		Scanner consoleIn = new Scanner(System.in);
		while (!enteredPassword.equals("badpassword")) {
			System.out.println("Please enter keystore password:");
			enteredPassword = consoleIn.nextLine();
			if (!enteredPassword.equals("badpassword")) {
				System.out.println("bad password... (incorrect)");
			}
		}
		consoleIn.close();
		char[] ksPassword = enteredPassword.toCharArray();

		try (InputStream keyStoreData = new FileInputStream(CERTSFILEPATH)) {
			KeyStore keyStore = KeyStore.getInstance("JCEKS");
			keyStore.load(keyStoreData, ksPassword);

			// we first need to get access to the private key
			PasswordProtection keyPassword = new PasswordProtection("client".toCharArray());
			PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) keyStore.getEntry("client_cert", keyPassword);

			// get the public and private keys
			Certificate cert = keyStore.getCertificate("client_cert");
			myPublicKey = cert.getPublicKey();
			myPrivateKey = privateKeyEntry.getPrivateKey();

			// get the servers public key
			cert = keyStore.getCertificate("server_cert");
			serverPublicKey = cert.getPublicKey();

			// lots of catch clauses
		} catch (FileNotFoundException e) {
			System.out.println("Keystore file not found");
		} catch (IOException e) {
			System.out.println("Error reading file");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Bad algorithm type");
		} catch (CertificateException e) {
			System.out.println("Cert error");
		} catch (KeyStoreException e) {
			System.out.println("Keystore error");
		} catch (UnrecoverableEntryException e) {
			System.out.println("UnrecoverableEntryException...(?)");
		}

		client.startConnection("127.0.0.1", 4444);
		System.out.println("Connected to server");
		System.out.println("");

		client.sendMessage("12345678");
		client.sendMessage("ABCDEFGH");
		client.sendMessage("87654321");
		client.sendMessage("HGFEDCBA");
		client.stopConnection();
	}
}
