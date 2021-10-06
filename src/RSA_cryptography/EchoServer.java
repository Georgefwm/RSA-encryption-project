package RSA_cryptography;

import java.net.*;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;

import RSA_cryptography.Util;


public class EchoServer {
	private static final String CIPHERTYPE = "RSA/ECB/PKCS1Padding";
	private static final String SIGNTYPE = "SHA256withRSA";
	private static final String CERTSFILEPATH = "src/RSA_cryptography/certs.jks";

	private static PrivateKey myPrivateKey;
	private static PublicKey myPublicKey; // doesnt accually get used here
	private static PublicKey clientPublicKey;

	private ServerSocket serverSocket;
	private Socket clientSocket;
	private DataOutputStream out;
	private DataInputStream in;

	/**
	 * Create the server socket and wait for a connection. Keep receiving messages
	 * until the input stream is closed by the client.
	 *
	 * @param port the port number of the server
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public void start(int port) {
		try {
			serverSocket = new ServerSocket(port);
			System.out.println("Waiting for client connection...");
			System.out.println("");
			clientSocket = serverSocket.accept();
			out = new DataOutputStream(clientSocket.getOutputStream());
			in = new DataInputStream(clientSocket.getInputStream());
			
			byte[] data = new byte[512];
			@SuppressWarnings("unused")
			int numBytes;
			while ((numBytes = in.read(data, 0, 512)) != -1) {
				byte[] encryptedBytes = Arrays.copyOfRange(data, 0, 256);
				byte[] signatureBytes = Arrays.copyOfRange(data, 256, 512);

				// decrypt data
				Cipher cipher = Cipher.getInstance(CIPHERTYPE);
				cipher.init(Cipher.DECRYPT_MODE, myPrivateKey);
				byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
				System.out.println("Successfully decrypted message");

				// verify signature
				Signature verifyingSig = Signature.getInstance(SIGNTYPE);
				verifyingSig.initVerify(clientPublicKey);
				verifyingSig.update(decryptedBytes);
				boolean validSig = verifyingSig.verify(signatureBytes);
				if (validSig)
					System.out.println("Signature verified");
				else
					System.out.println("Invalid signature");

				// print message
				String msg = new String(decryptedBytes, "UTF-8");
				System.out.println("Received message (plaintext): " + msg);
				System.out.println("");

				// encrypt
				System.out.println("Encrypting message with " + CIPHERTYPE);
				cipher = Cipher.getInstance(CIPHERTYPE);
				cipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);
				encryptedBytes = cipher.doFinal(decryptedBytes);

				// signing
				System.out.println("Signing message with " + SIGNTYPE);
				Signature signingSig = Signature.getInstance(SIGNTYPE);
				signingSig.initSign(myPrivateKey);
				signingSig.update(decryptedBytes); // sign the plaintext, not ciphertext
				signatureBytes = signingSig.sign();

				// concatenate the 2 byte arrays, and send
				byte[] toSend = Util.concatBytes(encryptedBytes, signatureBytes);
				out.write(toSend);
				out.flush();
				System.out.println("Sent message (ciphertext): " + Util.bytesToHex(encryptedBytes));

				// add gap for nice formatting
				System.out.println("");
				System.out.println("");
			}
			stop();
		} catch (IOException | InvalidKeyException e) {
			System.out.println("Error reading from keystore");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Encryption/decryption error");
		} catch (NoSuchPaddingException e) {
			System.out.println("No padding error");
		} catch (IllegalBlockSizeException e) {
			System.out.println("Block size error");
		} catch (BadPaddingException e) {
			System.out.println("Ciphertext padding error");
		} catch (SignatureException e) {
			System.out.println("Signature error");
		}
	}

	/**
	 * Close the streams and sockets.
	 *
	 */
	public void stop() {
		try {
			in.close();
			out.close();
			clientSocket.close();
			serverSocket.close();
		} catch (IOException e) {
			System.out.println(e.getMessage());
		}

	}

	public static void main(String[] args) throws NoSuchAlgorithmException {
		EchoServer server = new EchoServer();

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
			PasswordProtection keyPassword = new PasswordProtection("server".toCharArray());
			PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) keyStore.getEntry("server_cert", keyPassword);

			// get the public and private keys
			Certificate cert = keyStore.getCertificate("server_cert");
			myPublicKey = cert.getPublicKey();
			myPrivateKey = privateKeyEntry.getPrivateKey();

			// get the servers public key
			cert = keyStore.getCertificate("client_cert");
			clientPublicKey = cert.getPublicKey();

			// lots of catch clauses
		} catch (FileNotFoundException e) {
			System.out.println("Keystore file not found");
			return;
		} catch (IOException e) {
			System.out.println("Error reading file");
			return;
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Bad algorithm type");
			return;
		} catch (CertificateException e) {
			System.out.println("Cert error");
			return;
		} catch (KeyStoreException e) {
			System.out.println("Keystore error");
			return;
		} catch (UnrecoverableEntryException e) {
			System.out.println("UnrecoverableEntryException...(?)");
			return;
		}

		// begin to echo messages
		server.start(4444);

		System.out.println("Client connection lost, closing...");
	}

}
