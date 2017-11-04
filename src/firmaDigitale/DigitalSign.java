package firmaDigitale;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public class DigitalSign {

	private Signature sig;

	public DigitalSign() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {


		// Generazione di un signature engine
		sig = Signature.getInstance("SHA256withRSA");
		

		

	}

	public static KeyPair generateKeys() throws NoSuchAlgorithmException {
		// Generazione di una copia di chiavi
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(1024);
		KeyPair keyPair = kpg.generateKeyPair();
		
		System.out.println("Algoritmo: " +keyPair.getPrivate().getAlgorithm() );
		System.out.println("Formato chiave privata:    " + keyPair.getPrivate().getFormat());
		System.out.println("Formato chiave pubblica:   " + keyPair.getPublic().getFormat());
		return keyPair;

	}


	public byte[] generateDigitalSignature(byte[]data, PrivateKey pr) throws InvalidKeyException, SignatureException {
		// GENERAZIONE DELLA FIRMA DIGITALE

		// Inizializzazione dell'engine per la firma
		sig.initSign(pr);
		// Trasmissione dell'engine
		sig.update(data);
		// Generazione della firma digitale
		byte[] signatureBytes = sig.sign();
		return signatureBytes;
	}
	
	public Boolean verify(byte[] signatureBytes, byte[] data, PublicKey pb) throws InvalidKeyException, SignatureException {
		// Verifica della firma
		Boolean verified;
		sig.initVerify(pb);
		sig.update(data);
		
		try {
			verified = sig.verify(signatureBytes);
		} catch (SignatureException e) {
			verified = false;
		}

		return verified;

	}
	
	public static void convertByteArrayToFile(byte[] b,String newNameFile) throws IOException {
		OutputStream out;
		
		out = new FileOutputStream(Paths.get(System.getProperty("user.dir") + "/file/" +newNameFile).toString());
		out.write(b, 0, b.length);
		// out.position = 0;
		out.close();
	}

}
