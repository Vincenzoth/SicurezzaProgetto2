package progetto;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Incapsula {
	final static int LENGTH_METAINFO_BASE = 49;

	private String cifrario;
	private String mode;
	private String padding;

	private Cipher cipher;
	private Signature sig;
	private KeyManager km;

	/**
	 * Costruttore della classe Incapsula
	 * @param km
	 */
	public Incapsula(KeyManager km) {

		this.km = km;

	}
	
	/**
	 * Inizializza il cifrario della classe in base ai parametri passatigli come stringa.
	 * @param cifrario (tipo di cifrario)
	 * @param mode (modo operativo)
	 * @param padding
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 */

	public void initCipher(String cifrario, String mode, String padding)
			throws NoSuchAlgorithmException, NoSuchPaddingException {
		this.cifrario = cifrario;
		this.mode = mode;
		this.padding = padding;

		cipher = Cipher.getInstance(cifrario + "/" + mode + "/" + padding);		
	}
	
	
	/**
	 * Metodo relativo alla cifratura del file, crea un file con estensione .ts contenente 
	 * le meta informazioni cifrate con un cifrario asimmetrico, la firma se richiesta e il messaggio cifrato
	 * @param file (path del file da cifrare)
	 * @param sender (ID mittente)
	 * @param receiver (ID destinatario)
	 * @param signature (indica se è richiesta la firma)
	 * @param keyVerPath (path del file che contiene la chiave di firma)
	 */
	public void writeCipherFile(String file, String sender, String receiver, boolean signature, String keyVerPath) throws IllegalBlockSizeException,
	BadPaddingException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, SignatureException, InvalidKeySpecException {
		
		// Cifra il messaggio
		SecretKey secretKey = genSecretKey();
		byte[] cipherFile = cipherFile(secretKey, file);
		
		// firma se richiesto
		byte[] signatureBytes = null;		
		if (signature) {		
			sig = Signature.getInstance(km.getSigType(sender));
			//Leggiamo chiave
			byte[] keyBytes = Files.readAllBytes(Paths.get(keyVerPath));
			KeyFactory kf = KeyFactory.getInstance("DSA");
			PrivateKey sigKey = kf.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
			sig.initSign(sigKey);
			// Trasmissione dell'engine
			sig.update(Files.readAllBytes(Paths.get(file)));
			// Generazione della firma digitale
			signatureBytes = sig.sign();
					
		}
		
		// cifra meta informazioni
		byte[] cipherInfo = cipherInfo(secretKey, sender, receiver, signature);

		// scrivi il file
		FileOutputStream fos = new FileOutputStream(new File(file + ".ts"));
		fos.write(cipherInfo);
		if (signature)
			fos.write(signatureBytes);
		fos.write(cipherFile);

		fos.close();
	}
	
	/**
	 * Genera e restituisce una chiave simmetrica
	 * @return chiave simmetrica	 
	 */
	private SecretKey genSecretKey() throws NoSuchAlgorithmException {
		// Otteniamo un'istanza di KeyGenerator
		KeyGenerator keyGenerator = null;
		keyGenerator = KeyGenerator.getInstance(cifrario);
		if (cifrario.equals("AES"))
			keyGenerator.init(128, new SecureRandom());

		return keyGenerator.generateKey();
	}
	
	/**
	 * Legge il file relativo al path file passato come parametro e lo cifra usando il cifrario della classe.
	 * @param secretKey (chiave per il cifrario simmetrico)
	 * @param file (path del file da cifrare)
	 * @return Array di byte ottenuti dalla cifratura
	 */
	private byte[] cipherFile(SecretKey secretKey, String file)
			throws IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		return cipher.doFinal(Files.readAllBytes(Paths.get(file)));

	}
	
	/**
	 * Cifra il blocco di meta informazioni usando il cifrario asimmetrico e la
	 * chiae pubblica del destinatario
	 * @param secretKey (chiave simmetrica)
	 * @param sender (ID mittente)
	 * @param receiver (ID destinatario)
	 * @param signature (Flag di firma)
	 * @return Array di byte della cifratura
	 */
	private byte[] cipherInfo(SecretKey secretKey, String sender, String receiver, boolean signature)
			throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {

		// Creiamo l'array di byte delle informazioni in chiaro

		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		
		outputStream.write(Arrays.copyOf(receiver.getBytes(), 8));
		outputStream.write(Arrays.copyOf(sender.getBytes(), 8));
		outputStream.write(Arrays.copyOf(cifrario.getBytes(), 8));
		outputStream.write(Arrays.copyOf(mode.getBytes(), 8));
		outputStream.write(Arrays.copyOf(padding.getBytes(), 16));
		outputStream.write(ByteBuffer.allocate(1).put((signature) ? (byte)1 : (byte)0).array());		
		
		outputStream.write(secretKey.getEncoded());

		if (!mode.equals("ECB"))
			outputStream.write(cipher.getIV());

		byte plainMetaInfo[] = outputStream.toByteArray();

		// Cifriamo le meta info
		String modPadding = km.getModPadding(receiver);
		Cipher c = Cipher.getInstance("RSA/ECB/"+modPadding);
		PublicKey publicKey = km.getPublicKeyCod(receiver);
		c.init(Cipher.ENCRYPT_MODE, publicKey);

		return c.doFinal(plainMetaInfo);

	}

	/**
	 * Decifra il file cifrato indicato
	 * @param file (path del file da decifrare)
	 * @param receiverID (ID destinatario)
	 * @param keyPath (path del file contentente la chiave privata)
	 * @return
	 */
	public int writeDecipherFile(String file, String receiverID, String keyPath) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, MyException, InvalidAlgorithmParameterException, SignatureException {
		int isValid = 0; 
		
		// leggiamo la chiave
		byte[] keyBytes = Files.readAllBytes(Paths.get(keyPath));
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));

		//ottenere lunghezza blocco di cifratura
		RSAPublicKeySpec pub = kf.getKeySpec(km.getPublicKeyCod(receiverID), RSAPublicKeySpec.class);
		int len = pub.getModulus().bitLength()/8;
		
		// leggiamo le informazioni dal file
		FileInputStream fis = new FileInputStream(new File(file));
		
		byte[] cipherMetaInfo = new byte[len];
		fis.read(cipherMetaInfo);
		
		// decifra le informazioni sul cifrario utilizzato
		// il metodo lancia eccezione "Decryption error" se il destinatario non è quello giusto
		byte[] depicherMetaInfo = decipherInfo(cipherMetaInfo, receiverID, privateKey);
		
		String receiver = new String(depicherMetaInfo, 0, 8).replaceAll("\0", "");
		
		if (! receiver.equals(receiverID) ){
			fis.close();
			throw new MyException("This message is not for you");
		}
		
		String sender = new String(depicherMetaInfo, 8, 8).replaceAll("\0", "");
		String cifrario = new String(depicherMetaInfo, 16, 8).replaceAll("\0", "");
		String mode = new String(depicherMetaInfo, 24, 8).replaceAll("\0", "");
		String padding = new String(depicherMetaInfo, 32, 16).replaceAll("\0", "");
		boolean signature = ByteBuffer.wrap(Arrays.copyOfRange(depicherMetaInfo, 48, 49)).get(0) == 1 ? true : false;

		int secretKeyLength;
		switch(cifrario) {
		case "DES":
			secretKeyLength = 8;
			break;
		case "AES":
			secretKeyLength = 16;
			break;
		case "DESede":
			secretKeyLength = 24;
			break;
		default:
			fis.close();
			throw new MyException("This cipher is not for you");
		}


		byte[] secretKeyArray = new byte[secretKeyLength];
		secretKeyArray = Arrays.copyOfRange(depicherMetaInfo, LENGTH_METAINFO_BASE, LENGTH_METAINFO_BASE + secretKeyLength );

		SecretKey secretKey = new SecretKeySpec(secretKeyArray, 0, secretKeyLength, cifrario);

		IvParameterSpec iv = null;
		if(!mode.equals("ECB")) {
			int ivLength = cifrario.equals("AES") ? 16 : 8;
			byte[] ivBytes = new byte[ivLength];		
			ivBytes = Arrays.copyOfRange(depicherMetaInfo, LENGTH_METAINFO_BASE + secretKeyLength, LENGTH_METAINFO_BASE + secretKeyLength + ivLength);
			iv = new IvParameterSpec(ivBytes);
		
		}
		
		// leggi la firma
		byte[] bytesSig = null;
		if(signature) {
			byte[] firtBytesSig = new byte[2];
			fis.read(firtBytesSig);
			
			int remainingByte = firtBytesSig[1];
			
			byte[] otherBytesSig = new byte[remainingByte];
			fis.read(otherBytesSig);
			
			bytesSig = new byte[2 + remainingByte];
			System.arraycopy(firtBytesSig, 0, bytesSig, 0, 2);
			System.arraycopy(otherBytesSig, 0, bytesSig, 2, remainingByte);	
		}
		
		
		// decifra messaggio
		initCipher(cifrario, mode, padding);
		cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);


		String[] elementsOfPath = file.split("\\.");	
		String decipherPath = elementsOfPath[0] + "_DEC." + elementsOfPath[1];

		FileOutputStream fos = new FileOutputStream(new File(decipherPath));
		CipherInputStream cis = new CipherInputStream(fis, cipher);

		byte[] buffer = new byte[512];
		int r;
		while ((r = cis.read(buffer)) > 0) {
			fos.write(buffer, 0, r);
		}

		fis.close();
		fos.close();
		cis.close();
		
		// controlla firma
		if (signature) {
			byte[] message = Files.readAllBytes(Paths.get(decipherPath));

			// Verifica della firma
			isValid = verifySignature(bytesSig, message, sender) ? 1 : -1;			
		}
		
		return isValid;
		
	}

	/**
	 * Decifra il blocco di meta informazioni
	 * @param cipherMetaInfo 
	 * @param receiver(blocco di byte da decifrare)
	 * @param key (chiave per il cifrario asimmetrico)
	 * @return Array di byte delle meta info decifrate
	 */
	private byte[] decipherInfo(byte[] cipherMetaInfo, String receiver, PrivateKey key) throws NoSuchAlgorithmException,
	NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		Cipher c = Cipher.getInstance("RSA/ECB/"+km.getModPadding(receiver));
		c.init(Cipher.DECRYPT_MODE, key);
		return c.doFinal(cipherMetaInfo);

	}
	
	/**
	 * Verifica la firma
	 * @param signatureBytes (Array di byte della firma)
	 * @param data (Array di byte del messaggio firmato)
	 * @param sender (ID mittente)
	 * @return true se la firma è valida
	 */
	public Boolean verifySignature(byte[] signatureBytes, byte[] data, String sender) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException {
		// inizializza firma
		sig = Signature.getInstance(km.getSigType(sender));
		
		// Verifica della firma
		Boolean verified;
		sig.initVerify(km.getPublicKeyVer(sender));
		sig.update(data);
		
		try {
			verified = sig.verify(signatureBytes);
		} catch (SignatureException e) {
			verified = false;
		}
		return verified;

	}

}
