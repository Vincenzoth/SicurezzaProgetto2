package progetto;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Incapsula {

	final static String PATH = Paths.get(System.getProperty("user.dir")).toString();

	private String cifrario;
	private String mode;
	private String padding;
	private String fileName;
	private String mittente;
	private String destinatario;

	private Cipher cipher;
	private KeyManager km;

	private PrivateKey userKeyPr;
	private PublicKey userKeyPub;

	public Incapsula() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, ClassNotFoundException, IOException{

		this.km = new KeyManager();

	}

	public Cipher initCipher(String cifrario, String mode, String padding)
			throws NoSuchAlgorithmException, NoSuchPaddingException {
		this.cifrario = cifrario;
		this.mode = mode;
		this.padding = padding;

		cipher = Cipher.getInstance(cifrario + "/" + mode + "/" + padding);

		return cipher;
	}

	public void writeFile(String file, String sender, String receiver)
			throws IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {

		SecretKey secretKey = genSecretKey();
		byte[] cipherFile = cipherFile(secretKey, file);
		byte[] cipherInfo = cipherInfo(secretKey, sender, receiver);
		
		FileOutputStream fos = new FileOutputStream(new File(PATH+"/file/"+file+".ts"));
		
		fos.write(Arrays.copyOf(receiver.getBytes(), 8) );
		fos.write(ByteBuffer.allocate(4).putInt(cipherInfo.length).array() );		
		fos.write(cipherInfo);
		fos.write(cipherFile);
		
	}

	public SecretKey genSecretKey() {
		// Otteniamo un'istanza di KeyGenerator
		KeyGenerator keyGenerator = null;
		try {
			keyGenerator = KeyGenerator.getInstance(cifrario);
			if (cifrario.equals("AES"))
				keyGenerator.init(128, new SecureRandom());
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Impossibile generare SecretKey: " + cifrario + " non supportato");
		}
		return keyGenerator.generateKey();
	}

	public SecretKey decipherKey(byte[] cipherKey) {
		try {

			byte privata[] = userKeyPr.getEncoded();
			System.out.println("chiave lunghezza " + privata.length);
			// byte pubblica[] = userKeyPub.getEncoded();

			KeyFactory kf = KeyFactory.getInstance("RSA");
			// PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(pubblica));
			PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privata));

			Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");

			c.init(Cipher.DECRYPT_MODE, userKeyPr);
			byte[] decodificato = c.doFinal(cipherKey);
			System.out.println("Chiave cifrata: " + Arrays.toString(decodificato));
			SecretKey originalKey = new SecretKeySpec(decodificato, 0, decodificato.length, cifrario);
			System.out.println(originalKey.getFormat());
			return originalKey;

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;

	}

	public byte[] cipherFile(SecretKey secretKey, String file)
			throws IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		return cipher.doFinal(Files.readAllBytes(Paths.get(PATH + "/file/" +file)));

	}

	public byte[] cipherInfo(SecretKey secretKey, String sender, String receiver) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
								
		// Creiamo l'array di byte delle informazioni in chiaro
		
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		
		outputStream.write( Arrays.copyOf(sender.getBytes(), 8) );
		outputStream.write( Arrays.copyOf(cifrario.getBytes(), 8) );
		outputStream.write( Arrays.copyOf(mode.getBytes(), 8) );
		outputStream.write( Arrays.copyOf(padding.getBytes(), 8) );
		outputStream.write( secretKey.getEncoded() );
		
		if(mode!="ECB")
			outputStream.write( cipher.getIV() );

		byte plainMetaInfo[] = outputStream.toByteArray( );
		
		// Cifriamo le meta info
		//String modPadding = km.getPadding(receiver);
		Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");
		PublicKey publicKey = km.getPublicKeyCod(receiver);
		c.init(Cipher.ENCRYPT_MODE, publicKey);

		//System.out.println("Chiave da cifrare: " + Arrays.toString(plainMetaInfo));
		return c.doFinal(plainMetaInfo);


	}

	public void decipherFile() {

		FileInputStream fis;
		try {
			fis = new FileInputStream(new File(PATH + fileName + ".ts"));

			byte[] cipherKey = new byte[128];
			fis.read(cipherKey);

			SecretKey originalKey = decipherKey(cipherKey);
			System.out.println("Chiave cifrata: " + Arrays.toString(originalKey.getEncoded()));

			// Recuperiamo IV dal file (se presente)
			IvParameterSpec iv = null;
			if (mode != "ECB") {
				byte[] ivBytes = new byte[cifrario.equals("AES") ? 16 : 8];
				fis.read(ivBytes);
				iv = new IvParameterSpec(ivBytes);
				// System.out.println(Arrays.toString(ivBytes));
				// String encodedIV = Base64.getEncoder().encodeToString(ivBytes);
				// System.out.println("\nIV in Base64: " + encodedIV);
			}

			//Cipher cipher = initCipher(Cipher.DECRYPT_MODE, originalKey, iv);

			FileOutputStream fos = new FileOutputStream(new File(PATH + "/file/ohyeah.pdf"));
			CipherInputStream cis = new CipherInputStream(fis, cipher);

			byte[] mit = new byte[8];
			byte[] dest = new byte[8];

			// Recuperiamo il mittente e il destinatario dal file
			cis.read(mit);
			cis.read(dest);

			String mittente = new String(mit, "UTF8");
			String destinatario = new String(dest, "UTF8");
			System.out.println("Mittente: " + mittente);
			System.out.println("Destinatario: " + destinatario);

			byte[] buffer = new byte[512];
			int r;
			while ((r = cis.read(buffer)) > 0) {
				fos.write(buffer, 0, r);
			}

			fos.close();
			cis.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
}
