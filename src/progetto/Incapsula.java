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

	public Incapsula() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			ClassNotFoundException, IOException {

		this.km = new KeyManager();

	}

	public void initCipher(String cifrario, String mode, String padding)
			throws NoSuchAlgorithmException, NoSuchPaddingException {
		this.cifrario = cifrario;
		this.mode = mode;
		this.padding = padding;

		cipher = Cipher.getInstance(cifrario + "/" + mode + "/" + padding);		
	}

	public void writeCipherFile(String file, String sender, String receiver) throws IllegalBlockSizeException,
			BadPaddingException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {

		SecretKey secretKey = genSecretKey();
		byte[] cipherFile = cipherFile(secretKey, file);
		byte[] cipherInfo = cipherInfo(secretKey, sender, receiver);

		FileOutputStream fos = new FileOutputStream(new File(PATH + "/file/" + file + ".ts"));

		fos.write(Arrays.copyOf(receiver.getBytes(), 8));
		fos.write(ByteBuffer.allocate(4).putInt(cipherInfo.length).array());
		// System.out.println("len enript "+cipherInfo.length);
		fos.write(cipherInfo);
		fos.write(cipherFile);

	}

	private SecretKey genSecretKey() {
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

	private byte[] cipherFile(SecretKey secretKey, String file)
			throws IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		return cipher.doFinal(Files.readAllBytes(Paths.get(PATH + "/file/" + file)));

	}

	private byte[] cipherInfo(SecretKey secretKey, String sender, String receiver)
			throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {

		// Creiamo l'array di byte delle informazioni in chiaro

		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

		outputStream.write(Arrays.copyOf(sender.getBytes(), 8));
		outputStream.write(Arrays.copyOf(cifrario.getBytes(), 8));
		outputStream.write(Arrays.copyOf(mode.getBytes(), 8));
		outputStream.write(Arrays.copyOf(padding.getBytes(), 16));
		outputStream.write(secretKey.getEncoded());

		if (mode != "ECB")
			outputStream.write(cipher.getIV());

		byte plainMetaInfo[] = outputStream.toByteArray();

		// Cifriamo le meta info
		// String modPadding = km.getPadding(receiver);
		Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");
		PublicKey publicKey = km.getPublicKeyCod(receiver);
		c.init(Cipher.ENCRYPT_MODE, publicKey);

		// System.out.println("Chiave da cifrare: " + Arrays.toString(plainMetaInfo));
		return c.doFinal(plainMetaInfo);

	}

	public void writeDecipherFile(String file, String receiverID) throws Exception {

		FileInputStream fis = new FileInputStream(new File(PATH + "/file/" + file));

		byte[] receiver = new byte[8];
		fis.read(receiver);

		if (!Arrays.equals(receiver, Arrays.copyOf(receiverID.getBytes(), 8)))
			throw new Exception("This message is not for you");

		byte[] length = new byte[4];
		fis.read(length);
		int len = ByteBuffer.wrap(length).getInt();

		byte[] cipherMetaInfo = new byte[len];
		fis.read(cipherMetaInfo);
		
		byte[] depicherMetaInfo = decipherInfo(cipherMetaInfo, receiverID);
		String sender = new String(depicherMetaInfo, 0, 8);
		String cifrario = new String(depicherMetaInfo, 8, 8).replaceAll("\0", "");
		String mode = new String(depicherMetaInfo, 16, 8).replaceAll("\0", "");
		String padding = new String(depicherMetaInfo, 24, 16).replaceAll("\0", "");
		
		int secretKeyLength = 8;
		/*
		switch(cifrario) {
			case "DES":
				secretKeyLength = 8;
			case "AES":
				secretKeyLength = 16;
			case "DESede":
				secretKeyLength = 24;
		}
		*/
		System.out.println("lunghezza chiave "+secretKeyLength+" "+cifrario);
		
		if(secretKeyLength == 0)
			throw new Exception("This cipher is not for you");
		
		byte[] secretKeyArray = new byte[secretKeyLength];
		fis.read(secretKeyArray);
		SecretKey secretKey = new SecretKeySpec(secretKeyArray, 0, secretKeyLength, cifrario);
		
		
		IvParameterSpec iv = null;
		if(mode!="ECB") {
			byte[] ivBytes = new byte[cifrario.equals("AES") ? 16 : 8];		
			fis.read(ivBytes);
			iv = new IvParameterSpec(ivBytes);
		}
		
		initCipher(cifrario, mode, padding);
		cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
		System.out.println(cipher.getAlgorithm());
		
		FileOutputStream fos = new FileOutputStream(new File(PATH + "/file/ohyeahhhhh.pdf"));
		CipherInputStream cis = new CipherInputStream(fis, cipher);
		
		byte[] buffer = new byte[512];
		int r;
		while ((r = cis.read(buffer)) > 0) {
			fos.write(buffer, 0, r);
		}
		
		fis.close();
		fos.close();
		cis.close();
		
		

	}

	private void decipherFile() {

		FileInputStream fis;
		try {
			fis = new FileInputStream(new File(PATH + fileName + ".ts"));

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

	private byte[] decipherInfo(byte[] cipherMetaInfo, String receiver) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		PrivateKey pk = km.getPrivateKeyCod(receiver);
		Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");
		c.init(Cipher.DECRYPT_MODE, pk);
		return c.doFinal(cipherMetaInfo);

	}

}
