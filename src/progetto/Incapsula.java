package progetto;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
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

	final static String PATH = Paths.get(System.getProperty("user.dir")).toString();

	private String cifrario;
	private String mode;
	private String padding;

	private Cipher cipher;
	private KeyManager km;

	public Incapsula() throws InvalidKeyException, NoSuchAlgorithmException, ClassNotFoundException, IOException, NoSuchPaddingException {

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
		//fos.write(ByteBuffer.allocate(4).putInt(cipherInfo.length).array());// PUO' ESSERE SUPERFLUO
		fos.write(cipherInfo);
		fos.write(cipherFile);

		fos.close();
	}

	private SecretKey genSecretKey() throws NoSuchAlgorithmException {
		// Otteniamo un'istanza di KeyGenerator
		KeyGenerator keyGenerator = null;
		keyGenerator = KeyGenerator.getInstance(cifrario);
		if (cifrario.equals("AES"))
			keyGenerator.init(128, new SecureRandom());

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
		String modPadding = km.getModPadding(receiver);
		Cipher c = Cipher.getInstance("RSA/ECB/"+modPadding);
		PublicKey publicKey = km.getPublicKeyCod(receiver);
		c.init(Cipher.ENCRYPT_MODE, publicKey);

		return c.doFinal(plainMetaInfo);

	}

	public void writeDecipherFile(String file, String receiverID) throws Exception {

		FileInputStream fis = new FileInputStream(new File(PATH + "/file/" + file));

		// leggiamo il destinatario dai primi otto bit del messaggio
		byte[] receiver = new byte[8];
		fis.read(receiver);

		if (!Arrays.equals(receiver, Arrays.copyOf(receiverID.getBytes(), 8))) {
			fis.close();
			throw new Exception("This message is not for you");
		}

		// POSSO FARNE A MENO, DIPENDONO DA RSA 1024 = 128 || 2048 =256
		//byte[] length = new byte[4];
		//fis.read(length);
		//int len = ByteBuffer.wrap(length).getInt();
		int len = km.getBitKeyLength(receiverID)/8;
		
		byte[] cipherMetaInfo = new byte[len];
		fis.read(cipherMetaInfo);
		
		// decifra le informazioni sul cifrario utilizzato
		byte[] depicherMetaInfo = decipherInfo(cipherMetaInfo, receiverID);
		
		String sender = new String(depicherMetaInfo, 0, 8).replaceAll("\0", "");
		String cifrario = new String(depicherMetaInfo, 8, 8).replaceAll("\0", "");
		String mode = new String(depicherMetaInfo, 16, 8).replaceAll("\0", "");
		String padding = new String(depicherMetaInfo, 24, 16).replaceAll("\0", "");

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
			throw new Exception("This cipher is not for you");
		}

		// ECCO L'ERRORE, NON DEVO LEGGERE DALLINPUT STREAM !!!!!
		byte[] secretKeyArray = new byte[secretKeyLength];
		//fis.read(secretKeyArray);
		secretKeyArray = Arrays.copyOfRange(depicherMetaInfo, 40, 40 + secretKeyLength );

		SecretKey secretKey = new SecretKeySpec(secretKeyArray, 0, secretKeyLength, cifrario);

		
		IvParameterSpec iv = null;
		if(!mode.equals("ECB")) {
			int ivLength = cifrario.equals("AES") ? 16 : 8;
			byte[] ivBytes = new byte[ivLength];		
			//fis.read(ivBytes);
			ivBytes = Arrays.copyOfRange(depicherMetaInfo, 40 + secretKeyLength, 40 + secretKeyLength + ivLength);
			iv = new IvParameterSpec(ivBytes);
		
		}
		
		initCipher(cifrario, mode, padding);
		cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

		

		FileOutputStream fos = new FileOutputStream(new File(PATH + "/file/DEC_" + file.substring(0, file.length() - 3)));
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

	private byte[] decipherInfo(byte[] cipherMetaInfo, String receiver) throws NoSuchAlgorithmException,
	NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		PrivateKey pk = km.getPrivateKeyCod(receiver);
		Cipher c = Cipher.getInstance("RSA/ECB/"+km.getModPadding(receiver));
		c.init(Cipher.DECRYPT_MODE, pk);
		return c.doFinal(cipherMetaInfo);

	}

}
