package progetto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
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
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Incapsula {
	private String cifrario;
	private String mode;
	private String padding;
	private String fileName;
	private String path;	
	
	private PrivateKey userKeyPr;
	private PublicKey userKeyPub;

	public Incapsula(String cifrario, String mode, String padding, String fileName) {
		this.cifrario = cifrario;
		this.mode = mode;
		this.padding = padding;
		this.fileName = fileName;
		this.path = Paths.get(System.getProperty("user.dir")).toString();
		
		KeyPairGenerator keyPairGenerator;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048, new SecureRandom());
			KeyPair userKey = keyPairGenerator.generateKeyPair();

			userKeyPr = userKey.getPrivate();
			userKeyPub = userKey.getPublic();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	public SecretKey genSecretKey(String cifrario) {
		// Otteniamo un'istanza di KeyGenerator
		KeyGenerator keyGenerator = null;
		try {
			keyGenerator = KeyGenerator.getInstance(cifrario);
			if(cifrario.equals("AES"))
				keyGenerator.init(128, new SecureRandom());			
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Impossibile generare SecretKey: " + cifrario + " non supportato");
		}
		return keyGenerator.generateKey();
	}
	
	public byte[] cipherKey(SecretKey secretKey) {
		try {
			
			Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");
			// Cipher c = Cipher.getInstance("RSA");

			// ECB non serve a niente, serve solo per compatibilità con il formato usato
			// per i cifrari a blocchi
			c.init(Cipher.ENCRYPT_MODE, userKeyPub);				
			byte[] plaintext = secretKey.getEncoded();
			System.out.println(secretKey.getFormat());
			System.out.println("Chiave da cifrare: "+Arrays.toString(plaintext));
			byte[] ciphertext = c.doFinal(plaintext);
						
			return ciphertext;						

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
		}
		return null;
		
	}
	
	public SecretKey decipherKey(byte[] cipherKey) {
		try {		
			
			byte privata[] = userKeyPr.getEncoded();
			//byte pubblica[] = userKeyPub.getEncoded();			
			
			KeyFactory kf = KeyFactory.getInstance("RSA");
			//PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(pubblica));
			PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privata));
			
			Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");
			
			c.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] decodificato = c.doFinal(cipherKey);			
			System.out.println("Chiave cifrata: "+Arrays.toString(decodificato));
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

	private Cipher initCipher(int opmode, SecretKey secretKey, IvParameterSpec iv) {
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance(cifrario + "/" + mode + "/" + padding);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			System.err.println("Algoritmo o padding non supportato");
		}
		try {
			if (iv != null) {
				cipher.init(opmode, secretKey, iv);			
			}else
				cipher.init(opmode, secretKey);
		} catch (InvalidKeyException e) {
			System.err.println("Chiave non valida");
		} catch (InvalidAlgorithmParameterException e) {
			System.err.println("IV errato");
		}

		return cipher;
	}

	public void cipherFile() {

		FileOutputStream fos;
		// byte[] prova = "text".getBytecs();
		try {
			fos = new FileOutputStream(path + fileName + ".ts");
			// fos.write(prova);
			SecretKey secretKey = genSecretKey(cifrario);
			Cipher cipher = initCipher(Cipher.ENCRYPT_MODE, secretKey, null);
			FileInputStream fis = new FileInputStream(new File(path + fileName));
			CipherInputStream cis = new CipherInputStream(fis, cipher);

			String mittente = "Vecienzo";
			byte[] mit = mittente.getBytes("UTF8");
			fos.write(mit);
			
			String destinatario = "Giuseppe";
			byte[] dest = destinatario.getBytes("UTF8");
			fos.write(dest);
				
			byte[] cipherKey = cipherKey(secretKey);
			fos.write(cipherKey);
			System.out.println("Chiave cifrata in cipher: "+Arrays.toString(cipherKey));
			
			//boooooohhhhhhhh
			/*
			Signature dsa = Signature.getInstance("SHA1withDSA");
			dsa.initSign(userKeyPr);
			dsa.update(Files.readAllBytes(new File(path + fileName).toPath()));
			byte[] firma = dsa.sign();
			System.out.println(Arrays.toString(firma));
			System.out.println("Firma: "+firma.length);
			fos.write(firma);
			*/
			if (mode != "ECB")
				fos.write(cipher.getIV());
			//System.out.println(Arrays.toString(cipher.getIV()));

			// La CipherInputStream ha un buffer interno di 512 bytes (legge
			// al più 512 bytes alla volta).
			byte[] buffer = new byte[512];
			int r;
			while ((r = cis.read(buffer)) > 0) {
				fos.write(buffer, 0, r);
			}

			fis.close();
			cis.close();
			fos.close();

		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public void decipherFile() {
		
		FileInputStream fis;
		try {
			fis = new FileInputStream(new File(path + fileName + ".ts"));

			byte[] mit = new byte[8];
			byte[] dest = new byte[8];
			byte[] cipherKey = new byte[256];
			// Recuperiamo il mittente e il destinatario dal file
			fis.read(mit);
			fis.read(dest);
			fis.read(cipherKey);						
			
			String mittente = new String(mit, "UTF8");
			String destinatario = new String(dest, "UTF8");			
			System.out.println("Mittente: "+mittente);
			System.out.println("Destinatario: "+destinatario);
			SecretKey originalKey = decipherKey(cipherKey);
			System.out.println("Chiave cifrata: "+Arrays.toString(originalKey.getEncoded()));			
			

			// Recuperiamo IV dal file (se presente)
			IvParameterSpec iv = null;
			if (mode!="ECB") {
				byte[] ivBytes = new byte[cifrario.equals("AES") ? 16 : 8];
				fis.read(ivBytes);
				iv = new IvParameterSpec(ivBytes);
				//System.out.println(Arrays.toString(ivBytes));
				//String encodedIV = Base64.getEncoder().encodeToString(ivBytes);
				//System.out.println("\nIV in Base64: " + encodedIV);
			}
			
		
			
			Cipher cipher = initCipher(Cipher.DECRYPT_MODE, originalKey, iv);
						

			FileOutputStream fos = new FileOutputStream(new File(path + "/file/ohyeah.pdf"));
			CipherInputStream cis = new CipherInputStream(fis, cipher);

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
