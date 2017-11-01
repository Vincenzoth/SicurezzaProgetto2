package progetto;


import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class KeyManager {
	final static String fileName = "data/keys";
	final static String fileKey = "data/keyOfkeys";
	private KeyPairGenerator keyGenRSA;
	private Cipher cipher;
	private SecretKey key;
	private HashMap<String,User> keys;

	public KeyManager() throws NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidKeyException, ClassNotFoundException {
		// inizializza cifrario
		this.cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
		key = loadKey();

		// inizializza generatore chiavi
		this.keyGenRSA = KeyPairGenerator.getInstance("RSA");
		
		// inizializza mappa
		keys = new HashMap<String,User>();

		//popola la mappa
		loadMap();
	}

	private void loadMap() throws InvalidKeyException, FileNotFoundException, IOException, ClassNotFoundException {
		File f = new File(fileName);
		if(f.exists() && !f.isDirectory()) { 
			// il file delle chiavi esiste
			this.cipher.init(Cipher.DECRYPT_MODE, key);

			ObjectInputStream ois;
			ois = new ObjectInputStream(new CipherInputStream(new FileInputStream(fileName), cipher));
			this.keys = (HashMap<String,User>) ois.readObject();
			ois.close();
		}
	}

	private SecretKey loadKey() throws NoSuchAlgorithmException, IOException {
		SecretKey secretKey;

		File f = new File(fileKey);
		if(f.exists() && !f.isDirectory()) { 
			// La chiave esiste
			byte[] keyBytes = Files.readAllBytes(f.toPath());
			secretKey = new SecretKeySpec(keyBytes, "DESede");

		}else {
			// genera una chiave
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
			keyGenerator.init(168, new SecureRandom());
			secretKey = keyGenerator.generateKey();

			// Scrivi il file
			f.getParentFile().mkdirs();

			FileOutputStream fos = new FileOutputStream(f);
			fos.write(secretKey.getEncoded());
			fos.flush();
			fos.close();
		}

		return secretKey;
	}
	
	public void renewKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException {
		// genera una nuova chiave
		KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
		keyGenerator.init(168, new SecureRandom());
		this.key = keyGenerator.generateKey();

		// Scrivi il file della chiave
		File f = new File(fileKey);
		f.getParentFile().mkdirs();
		FileOutputStream fos = new FileOutputStream(f);
		fos.write(this.key.getEncoded());
		fos.flush();
		fos.close();
		
		// cifra il file delle chiavi
		this.cipher.init(Cipher.ENCRYPT_MODE, key);
		ObjectOutputStream oss;
		oss = new ObjectOutputStream(new CipherOutputStream(new FileOutputStream(fileName), cipher));
		oss.writeObject(keys);
		oss.close();		
	}

	public void newUser(String newID, int keylength) throws IOException, InvalidKeyException {
		// Genera chiavi RSA
		KeyPair pairRSA;

		this.keyGenRSA.initialize(keylength);
		pairRSA = this.keyGenRSA.generateKeyPair();
		keys.put(newID, new User(newID, pairRSA.getPublic(), pairRSA.getPrivate(), newID, newID));
		
		// Genera chiavi FIRMA
		// ...

		// aggiungi al file	
		this.cipher.init(Cipher.ENCRYPT_MODE, key);
		ObjectOutputStream oss;
		oss = new ObjectOutputStream(new CipherOutputStream(new FileOutputStream(fileName), cipher));
		oss.writeObject(keys);
		oss.close();
	}

	public void removeUser(String userID) throws InvalidKeyException, FileNotFoundException, IOException {
		keys.remove(userID);

		// Aggiorna il file delle chiavi	
		this.cipher.init(Cipher.ENCRYPT_MODE, key);
		ObjectOutputStream oss;
		oss = new ObjectOutputStream(new CipherOutputStream(new FileOutputStream(fileName), cipher));
		oss.writeObject(keys);
		oss.close();

	}

	public PrivateKey getPrivateKeyCod(String userID) {
		return keys.get(userID).getPrivKeyCod();
	}

	public PublicKey getPublicKeyCod(String userID) {
		return keys.get(userID).getPubKeyCod();
	}

	// AGGIUNGI GET CHIAVE DI VERIFICA

}
