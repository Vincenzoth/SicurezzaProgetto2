package progetto;


import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class KeyManager {
	final static String PATH = Paths.get(System.getProperty("user.dir")).toString();
	final static String FILE_NAME = PATH + "/data/keys";
	final static String PR_KEYS_PATH = PATH + "/keys/";

	private KeyPairGenerator keyGenRSA;
	private KeyPairGenerator keyGenSig;
	private Cipher cipher;
	private SecretKey key;
	private HashMap<String,User> keys;
	private char[] password;

	public KeyManager(String password) throws NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidKeyException, ClassNotFoundException, InvalidKeySpecException {
		// inizializza cifrario
		this.cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
		// genera la chiave
		this.password = password.toCharArray();
		key = loadKey();

		// inizializza mappa
		keys = new HashMap<String,User>();

		//popola la mappa
		loadMap();
	}

	private void loadMap() throws InvalidKeyException, FileNotFoundException, IOException, ClassNotFoundException {
		File f = new File(FILE_NAME);
		if(f.exists() && !f.isDirectory()) { 
			// il file delle chiavi esiste
			this.cipher.init(Cipher.DECRYPT_MODE, key);

			ObjectInputStream ois;
			ois = new ObjectInputStream(new CipherInputStream(new FileInputStream(FILE_NAME), cipher));
			this.keys = (HashMap<String,User>) ois.readObject();
			ois.close();
		}
	}

	private SecretKey loadKey() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {		
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		byte[] salt = new byte[] { 0x7d, 0x60, 0x43, 0x5f, 0x02, (byte) 0xe9, (byte) 0xe0, (byte) 0xae };

		// Specifica della chiave
		KeySpec keySpec = new PBEKeySpec(password, salt, 65536, 192);

		// Genera una chiave generica
		SecretKey tmp = factory.generateSecret(keySpec);

		// Genera una chiave DESede
		SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "DESede");

		return secretKey;
	}

	public void renewKey(String newPassword) throws NoSuchAlgorithmException, IOException, InvalidKeyException, InvalidKeySpecException {
		// genera una nuova chiave

		this.password = newPassword.toCharArray();
		this.key = loadKey();;

		// cifra il file delle chiavi
		this.cipher.init(Cipher.ENCRYPT_MODE, key);
		ObjectOutputStream oss;
		oss = new ObjectOutputStream(new CipherOutputStream(new FileOutputStream(FILE_NAME), cipher));
		oss.writeObject(keys);
		oss.close();		
	}

	public boolean newUser(String newID, int keylengthRSA, String modPadding, int keyLengthSig, String sigType) throws IOException, InvalidKeyException, NoSuchAlgorithmException, MyException {
		if(sigType.equals("SHA1withDSA") && keyLengthSig == 2048 )
		throw new MyException("User "+newID+" Is not possible use SHA1withDSA with 2048 key!");

		// Genera chiavi RSA
		this.keyGenRSA = KeyPairGenerator.getInstance("RSA");
		this.keyGenRSA.initialize(keylengthRSA, new SecureRandom());
		KeyPair pairRSA = this.keyGenRSA.generateKeyPair();

		// Genera chiavi firma DSA
		this.keyGenSig = KeyPairGenerator.getInstance("DSA");
		this.keyGenSig.initialize(keyLengthSig, new SecureRandom());
		KeyPair pairDSA = this.keyGenSig.generateKeyPair();

		// aggiungi alla mappa
		User retValue = keys.put(newID, new User(newID, pairRSA.getPublic(), pairRSA.getPrivate(), modPadding, pairDSA.getPublic(), pairDSA.getPrivate(), sigType));

		if( retValue == null) {
			// aggiungi al file	
			this.cipher.init(Cipher.ENCRYPT_MODE, key);
			File keysFile = new File(FILE_NAME);
			if(!keysFile.exists()) 			 
				keysFile.getParentFile().mkdirs();
			ObjectOutputStream oss;
			oss = new ObjectOutputStream(new CipherOutputStream(new FileOutputStream(keysFile), cipher));
			oss.writeObject(keys);
			oss.close();

			// scrivi i file della chiave
			FileOutputStream fos;
			File keysPath = new File(PR_KEYS_PATH);
			if(!keysPath.exists()) 			 
				keysPath.mkdirs();
			fos = new FileOutputStream(new File(PR_KEYS_PATH + "privateKey_" + newID));
			fos.write(pairRSA.getPrivate().getEncoded());
			fos.flush();
			fos = new FileOutputStream(new File(PR_KEYS_PATH + "privateSig_" + newID));
			fos.write(pairDSA.getPrivate().getEncoded());
			fos.flush();

			fos.close();
		}

		return retValue != null ? false : true;
	}

	public boolean removeUser(String userID) throws InvalidKeyException, FileNotFoundException, IOException {
		User retValue = keys.remove(userID);

		// Aggiorna il file delle chiavi	
		this.cipher.init(Cipher.ENCRYPT_MODE, key);
		ObjectOutputStream oss;
		oss = new ObjectOutputStream(new CipherOutputStream(new FileOutputStream(FILE_NAME), cipher));
		oss.writeObject(keys);
		oss.close();

		return retValue == null ? false : true;

	}

	public PrivateKey getPrivateKeyCod(String userID) {
		return keys.get(userID).getPrivKeyCod();
	}

	public PublicKey getPublicKeyCod(String userID) {
		return keys.get(userID).getPubKeyCod();
	}

	public String getModPadding(String userID) {
		return keys.get(userID).getmodPadding();
	}

	public PrivateKey getPrivateKeyVer(String userID) {
		return keys.get(userID).getPrivKeyVer();
	}

	public PublicKey getPublicKeyVer(String userID) {
		return keys.get(userID).getPubKeyVer();
	}

	public String getSigType(String userID) {
		return keys.get(userID).getSigType();
	}

	public String[] getAllUsers(){
		ArrayList<String> usersID = new ArrayList<String>(); 
		for (User user: keys.values()){			
			usersID.add(user.getID());			
		}

		return usersID.toArray(new String[usersID.size()]);
	}
}
