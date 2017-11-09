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
	
	/**
	 * Il costruttore si occupa di popolare la mappa degli utenti keys.
	 * @param password (permette di generare la chiave utilizzata nel cifrario)
	 */
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
	
	/**
	 * Se il file delle chiavi è presente decripta le informazioni contenute e le utilizza
	 * per popolare la mappa degli utenti
	 */
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
	
	/**
	 * Genera la chiave per decifrare il file delle chiavi a partire dalla password passata nel costruttore
	 * @return secretKey
	 */
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
	
	/**
	 * Genera una nuova chiave utilizzando una nuova password dopodichè ricifra il file delle chiavi 
	 * @param newPassword (password utilizzata per generare una nuova chiave)
	 */
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
	
	/**
	 * Inserisce un nuovo utente all’interno della mappa degli utenti e all’interno del file delle chiavi
	 * @param newID (ID nuovo utente)
	 * @param keylengthRSA (lunghezza chiave RSA)
	 * @param modPadding (tipo padding)
	 * @param keyLengthSig (lunghezza della chiave per la firma)
	 * @param sigType (tipo di firma)
	 * @return true se l'inserimento va a buon fine, false se ID già presente 
	 */
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

	/**
	 * Rimuove l'utente identificato dall'id userID dalla mappa e dal file delle chiavi.
	 * @param userID (ID dell'utente da rimuovere)
	 * @return true se la rimozione va a buon fine altrimenti false
	 */
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
	
	/**
	 * Restituisce la chiave privata dell'utente userID
	 * @param userID (ID dell'utente)
	 * @return chiave privata dell'utente userID
	 */
	public PrivateKey getPrivateKeyCod(String userID) {
		return keys.get(userID).getPrivKeyCod();
	}
	
	/**
	 * Restituisce la chiave privata dell'utente userID
	 * @param userID (ID dell'utente)
	 * @return chiave pubblica dell'utente userID
	 */
	public PublicKey getPublicKeyCod(String userID) {
		return keys.get(userID).getPubKeyCod();
	}
	
	/**
	 * Restituisce la modalità di padding usata dall'utente userID
	 * @param userID (ID dell'utente)
	 * @return modalità di padding
	 */
	public String getModPadding(String userID) {
		return keys.get(userID).getmodPadding();
	}
	
	/**
	 * Restituisce la chiave privata di verifica dell’utente userID.
	 * @param userID (ID dell'utente) 
	 * @return chiave privata di verifica dell'utente userID
	 */
	public PrivateKey getPrivateKeyVer(String userID) {
		return keys.get(userID).getPrivKeyVer();
	}
	
	/**
	 * Restituisce la chiave pubblica di verifica dell’utente userID.
	 * @param userID (ID dell'utente)
	 * @return chiave pubblica di verifica dell'utente userID
	 */
	public PublicKey getPublicKeyVer(String userID) {
		return keys.get(userID).getPubKeyVer();
	}
	
	/**
	 * Restituisce la tipologia di firma prevista per l’utente userID.
	 * @param userID
	 * @return tipologia di firma dell'utente userID
	 */
	public String getSigType(String userID) {
		return keys.get(userID).getSigType();
	}
	
	/**
	 * Restituisce un array contente tutti gli ID degli utenti presenti nella mappa
	 * @return Stringa di array contente gli ID degli utenti
	 */
	public String[] getAllUsers(){
		ArrayList<String> usersID = new ArrayList<String>(); 
		for (User user: keys.values()){			
			usersID.add(user.getID());			
		}

		return usersID.toArray(new String[usersID.size()]);
	}
}
