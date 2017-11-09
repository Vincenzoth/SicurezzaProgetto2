package gui;

import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;

import progetto.Incapsula;
import progetto.KeyManager;


public class Test {

	public static void main(String[] args) {

		System.out.println("\n  test  -------     -------   Keymanager:");
		try {
			String PATH = Paths.get(System.getProperty("user.dir")).toString();

			String password = "qwerty";
			KeyManager km = new KeyManager(password);

			/*
			 // Aggiungi utenti
	
			km.newUser("giu", 2048, "PKCS1Padding", 1024, "SHA256withDSA");
			km.newUser("mic", 1024, "OAEPPadding", 2048, "SHA224withDSA");
			km.newUser("vin", 1024, "OAEPPadding", 1024, "SHA1withDSA");
			*/
			
			// Rimuovi utente
			// km.removeUser("01");

			
			PrivateKey privKeyCod = km.getPrivateKeyCod("giu");
			PublicKey pubKeyCod = km.getPublicKeyCod("giu");
			PrivateKey privKeyVer = km.getPrivateKeyVer("giu");
			PublicKey pubKeyVer = km.getPublicKeyVer("giu");

			System.out.println("Chiave privata: " + privKeyCod);
			System.out.println("Chiave pubblica: " + pubKeyCod);
			System.out.println("Chiave privata ver: " + privKeyVer);
			System.out.println("Chiave pubblica ver: " + pubKeyVer);
			System.out.println();

			System.out.println();
			System.out.println("\n  test  -------     -------   cipher:");
			
			boolean sig = false;
			Incapsula inc = new Incapsula(km);
			inc.initCipher("DESede", "CBC", "PKCS5Padding");
			inc.writeCipherFile(PATH + "/file/" + "documento.pdf", "vin", "giu", sig, PATH+"/keys/privateSig_vin");		
			System.out.println("File Criptato");
			
			int isVer = inc.writeDecipherFile(PATH+"/file/"+"documento.pdf.ts", "giu", PATH+"/keys/privateKey_giu");
			System.out.println("File decriptato");


			if(isVer == 1)
				System.out.println("La firma è valida");
			else if (isVer == -1)
				System.out.println("La firma NON è valida");
			else
				System.out.println("Il file non è firmato");


		} catch (Exception e) {
			e.printStackTrace();
		}

	}

}
