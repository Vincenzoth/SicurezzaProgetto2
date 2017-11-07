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
			km.newUser("01", 2048, "PKCS1Padding", 1024, "SHA256withDSA");
			km.newUser("02", 1024, "OAEPPadding", 1024, "SHA224withDSA");
			km.newUser("03", 1024, "OAEPPadding", 1024, "SHA1withDSA");
			km.newUser("04", 1024, "PKCS1Padding", 2048, "SHA224withDSA");
			km.newUser("05", 2048, "OAEPPadding", 2048, "SHA256withDSA");
			km.newUser("06", 2048, "OAEPPadding", 2048, "SHA1withDSA");
			 */			

			km.newUser("01", 2048, "PKCS1Padding", 1024, "SHA256withDSA");
			km.newUser("02", 1024, "OAEPPadding", 1024, "SHA224withDSA");
			km.newUser("03", 1024, "OAEPPadding", 1024, "SHA1withDSA");

			
			// Rimuovi utente
			// km.removeUser("01");

			PrivateKey privKeyCod = km.getPrivateKeyCod("02");
			PublicKey pubKeyCod = km.getPublicKeyCod("02");
			PrivateKey privKeyVer = km.getPrivateKeyVer("02");
			PublicKey pubKeyVer = km.getPublicKeyVer("02");

			System.out.println("Chiave privata: " + privKeyCod);
			System.out.println("Chiave pubblica: " + pubKeyCod);
			System.out.println("Chiave privata ver: " + privKeyVer);
			System.out.println("Chiave pubblica ver: " + pubKeyVer);
			System.out.println();

			System.out.println();
			System.out.println("\n  test  -------     -------   cipher:");
			
			boolean sig = true;
			Incapsula inc = new Incapsula(km);
			inc.initCipher("DESede", "CBC", "PKCS5Padding");
			inc.writeCipherFile(PATH + "/file/" + "documento.pdf", "05", "02", sig);		
			System.out.println("File Criptato");

			int isVer = inc.writeDecipherFile(PATH + "/file/" + "documento.pdf.ts", "02");
			System.out.println("File decriptato");


			if(isVer == 1)
				System.out.println("La firma è valida");
			else if (isVer == -1)
				System.out.println("La firma NON è valida");
			else
				System.out.println("Il file non è firmato");


		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

}
