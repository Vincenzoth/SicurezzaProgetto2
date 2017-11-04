package progetto;


import java.security.PrivateKey;
import java.security.PublicKey;

public class Run {

	public static void main(String[] args) {

		System.out.println("\n  -------     -------   Keymanager:");
		try {
			
			KeyManager km = new KeyManager();
			
			/*
			 // Aggiungi utenti
			km.newUser("01", 2048, "PKCS1Padding");
			km.newUser("02", 1024, "OAEPPadding");
			km.newUser("03", 1024, "OAEPPadding");
			km.newUser("04", 1024, "PKCS1Padding");
			km.newUser("05", 2048, "OAEPPadding");
			*/
			km.newUser("04", 1024, "PKCS1Padding");
			km.newUser("05", 2048, "OAEPPadding");
			// Rimuovi utente
			// km.removeUser("01");
			
			
			PrivateKey privKeyCod = km.getPrivateKeyCod("02");
			PublicKey pubKeyCod = km.getPublicKeyCod("02");
			
			System.out.println("Chiave privata: " + privKeyCod);
			System.out.println("Chiave pubblica: " + pubKeyCod);
			System.out.println();
						
			
			Incapsula incul = new Incapsula();
			incul.initCipher("DESede", "ECB", "PKCS5Padding");
			incul.writeCipherFile("documento.pdf", "01", "05");
			incul.writeDecipherFile("documento.pdf.ts", "05");
			
			System.out.println("File Criptato");
			

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

}
