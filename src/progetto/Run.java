package progetto;


import java.security.PrivateKey;
import java.security.PublicKey;

public class Run {

	public static void main(String[] args) {

		System.out.println("\n  -------     -------   Keymanager:");
		try {
			
			KeyManager km = new KeyManager();
			
			
			 // Aggiungi utenti
			km.newUser("01", 2048);
			km.newUser("02", 1024);
			
			
			
			
			// Rimuovi utente
			// km.removeUser("01");
			
			
			PrivateKey privKeyCod = km.getPrivateKeyCod("02");
			PublicKey pubKeyCod = km.getPublicKeyCod("02");
			
			System.out.println("Chiave privata: " + privKeyCod);
			System.out.println("Chiave pubblica: " + pubKeyCod);
			System.out.println("ok");
			
			
			
			Incapsula incul = new Incapsula();
			incul.initCipher("DES", "CBC", "PKCS5Padding");
			//"01","02",, "/file/documento.pdf"
			incul.writeCipherFile("documento.pdf", "01", "02");
			incul.writeDecipherFile("documento.pdf.ts", "02");
			

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

}
