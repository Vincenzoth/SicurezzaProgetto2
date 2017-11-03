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
			incul.initCipher("DES", "CFB", "PKCS5Padding");
			//"01","02",, "/file/documento.pdf"
			incul.writeFile("documento.pdf", "01", "02");
			//incul.decipherFile();
			

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

}
