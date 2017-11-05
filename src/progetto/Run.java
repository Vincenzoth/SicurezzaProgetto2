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
			km.newUser("01", 2048, "PKCS1Padding", 1024, "SHA256withDSA");
			km.newUser("02", 1024, "OAEPPadding", 1024, "SHA224withDSA");
			km.newUser("03", 1024, "OAEPPadding", 1024, "SHA1withDSA");
			km.newUser("04", 1024, "PKCS1Padding", 2048, "SHA224withDSA");
			km.newUser("05", 2048, "OAEPPadding", 2048, "SHA256withDSA");
			km.newUser("06", 2048, "OAEPPadding", 2048, "SHA1withDSA");//ERRORE
			*/
			
			km.newUser("01", 2048, "PKCS1Padding", 1024, "SHA256withDSA");
			km.newUser("02", 1024, "OAEPPadding", 1024, "SHA224withDSA");
			km.newUser("03", 1024, "OAEPPadding", 1024, "SHA1withDSA");
			km.newUser("04", 1024, "PKCS1Padding", 2048, "SHA224withDSA");
			km.newUser("05", 2048, "OAEPPadding", 2048, "SHA256withDSA");
		

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
						
			boolean sig = true;
			Incapsula incul = new Incapsula();
			incul.initCipher("DESede", "ECB", "PKCS5Padding");
			incul.writeCipherFile("documento.pdf", "05", "02", sig);		
			System.out.println("File Criptato");
			
			boolean isVer = incul.writeDecipherFile("documento.pdf.ts", "02");
			System.out.println("File decriptato");
			
			if(sig) {
				if(isVer)
					System.out.println("La firma è valida");
				else
					System.out.println("La firma NON è valida");
			}
			

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

}
