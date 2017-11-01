package progetto;

public class Run {

	public static void main(String[] args) {
		Incapsula incul = new Incapsula("DES", "CFB", "PKCS5Padding", "/file/documento.pdf");		
		incul.cipherFile();
		incul.decipherFile();

	}

}
