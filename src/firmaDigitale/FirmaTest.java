package firmaDigitale;
import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class FirmaTest {

	private DigitalSign fr;
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
	}

	@Before
	public void setUp() throws Exception {
		fr = new DigitalSign();
		
	}

	@Test
	public void testFirmaCorretta() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
		// GENERAZIONE DELLA FIRMA DIGITALE
				// Prendere il testo da firmare
		String text = "Salerno";
		byte[] data = text.getBytes();
		KeyPair keyPair = DigitalSign.generateKeys();
		byte[] signatureBytes = fr.generateDigitalSignature(data, keyPair.getPrivate());
		// Verifica della firma
		assertTrue(fr.verify(signatureBytes, data, keyPair.getPublic()));
		
	}
	@Test
	public void testFirmaNonCorretta() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
		// GENERAZIONE DELLA FIRMA DIGITALE
				// Prendere il testo da firmare
		String text = "Salerno";
		byte[] data = text.getBytes();
		KeyPair keyPair = DigitalSign.generateKeys();
		KeyPair keyPair1 = DigitalSign.generateKeys();
		byte[] signatureBytes = fr.generateDigitalSignature(data, keyPair.getPrivate());

		// Verifica della firma
		assertFalse(fr.verify(signatureBytes, data, keyPair1.getPublic()));
		
	}
	
	@Test
	public void testFirmaFileCorretta() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, IOException {
		// GENERAZIONE DELLA FIRMA DIGITALE
				// Prendere il testo da firmare
		byte[] pdf = Files.readAllBytes(Paths.get(System.getProperty("user.dir") + "/file/" +"documento.pdf.ts"));
		KeyPair keyPair = DigitalSign.generateKeys();

		byte[] signatureBytes = fr.generateDigitalSignature(pdf, keyPair.getPrivate());
		DigitalSign.convertByteArrayToFile(signatureBytes, "documento.pdf.ts");
		// Verifica della firma
		assertTrue(fr.verify(signatureBytes, pdf, keyPair.getPublic()));
		
	}

}
