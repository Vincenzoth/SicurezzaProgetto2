package progetto;


import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;

public class User implements Serializable {
	private String ID;
	private PublicKey pubKeyCod;
	private PrivateKey privKeyCod;
	private String pubKeyVer;
	private String privKeyVer;
	
	public User(String ID, PublicKey pubKeyCod, PrivateKey privKeyCod, String pubKeyVer, String privKeyVer) {
		this.ID = ID;
		this.pubKeyCod = pubKeyCod;
		this.privKeyCod = privKeyCod;
		this.pubKeyVer = pubKeyVer;
		this.pubKeyVer = pubKeyVer;
	}

	public String getID() {
		return ID;
	}
	public void setID(String iD) {
		ID = iD;
	}
	public PublicKey getPubKeyCod() {
		return pubKeyCod;
	}
	public void setPubKeyCod(PublicKey pubKeyCod) {
		this.pubKeyCod = pubKeyCod;
	}
	public PrivateKey getPrivKeyCod() {
		return privKeyCod;
	}
	public void setPrivKeyCod(PrivateKey privKeyCod) {
		this.privKeyCod = privKeyCod;
	}
	public String getPubKeyVer() {
		return pubKeyVer;
	}
	public void setPubKeyVer(String pubKeyVer) {
		this.pubKeyVer = pubKeyVer;
	}
	public String getPrivKeyVer() {
		return privKeyVer;
	}
	public void setPrivKeyVer(String privKeyVer) {
		this.privKeyVer = privKeyVer;
	}
}
