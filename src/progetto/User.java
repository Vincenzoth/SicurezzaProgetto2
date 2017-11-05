package progetto;


import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;

public class User implements Serializable {

	private static final long serialVersionUID = 1L;
	
	private String ID;
	private PublicKey pubKeyCod;
	private PrivateKey privKeyCod;
	private String modPadding; 
	
	private PublicKey pubKeyVer;
	private PrivateKey privKeyVer;
	private String sigType;
	
	
	public User(String ID,  PublicKey pubKeyCod, PrivateKey privKeyCod, String modPadding, PublicKey pubKeyVer, PrivateKey privKeyVer, String sigType) {
		this.ID = ID;
		this.pubKeyCod = pubKeyCod;
		this.privKeyCod = privKeyCod;
		this.modPadding = modPadding;
		this.pubKeyVer = pubKeyVer;
		this.privKeyVer = privKeyVer;
		this.sigType = sigType;
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
	public String getmodPadding() {
		return modPadding;
	}
	public void setModPadding(String modPadding) {
		this.modPadding = modPadding;
	}
	public PublicKey getPubKeyVer() {
		return pubKeyVer;
	}
	public void setPubKeyVer(PublicKey pubKeyVer) {
		this.pubKeyVer = pubKeyVer;
	}
	public PrivateKey getPrivKeyVer() {
		return privKeyVer;
	}
	public void setPrivKeyVer(PrivateKey privKeyVer) {
		this.privKeyVer = privKeyVer;
	}
	public String getSigType() {
		return sigType;
	}
	public void setSigType(String sigType) {
		this.sigType = sigType;
	}
}
