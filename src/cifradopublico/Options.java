package cifradopublico;

/**
 * <p>Título: BySSLab</p>
 * <p>Descripción: Prácticas de BySS</p>
 * <p>Copyright: Copyright (c) 2013</p>
 * <p>Empresa: DISIT de la UEx</p>
 * @author Lorenzo M. Martínez Bravo
 * @version 1.0
 */

public class Options {

  public final static String []ciphers = {"RSA/ECB/PKCS1Padding"};
  public final static String []signers = {"SHA1withRSA","MD2withRSA","MD5withRSA"};

  private String cipher  = "RSA/ECB/PKCS1Padding";
  private String signer  = "SHA1withRSA";
  
  public Options() {
	  this.cipher = ciphers[0];
	  this.signer = signers[0];
  }
  
  public Options(String c, String s) {
	  this.cipher = c;
	  this.signer = s;
  }

  public String getCipher() {
    return cipher;
  }

  public void setCipher(String c) {
    this.cipher = c;
  }

  public String getSigner() {
		return signer;
  }
  
  public void setSigner(String signer) {
	this.signer = signer;
  }
}
