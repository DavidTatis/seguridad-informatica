package cifradopublico;

/**
 * <p>Título: BySSLab</p>
 * <p>Descripción: Prácticas de BySS</p>
 * <p>Copyright: Copyright (c) 2015</p>
 * <p>Empresa: DISIT de la UEx</p>
 * @author Lorenzo M. Martínez Bravo
 * @version 2.0
 */

import java.io.*;

public class Header {
  private final static byte MARK[]= {1,2,3,4,5,6,7,8,9,0};
  private final static int MARKLENGTH = 10;
  private final static int HEADERLENGTH = MARKLENGTH+2;
  /**
   * Algoritmo de cifrado de clave pública  
   */
  private String cipher;
  /**
   * Algoritmo de firma con clave privada 
   */
  private String signer;
  /**
   * Firma calculada
   */
  private byte[] sign;

  /**
   * Constructor por omision. Inicia los atributos con valores por omision.
   */
  public Header() {
    cipher = Options.ciphers[0];
    signer = Options.signers[0];
  }

  /**
   * Constructor. Inicia los atributos con valores suministrados para cifrado
   * @param cipher - nombre estándar del algoritmo elegido
   */
  public Header(String cipher) {
     this.cipher = cipher;
     this.signer = Options.signers[0];
  }

  /**
   * Constructor. Inicia los atributos con valores suministrados para firma
   * @param signer - nombre estándar del algoritmo elegido
   * @param sign   - Firma calculada con el algoritmo elegido
   */
  public Header(String signer, byte[] sign) {
     this.signer = signer;
     this.sign   = sign;
     this.cipher = Options.ciphers[0];
  }

  public String getCipher(){
    return cipher;
  }

  public String getSigner(){
	    return signer;
	  }
  
  public byte[] getSign() {
    return sign;
  }

  /**
   * Intenta cargar los datos de una cabecera desde un InputStream abierto.   
   * Si tiene exito, los datos quedan en la clase.
   * @param r el InputStream abierto
   * @return true si la carga es correcta, false en otro caso
   */
  public boolean load(InputStream r){
    byte buf[] = new byte[HEADERLENGTH];
    boolean breturn=false;
    try {
      if(r.read(buf,0,HEADERLENGTH)==HEADERLENGTH) {
        byte i=0;
        while((i<MARKLENGTH) && (buf[i]==MARK[i])) i++;
        if (i==MARKLENGTH) {
          cipher = Options.ciphers[buf[i]];
            System.out.println("respuesta:"+buf[i-1]+".."+MARK[i-1]);
            System.out.println((i+1)+"<---option buf i+1");
          signer = Options.signers[buf[i+1]];
          ObjectInputStream ois = new ObjectInputStream(r);
          sign = (byte[])ois.readObject();
          breturn = true;
        }
      }
    }
    catch (Exception e) {
      e.printStackTrace();
    }
    return breturn;
  }

  /**
   * Intenta guardar la cabecera actual en un OutputStream abierto.
   * @param fos el OutputStream abierto
   * @return true si tiene exito, false en otro caso
   */
  public boolean save(OutputStream fos){
    boolean breturn=false;
    try {
      fos.write(MARK);
      fos.write(search(Options.ciphers, cipher));
      fos.write(search(Options.signers, signer));
      ObjectOutputStream oos = new ObjectOutputStream(fos);
        System.out.println(sign.toString()+"<------firma");
      oos.writeObject(sign);
      breturn = true;
    }
    catch (Exception e) {
    }
    return breturn;
  }

  private int search(String a[], String m) {
    int i;
    for(i=a.length-1; i!=-1; i--)
      if(a[i].compareTo(m)==0) break;
    return i;
  }

  /**
   * Prueba el funcionamiento de la clase, creando una cabecera, guardandola en un   
   * fichero y recuperandola posteriomente.
   */
  public static void test() {
    try {
    Header fh = new Header("RSA/ECB/PKCS1Padding");
    FileOutputStream fos = new FileOutputStream("fileheader.prueba1");
    fh.save(fos);
    fos.close();

    byte[] sign = {1,2,3,4,5,6,7,8,9,0};
    fh = new Header("SHA1withRSA",sign);
    fos = new FileOutputStream("fileheader.prueba2");
    fh.save(fos);
    fos.close();
    
    Header fh2= new Header();
    FileInputStream fis = new FileInputStream("fileheader.prueba1");
    if (fh2.load(fis)){
      System.out.println("Leído, Algoritmo: "+fh2.getCipher());
    }
    else
      System.out.println("Error en la carga 1");
    fis.close();
    
    fh2= new Header();
    fis = new FileInputStream("fileheader.prueba2");
    if (fh2.load(fis)){
      System.out.print("Leído, Algoritmo: "+fh2.getSigner()+
    		  			" Firma: ");
      sign = fh2.getSign();
      for(int i=0; i<sign.length;i++) System.out.print(sign[i]);
    }
    else
      System.out.println("Error en la carga 2");
    fis.close();
    }
    catch (Exception e) {e.printStackTrace();};
  }

  public static void main(String[] args){
	  Header.test();
  }
  
}//FileHeader