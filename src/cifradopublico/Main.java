/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cifradopublico;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.DefaultListModel;
import javax.swing.JFileChooser;

/**
 *
 * @author David
 */
public class Main extends javax.swing.JFrame {
    DefaultListModel<String> model = new DefaultListModel<>();
    File file;
    /**
     * Creates new form Main
     */
    public Main() {
        initComponents();
    }
    
    private  File seleccionarArchivo(){
        //Se crea y se muestra el JFileChooser.        
        final JFileChooser fc=new JFileChooser();
        int returnVal = fc.showOpenDialog(this);
        //En caso de seleccionar algun archivo, se procede a almacenarlo en la variable file
         if (returnVal == JFileChooser.APPROVE_OPTION) {
            file = fc.getSelectedFile();
            return file;
         }
         return null;
    }
    
    /**
     * 
     * @param algoritmo algoritmo a utilizar para generar las firma, ejemplo: "RSA"
     * @throws NoSuchAlgorithmException
     * @throws IOException 
     */
     void GenerarCalves(String algoritmo) throws NoSuchAlgorithmException, IOException{
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algoritmo);
        kpg.initialize(512); // 512 bits
        KeyPair kp= kpg.generateKeyPair();
        FileOutputStream fout = null;
        ObjectOutputStream oos = null;
        fout = new FileOutputStream("kp.key");
        oos = new ObjectOutputStream(fout);
        oos.writeObject(kp);
        oos.close();
        fout.close();
        model.add(0,"Se han generado firmas correctamente.");
        logList.setModel(model);
    }
    
     /**
      * 
      * @param algoritmo Algoritmo de firma
      * @param privateKey Clave privada para firmar el archivo
      * @param file Archivo a firmar
      * @throws NoSuchAlgorithmException
      * @throws InvalidKeyException
      * @throws FileNotFoundException
      * @throws IOException
      * @throws SignatureException 
      * Se crea e archivo firmado en la misma ubicacion que el archivo seleccionado para firmar.
      */
    void Firmar(String algoritmo,PrivateKey privateKey, File file) throws NoSuchAlgorithmException, InvalidKeyException, FileNotFoundException, IOException, SignatureException{
        Signature dsa = Signature.getInstance(algoritmo);
        dsa.initSign(privateKey);        
        byte[] bytesArray = new byte[(int) file.length()]; 
        FileInputStream fis = new FileInputStream(file);
        fis.read(bytesArray);
        //GENERAR LA FIRMA CON EL FICHERO LEIDO
        dsa.update(bytesArray);
        //OBTENER LA FIRMA
        byte[] sig = dsa.sign();
        Header header=new Header(algoritmo,sig);
        //SE GUARDARA EL ARCHIVO EN LA MISMA UBICACION DE file, CON EL MISMO NOMBRE INCLUYENDO ".firmado" ANTES DE LA EXTENSION
        OutputStream ops=new FileOutputStream(file.getAbsolutePath()+".firmado."+file.getName().split("\\.")[file.getName().split("\\.").length-1]);
        //SE AGREGA EL Header A EL ARCHIVO FIRMADO, Y POSTERIORMENTE EL CONTENIDO ORIGINAL DE file
        header.save(ops);
        ops.write(bytesArray);
        ops.close();
        fis.close();
        model.add(0,"Se ha firamdo correctamente.");
        logList.setModel(model);
    }
    
    
    /***
     * 
     * @param algoritmo Algoritmo usado para verificar la firma. Debe ser el mismo con el que se firmó
     * @param file Archivo a verificar firma
     * @return True si la firma coincide con la clave publica almacenada en kp.key o False si no coincide 
     * @throws NoSuchAlgorithmException
     * @throws FileNotFoundException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     * @throws SignatureException
     * @throws ClassNotFoundException 
     */
    boolean VerificarFirma(String algoritmo,File file) throws NoSuchAlgorithmException, FileNotFoundException, IOException, InvalidKeyException, InvalidKeySpecException, SignatureException, ClassNotFoundException{
        Signature dsa = Signature.getInstance(algoritmo);
        FileInputStream fin = null;
        ObjectInputStream ois = null;
        fin = new FileInputStream(new File("kp.key"));
        ois = new ObjectInputStream(fin);
        //SE OBTIENE LA CLAVE PUBLICA, DEBE ENCONTRARSE ALMACENADA EN EL ARCHIVO KP.KEY
        PublicKey publicKey=((KeyPair)ois.readObject()).getPublic();
        dsa.initVerify(publicKey);
        
        Header header=new Header();
        FileInputStream fis = new FileInputStream(file);
        try{
            //SE EXTRAE EL Header DEL ARCHIVO, EN CASO DE QUE NO TENGA LA CABECERA, NO TIENE FIRMA.
            if (header.load(fis)) {
                model.add(0,"Carga correcta.");
                logList.setModel(model);
                
                byte[] bytesArray = new byte[(int) file.length()]; 
                int l;
                while((l=fis.read())!=-1){
                    dsa.update((byte) l);
                }
                
                fis.close();
                //EN CASO DE QUE EXISTA UNA CABECERA PERO NO COINCIDA EL ALGORITMO DE FIRMA:
                try{
                    boolean verifies = dsa.verify(header.getSign());
                    return verifies;
                }catch(SignatureException e){
                      model.add(0,"Algoritmo de firma incorrecto.");
                     logList.setModel(model);
                    return false;
                }
            }else{
                model.add(0,"Carga incorrecta.");
                logList.setModel(model);
            }
        }catch(ArrayIndexOutOfBoundsException e){
            model.add(0,"Firma incorrecta.");
            logList.setModel(model);
        }
       return false;
         
    }
    
    /***
     * Cifra con la clave publica que se encuentra en el archivo "kp.key" y usando el algoritmo  RSA/ECB/PKCS1Padding
     * @param file Archivo a cifrar
     * @throws NoSuchAlgorithmException
     * @throws FileNotFoundException
     * @throws NoSuchPaddingException
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws InvalidKeyException
     * @throws FileNotFoundException
     * @throws FileNotFoundException
     * @throws FileNotFoundException
     * @throws FileNotFoundException
     * @throws FileNotFoundException
     * @throws FileNotFoundException
     * @throws IOException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     */
    void Cifrar( File file) throws NoSuchAlgorithmException, FileNotFoundException, NoSuchPaddingException, IOException, ClassNotFoundException, InvalidKeyException, FileNotFoundException, FileNotFoundException, FileNotFoundException, FileNotFoundException, FileNotFoundException, FileNotFoundException, IOException, IllegalBlockSizeException, BadPaddingException{
            Header header=new Header("RSA/ECB/PKCS1Padding");
            Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");            
            FileInputStream fin = null;
            ObjectInputStream ois = null;
            fin = new FileInputStream(new File("kp.key"));
            ois = new ObjectInputStream(fin);
            PublicKey publicKey=((KeyPair)ois.readObject()).getPublic();
                
            c.init(Cipher.ENCRYPT_MODE,publicKey);
            //Archivo de salida, se almacena en la misma carpeta del archivo a cifrar con la palabra .cifrado. en el nombre            
            OutputStream outputStream=new FileOutputStream(file.getAbsolutePath()+".cifrado."+file.getName().split("\\.")[file.getName().split("\\.").length-1]);
            //SE CIFRA EL ARCHIVO EN BLOQUES DE 53
            float blockSize = 53;
            fin = new FileInputStream(file);
            byte[] l =new byte[(int)blockSize];           
            while((fin.read(l,0,53))!=-1){
                //SE CIFRA Y DE INMEDIATO SE ESCRIBE EN EL ARCHIVO DE SALIDA UBICADO EN LA MISMA RUTA DE file AÑADIENDO LA PALABRA .cifrado. ANTES DE LA EXTENSION
               outputStream.write(c.doFinal(l,0,53));
            }
            outputStream.close();
            fin.close();           
            //SE NOTIFICA LA OPERACION REALIZADA
            model.add(0,"Se ha cifrado correctamente");
            logList.setModel(model);            
    }
    
    /***
     * Descifra con la clave privada que se encuentra en el archivo "kp.key" y usando el algoritmo  RSA/ECB/PKCS1Padding
     * @param file Archivo a descifrar
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws FileNotFoundException
     * @throws IOException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws ClassNotFoundException
     * @throws IOException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException 
     */
    void Descifrar(File file) throws NoSuchAlgorithmException, NoSuchPaddingException, FileNotFoundException, IOException, IOException, InvalidKeyException, ClassNotFoundException, IOException, NoSuchPaddingException, IllegalBlockSizeException{
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        FileInputStream fin = null;
        ObjectInputStream ois = null;
        fin = new FileInputStream(new File("kp.key"));
        ois = new ObjectInputStream(fin);
        PrivateKey privateKey=((KeyPair)ois.readObject()).getPrivate();
        c.init(Cipher.DECRYPT_MODE,privateKey);        
        Header header=new Header("RSA/ECB/PKCS1Padding");
        InputStream is=new FileInputStream(file);
        //SE DESCIFRA EN BLOQUES DE 64
        int blockSize = 64;
        byte[] l =new byte[(int)blockSize];
        //ARCHIVO DE SALIDA, SE ENCUENTRA EN LA MISMA RUTA QUE file, SE LE AÑADE .descifrado. ANTES DE LA EXTENSION
        OutputStream ops= new FileOutputStream(file.getAbsolutePath()+".descifrado."+file.getName().split("\\.")[file.getName().split("\\.").length-1]);
        try {   
            while((is.read(l,0,64))!=-1){
                //SE DESCIFRA Y SE ALMACENA DE INMEDIATO
                ops.write(c.doFinal(l,0,64));
             }
            model.add(0,"Se ha descifrado correctamente.");
            logList.setModel(model);   
        } catch (BadPaddingException ex) {
            model.add(0,"Error al descifrar.");
            logList.setModel(model);   
        }
         ops.close();
         is.close();
        
            
    }
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        cb_firma = new javax.swing.JComboBox<>();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jButton1 = new javax.swing.JButton();
        jButton2 = new javax.swing.JButton();
        jButton3 = new javax.swing.JButton();
        jButton4 = new javax.swing.JButton();
        jLabel3 = new javax.swing.JLabel();
        jButton5 = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        logList = new javax.swing.JList<>();
        jLabel4 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();
        jLabel7 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        cb_firma.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "SHA1withRSA", "MD2withRSA", "MD5withRSA" }));
        cb_firma.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cb_firmaActionPerformed(evt);
            }
        });

        jLabel1.setText("Cifrado:");

        jLabel2.setText("Firma:");

        jButton1.setFont(new java.awt.Font("Calibri", 0, 12)); // NOI18N
        jButton1.setText("Cifrar");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        jButton2.setFont(new java.awt.Font("Calibri", 0, 12)); // NOI18N
        jButton2.setText("Descifrar");
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });

        jButton3.setText("Firmar");
        jButton3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton3ActionPerformed(evt);
            }
        });

        jButton4.setText("Verificar Firma");
        jButton4.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton4ActionPerformed(evt);
            }
        });

        jLabel3.setText("RSA/ECB/PKCS1Padding");

        jButton5.setText("Generar par de claves");
        jButton5.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton5ActionPerformed(evt);
            }
        });

        jScrollPane1.setViewportView(logList);

        jLabel4.setText("Recuerde antes de cualquier operacion debe tener un par de llaves");

        jLabel5.setText("El par de llaves debe encontrarse en la carpeta de este programa y llamarse kp.key, si no cuenta con una seleccione \"Generar par de claves\"");

        jLabel6.setText("Esta opcion le permite generar un par de llaves listas para usar");

        jLabel7.setText("David Tatis Posada");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jScrollPane1)
                        .addContainerGap())
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jButton1)
                                .addGap(18, 18, 18)
                                .addComponent(jButton2))
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jButton3)
                                .addGap(18, 18, 18)
                                .addComponent(jButton4)))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 337, Short.MAX_VALUE)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                .addComponent(jLabel1)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(jLabel3))
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                .addComponent(jLabel2)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(cb_firma, javax.swing.GroupLayout.PREFERRED_SIZE, 134, javax.swing.GroupLayout.PREFERRED_SIZE)))
                        .addGap(64, 64, 64))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jButton5)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jLabel6)
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel5)
                            .addComponent(jLabel4)
                            .addComponent(jLabel7))
                        .addGap(0, 0, Short.MAX_VALUE))))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButton5)
                    .addComponent(jLabel6))
                .addGap(54, 54, 54)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 182, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(jButton1)
                        .addComponent(jButton2))
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(jLabel1)
                        .addComponent(jLabel3)))
                .addGap(30, 30, 30)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(cb_firma, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(jLabel2))
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(jButton3)
                        .addComponent(jButton4)))
                .addGap(18, 18, 18)
                .addComponent(jLabel4, javax.swing.GroupLayout.PREFERRED_SIZE, 19, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(1, 1, 1)
                .addComponent(jLabel5)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 38, Short.MAX_VALUE)
                .addComponent(jLabel7)
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
    
          if (seleccionarArchivo()!=null) {
              try {
                  Cifrar(file);
              } catch (NoSuchAlgorithmException ex) {
                  Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
              } catch (NoSuchPaddingException ex) {
                  Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
              } catch (IOException ex) {
                  Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
              } catch (ClassNotFoundException ex) {
                  Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
              } catch (InvalidKeyException ex) {
                  Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
              } catch (IllegalBlockSizeException ex) {
                  Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
              } catch (BadPaddingException ex) {
                  Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
              }
          }  
    }//GEN-LAST:event_jButton1ActionPerformed

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
        //SE EJECUTA EL METODO seleccionarArchivo() EL CUAL ABRIRA UNA VENTANA PARA SELECCIONAR EL FICHERO.
        //SI SE HA SELECCIONADO UN FICHERO A descifrar SE PROCEDE
        if (seleccionarArchivo()!=null) {
            try {
                Descifrar(file);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchPaddingException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            } catch (ClassNotFoundException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IllegalBlockSizeException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        
    }//GEN-LAST:event_jButton2ActionPerformed

    private void jButton5ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton5ActionPerformed
        try {
            GenerarCalves("RSA");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_jButton5ActionPerformed

    private void jButton3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton3ActionPerformed
        try {
             if (seleccionarArchivo()!=null) {
                  FileInputStream fin = null;
                  ObjectInputStream ois = null;
                  fin = new FileInputStream(new File("kp.key"));
                  ois = new ObjectInputStream(fin);
                  PrivateKey privateKey=((KeyPair)ois.readObject()).getPrivate();
                  Firmar((String) cb_firma.getSelectedItem(), privateKey, file);
                  ois.close();
                  fin.close();
            }
            
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        
    }//GEN-LAST:event_jButton3ActionPerformed

    private void cb_firmaActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cb_firmaActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_cb_firmaActionPerformed

    private void jButton4ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton4ActionPerformed
        // TODO add your handling code here:
        if (seleccionarArchivo()!=null) {
            try {
                model.add(0,"------------------------");
                if(VerificarFirma((String) cb_firma.getSelectedItem(), file)){
                    model.add(0,"Firma correcta.");
                
                }else{
                    model.add(0,"Firma incorrecta.");
                    
                }
                model.add(0,"------------------------");
                logList.setModel(model);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeySpecException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            } catch (SignatureException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            } catch (ClassNotFoundException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }//GEN-LAST:event_jButton4ActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(Main.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Main.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Main.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Main.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new Main().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JComboBox<String> cb_firma;
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JButton jButton3;
    private javax.swing.JButton jButton4;
    private javax.swing.JButton jButton5;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JList<String> logList;
    // End of variables declaration//GEN-END:variables
}
