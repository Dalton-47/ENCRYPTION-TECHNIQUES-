
package rsa_encryption_technique;

/**
 *
 * @author Dalton
 * This code is unique because:
 
 * I have used the Java Cryptography API, which provides a higher level of security compared to other implementation methods, 
 * such as hand-rolled encryption algorithms. Additionally, the code generates both the public and private keys on-the-fly, 
 * which provides a higher level of security compared to other implementations that use Pre-defined or hardCoded keys.
 * 
 */

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;
import javax.crypto.Cipher;

public class RSA_ENCRYPTION_TECHNIQUE {
  public static void main(String[] args) throws Exception {
    Scanner sc = new Scanner(System.in);
    
    System.out.println("*************HELLO THERE LET'S TRY OUT RSA ENCRYPTION TECHNIQUE, THIS IS FUN****************");
   System.out.println("ENTER YOUR MESSAGE BELOW");
    String originalMessage = sc.nextLine();

    // Next we create a new instance of the KeyPairGenerator class, which is used to generate a public and private key pair for RSA encryption.
    //The argument passed in the parameters "RSA" specifies the type of encryption algorithm to be used.
    KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
    keyGenerator.initialize(512);//initializes the keyGenerator object with a key length of 512 bits.
    KeyPair keyPair = keyGenerator.generateKeyPair();//generates a new key pair and assigns it to the keyPair variable.
    PublicKey publicKey = keyPair.getPublic();//gets the public key from the keyPair object and assigns it to the publicKey variable.
    PrivateKey privateKey = keyPair.getPrivate();//gets the private key from the keyPair object and assigns it to the privateKey variable.

    
    //Next we now create an instance of the Cipher class, which is used to encrypt and decrypt data using the RSA encryption algorithm. 
    //The argument "RSA" specifies the type of encryption algorithm to be used.
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);//initializes the cipher object for encryption mode and uses the publicKey for the encryption.
    byte[] encryptedMessage = cipher.doFinal(originalMessage.getBytes());//encrypt the message and store the encrypted message as an array of bytes in the encryptedMessage variable.
    
     System.out.println("Original message: " + originalMessage);
     
      String hexEncrypted = toHexString(encryptedMessage);
     System.out.println("Encrypted Message in Hexadecimal: " + hexEncrypted);
  

    cipher.init(Cipher.DECRYPT_MODE, privateKey);//initializes the cipher object for decryption mode and uses the privateKey for the decryption.
    byte[] decryptedMessage = cipher.doFinal(encryptedMessage);
    System.out.println("Decrypted message: " + new String(decryptedMessage));
  }
  
   //use a method to convert the encrypted characters to Hexadecimal
    public static String toHexString(byte[] bytes) {
    StringBuilder hexString = new StringBuilder();

    for (int i = 0; i < bytes.length; i++) {
        String hex = Integer.toHexString(0xFF & bytes[i]);
        if (hex.length() == 1) {
            hexString.append('0');
        }
        hexString.append(hex);
    }

    return hexString.toString();
}
}
