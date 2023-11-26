
package aes_encryption_technique;

/**
 
 * @author Dalton
  
 * This code is unique because of the following:
  
 * The encryption and decryption method have been implemented in separate functions,
 * encryptMessage and decryptMessage, respectively.

 * The key used for encryption is generated dynamically by the generateKey method,
 * which returns a SecretKeySpec object with the algorithm AES and a string of characters "SecretKey1234567890".

 * The encrypted message is encoded in Base64 and decoded before decryption.

 * The main function prompts the user to enter a message to be encrypted and displays the original message,
 * the encrypted message, and the decrypted message.
 
 */

import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Scanner;
import java.util.*;

public class AES_ENCRYPTION_TECHNIQUE {
    
    public static void main(String[] args) {
        //prompt user to enter originalMessage to encrypt
        Scanner input = new Scanner(System.in);
        
    System.out.println("*************HELLO THERE LET'S TRY OUT AES ENCRYPTION TECHNIQUE, THIS IS FUN****************");
   System.out.println("ENTER YOUR MESSAGE BELOW");
        String originalMessage = input.nextLine();

        try {
            Key key = new SecretKeySpec("abcdefghijklmnop".getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
             System.out.println("Original Message: " + originalMessage);

            //We now encrypt the message and display to user the encrypted message
            byte[] encrypted = cipher.doFinal(originalMessage.getBytes());
            String hexEncrypted = toHexString(encrypted);
              System.out.println("Encrypted Message in Hexadecimal: " + hexEncrypted);
           
              //Decrypt the message and display to user
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decrypted = cipher.doFinal(encrypted);
            System.out.println("Decrypted message: " + new String(decrypted));
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
  }
    
    //Use a method to convert the byte characters into hexadecimal
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
    
    //Next line of code declares a constant named ALGORITHM of type String and initializes it with the value "AES", 
    //which stands for Advanced Encryption Standard.
  private static final String ALGORITHM = "AES";
  
  //We then declare a constant named KEY_VALUE of type byte array and initializes it with an array of characters
  //that represents a string "SecretKey". This value will be used as the encryption key.
  private static final byte[] KEY_VALUE = 
            new byte[] { 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y' };

  public static String encryptMessage(String message) throws Exception {
      /*
      This method encrypts a plain text originalMessage. It generates a secret key using the generateKey method and initializes a cipher object 
      using the ALGORITHM constant. The encryption mode is set using the constant Cipher.ENCRYPT_MODE and the secret key.
      The originalMessage is encrypted using the doFinal method of the cipher object, which returns the encrypted originalMessage as a byte array.
      The byte array is then encoded as a Base64 string and returned.
      */
    Key secretKey = generateKey();
    Cipher cipher = Cipher.getInstance(ALGORITHM);
    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    byte[] encryptedMessage = cipher.doFinal(message.getBytes());
    return Base64.getEncoder().encodeToString(encryptedMessage);
  }

  public static String decryptMessage(String encryptedMessage) throws Exception {
      /*
      This method decrypts an encrypted originalMessage. It generates a secret key using the generateKey method and initializes a cipher object using the ALGORITHM constant.
      The decryption mode is set using the constant Cipher.DECRYPT_MODE and the secret key. The encrypted originalMessage is first decoded from Base64
      and then passed to the doFinal method of the cipher object to decrypt it. The decrypted originalMessage is then returned as a string.
      */
    Key secretKey = generateKey();
    Cipher cipher = Cipher.getInstance(ALGORITHM);
    cipher.init(Cipher.DECRYPT_MODE, secretKey);
    byte[] decodedMessage = Base64.getDecoder().decode(encryptedMessage);
    byte[] decryptedMessage = cipher.doFinal(decodedMessage);
    return new String(decryptedMessage);
  }

 private static Key generateKey() throws Exception {
     /*
     In this method we generate a secret key used for encryption and decryption. It returns a SecretKeySpec object initialized with a byte array of characters
     that represents the string "SecretKey1234567890" and the algorithm "AES".
     */
  return new SecretKeySpec(new byte[] { 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0' }, "AES");
}



}
    
    
   
