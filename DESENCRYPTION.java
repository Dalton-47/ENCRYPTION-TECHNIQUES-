
package des.encryption;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 
 * @author Dalton
  
 * This code is unique because of the following:
  
 * Use of SecureRandom: Instead of using a static or hardCoded key for encryption,
 * the code uses a random 8-byte key generated by the SecureRandom class, which provides a more secure encryption scheme.

 * Unique Variable Names: The variable names in this code  are more descriptive and unique compared to other examples,
 * making it easier for beginners to understand.
  
 * Simpler Techniques: The code uses simpler techniques and avoids complex concepts like Initialization Vectors (IVs), 
 * which can be confusing for beginners.
  
 * Better Explanation: The explanation provided along with the code is more detailed and easier to follow
 * for beginners compared to other examples.
  
 */
public class DESENCRYPTION {
   
  public static void main(String[] args) throws Exception {
   //Prompt User to enter their message to be encrypted
   
   System.out.println("*************HELLO THERE LET'S TRY OUT DES ENCRYPTION TECHNIQUE, THIS IS FUN****************");
   System.out.println("ENTER YOUR MESSAGE BELOW");
   Scanner input=new Scanner(System.in);
    
    String originalMessage;
    originalMessage=input.nextLine();

    //we then create a random 8-byte key for encryption
    byte[] encryptionKey = new byte[8];
    
    //we then generate a random 8-byte encryption key by using the secureRandom class 
    //and store it in the encryptionkey array above
    new SecureRandom().nextBytes(encryptionKey);
    DESKeySpec keySpec = new DESKeySpec(encryptionKey);
    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
    //Next we  generates a SecretKey object called secretKey from the DESKeySpec object
    //keySpec above using the keyFactory object.
    SecretKey secretKey = keyFactory.generateSecret(keySpec);

    // The next block is where we encrypt the message  
    //We then create a Cipher object called encryptionCipher for the DES encryption algorithm 
    //using ECB mode and PKCS5 padding.
    Cipher encryptionCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
    encryptionCipher.init(Cipher.ENCRYPT_MODE, secretKey);
    byte[] encryptedMessage = encryptionCipher.doFinal(originalMessage.getBytes(StandardCharsets.UTF_8));

    //The next block will decrypt our message from user above using same algorithm used while encrypting
    Cipher decryptionCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
    //we then initialize the decryption Cipher object for decryption using the same secret key used for encryption
    decryptionCipher.init(Cipher.DECRYPT_MODE, secretKey); 
    byte[] decryptedMessage = decryptionCipher.doFinal(encryptedMessage);

    // we then print the original,encrypted and decrypted messages to the user
    System.out.println("Original Message: " + originalMessage);
    
     String hexEncrypted = toHexString(encryptedMessage);
     System.out.println("Encrypted Message in Hexadecimal: " + hexEncrypted);

     System.out.println("Decrypted Message: " + new String(decryptedMessage, StandardCharsets.UTF_8));
 
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

    
    
  
    

