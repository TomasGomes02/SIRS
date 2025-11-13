package pt.tecnico.crypto;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import javax.crypto.Cipher;
import org.junit.jupiter.api.Test;

/**
 * Test suite to show how the Java Security API can be used for asymmetric
 * cryptography.
 *
 * Performance timing measurements added to compare RSA operations with AES.
 */
public class AsymCryptoTest {

  /** Plain text to digest. */
  private final String plainText = "This is the plain text!";
  /** Plain text bytes. */
  private final byte[] plainBytes = plainText.getBytes();

  /** Asymmetric cryptography algorithm. */
  private static final String ASYM_ALGO = "RSA";
  /** Asymmetric cryptography key size. */
  private static final int ASYM_KEY_SIZE = 2048;
  /**
   * Asymmetric cipher: combination of algorithm, block processing, and padding.
   */
  private static final String ASYM_CIPHER = "RSA/ECB/PKCS1Padding";

  /**
   * Public key cryptography test. Cipher with public key, decipher with private
   * key.
   *
   * @throws Exception because test is not concerned with exception handling
   */
  @Test
  public void testCipherPublicDecipherPrivate() throws Exception {
    System.out.print("TEST '");
    System.out.print(ASYM_CIPHER);
    System.out.println("' cipher with public, decipher with private");

    System.out.println("Text");
    System.out.println(plainText);
    System.out.println("Bytes:");
    System.out.println(printHexBinary(plainBytes));

    // Start counting time for key generation
    long startingKeyGenerationTime = System.nanoTime();

    // generate an RSA key pair
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ASYM_ALGO);
    keyGen.initialize(ASYM_KEY_SIZE);
    KeyPair keyPair = keyGen.generateKeyPair();

    long endingKeyGenerationTime = System.nanoTime();
    System.out.printf("Key pair generated in %.3f milliseconds%n",
                      (endingKeyGenerationTime - startingKeyGenerationTime) /
                          1_000_000.0);
    System.out.println();

    // get an RSA cipher object
    Cipher cipher = Cipher.getInstance(ASYM_CIPHER);

    System.out.println("Ciphering with public key...");

    // Start counting time for encryption
    long startingEncryptionTime = System.nanoTime();

    // encrypt the plain text using the public key
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
    byte[] cipherBytes = cipher.doFinal(plainBytes);

    long endingEncryptionTime = System.nanoTime();

    System.out.println("Ciphered bytes:");
    System.out.println(printHexBinary(cipherBytes));
    System.out.printf("Encryption completed in %.3f milliseconds%n",
                      (endingEncryptionTime - startingEncryptionTime) /
                          1_000_000.0);
    System.out.println();

    System.out.println("Deciphering with private key...");

    // Start counting time for decryption
    long startingDecryptionTime = System.nanoTime();

    // decipher the ciphered digest using the private key
    cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
    byte[] decipheredBytes = cipher.doFinal(cipherBytes);

    long endingDecryptionTime = System.nanoTime();

    System.out.println("Deciphered bytes:");
    System.out.println(printHexBinary(decipheredBytes));
    System.out.printf("Decryption completed in %.3f milliseconds%n",
                      (endingDecryptionTime - startingDecryptionTime) /
                          1_000_000.0);
    System.out.println();

    System.out.println("Text:");
    String newPlainText = new String(decipheredBytes);
    System.out.println(newPlainText);

    assertEquals(plainText, newPlainText);

    System.out.println();
    System.out.println();
  }

  /**
   * Public key cryptography test. Cipher with private key, decipher with public
   * key.
   *
   * @throws Exception because test is not concerned with exception handling
   */
  @Test
  public void testCipherPrivateDecipherPublic() throws Exception {
    System.out.print("TEST '");
    System.out.print(ASYM_CIPHER);
    System.out.println("' cipher with private, decipher with public");

    System.out.println("Text:");
    System.out.println(plainText);
    System.out.println("Bytes:");
    System.out.println(printHexBinary(plainBytes));

    // Start counting time for key generation
    long startingKeyGenerationTime = System.nanoTime();

    // generate an RSA key pair
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ASYM_ALGO);
    keyGen.initialize(ASYM_KEY_SIZE);
    KeyPair keyPair = keyGen.generateKeyPair();

    long endingKeyGenerationTime = System.nanoTime();
    System.out.printf("Key pair generated in %.3f milliseconds%n",
                      (endingKeyGenerationTime - startingKeyGenerationTime) /
                          1_000_000.0);
    System.out.println();

    // get an RSA cipher object
    Cipher cipher = Cipher.getInstance(ASYM_CIPHER);

    System.out.println("Ciphering with private key...");

    // Start counting time for encryption
    long startingEncryptionTime = System.nanoTime();

    cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
    byte[] cipherBytes = cipher.doFinal(plainBytes);

    long endingEncryptionTime = System.nanoTime();

    System.out.println("Ciphered bytes:");
    System.out.println(printHexBinary(cipherBytes));
    System.out.printf("Encryption completed in %.3f milliseconds%n",
                      (endingEncryptionTime - startingEncryptionTime) /
                          1_000_000.0);
    System.out.println();

    System.out.println("Deciphering with public key...");

    // Start counting time for decryption
    long startingDecryptionTime = System.nanoTime();

    cipher.init(Cipher.DECRYPT_MODE, keyPair.getPublic());
    byte[] decipheredBytes = cipher.doFinal(cipherBytes);

    long endingDecryptionTime = System.nanoTime();

    System.out.println("Deciphered bytes:");
    System.out.println(printHexBinary(decipheredBytes));
    System.out.printf("Decryption completed in %.3f milliseconds%n",
                      (endingDecryptionTime - startingDecryptionTime) /
                          1_000_000.0);
    System.out.println();

    System.out.println("Text:");
    String newPlainText = new String(decipheredBytes);
    System.out.println(newPlainText);

    assertEquals(plainText, newPlainText);

    System.out.println();
    System.out.println();
  }
}
