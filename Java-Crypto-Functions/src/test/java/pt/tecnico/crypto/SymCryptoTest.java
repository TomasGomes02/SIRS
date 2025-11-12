package pt.tecnico.crypto;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import org.junit.jupiter.api.Test;

public class SymCryptoTest {
  /**
   * Plain text with repeated pattern (32 'a' characters = two 16-byte AES
   * blocks)
   */
  private final String plainTextWithPattern =
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  /** Plain text bytes. */
  private final byte[] plainBytes = plainTextWithPattern.getBytes();

  /** Symmetric cryptography algorithm. */
  private static final String SYM_ALGO = "AES";
  /** Symmetric algorithm key size. */
  private static final int SYM_KEY_SIZE = 128;

  /** ECB Cipher configuration. */
  private static final String SYM_CIPHER_ECB = "AES/ECB/PKCS5Padding";
  /** CBC Cipher configuration. */
  private static final String SYM_CIPHER_CBC = "AES/CBC/PKCS5Padding";

  /**
   * Test AES encryption/decryption using ECB mode with repeated pattern.
   * ECB mode will show identical ciphertext blocks for identical plaintext
   * blocks.
   */
  @Test
  public void testECBRepeatedPattern() throws Exception {
    System.out.println("=== TEST ECB MODE WITH REPEATED PATTERN ===");
    System.out.println("Cipher: " + SYM_CIPHER_ECB);
    System.out.println("Plaintext: \"" + plainTextWithPattern + "\"");
    System.out.println("Plaintext bytes: " + printHexBinary(plainBytes));
    System.out.println();

    // Generate AES key
    KeyGenerator keyGen = KeyGenerator.getInstance(SYM_ALGO);
    keyGen.init(SYM_KEY_SIZE);
    Key key = keyGen.generateKey();
    System.out.println("Key: " + printHexBinary(key.getEncoded()));
    System.out.println();

    // Get ECB cipher object (no IV needed)
    Cipher cipher = Cipher.getInstance(SYM_CIPHER_ECB);
    System.out.println("Provider: " + cipher.getProvider().getInfo());
    System.out.println();

    // Encrypt
    System.out.println("ENCRYPTING...");
    cipher.init(Cipher.ENCRYPT_MODE, key);
    byte[] cipherBytes = cipher.doFinal(plainBytes);

    System.out.println("Ciphertext: " + printHexBinary(cipherBytes));
    System.out.println();
    System.out.println(
        ">>> SECURITY ISSUE: With ECB, identical plaintext blocks produce");
    System.out.println(">>> identical ciphertext blocks! Notice the " +
                       "repeating patterns above.");
    System.out.println();

    // Decrypt
    System.out.println("DECRYPTING...");
    cipher.init(Cipher.DECRYPT_MODE, key);
    byte[] decryptedBytes = cipher.doFinal(cipherBytes);

    System.out.println("Decrypted: " + new String(decryptedBytes));
    System.out.println();

    // Verify
    assertEquals(plainTextWithPattern, new String(decryptedBytes));
    System.out.println("✓ ECB test passed");
    System.out.println();
  }

  /**
   * Test AES encryption/decryption using CBC mode with repeated pattern.
   * CBC mode will obfuscate patterns by XORing each block with the previous
   * ciphertext block.
   */
  @Test
  public void testCBCRepeatedPattern() throws Exception {
    System.out.println("=== TEST CBC MODE WITH REPEATED PATTERN ===");
    System.out.println("Cipher: " + SYM_CIPHER_CBC);
    System.out.println("Plaintext: \"" + plainTextWithPattern + "\"");
    System.out.println("Plaintext bytes: " + printHexBinary(plainBytes));
    System.out.println();

    // Generate AES key
    KeyGenerator keyGen = KeyGenerator.getInstance(SYM_ALGO);
    keyGen.init(SYM_KEY_SIZE);
    Key key = keyGen.generateKey();
    System.out.println("Key: " + printHexBinary(key.getEncoded()));
    System.out.println();

    // Get CBC cipher object
    Cipher cipher = Cipher.getInstance(SYM_CIPHER_CBC);
    System.out.println("Provider: " + cipher.getProvider().getInfo());
    System.out.println();

    // Generate random IV for CBC mode
    cipher.init(Cipher.ENCRYPT_MODE, key);
    IvParameterSpec ivSpec =
        cipher.getParameters().getParameterSpec(IvParameterSpec.class);
    System.out.println("Generated IV: " + printHexBinary(ivSpec.getIV()));
    System.out.println();
    System.out.println(
        ">>> SECURITY: A random IV is generated for each encryption session.");
    System.out.println(
        ">>> This IV must be stored/sent with the ciphertext for decryption.");
    System.out.println();

    // Encrypt
    System.out.println("ENCRYPTING...");
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    byte[] cipherBytes = cipher.doFinal(plainBytes);

    System.out.println("Ciphertext: " + printHexBinary(cipherBytes));
    System.out.println();
    System.out.println(
        ">>> ADVANTAGE: Even with identical plaintext blocks, the ciphertext");
    System.out.println(">>> appears random with no repeating patterns! " +
                       "Patterns are obfuscated.");
    System.out.println();

    // Decrypt (must use the same IV)
    System.out.println("DECRYPTING...");
    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    byte[] decryptedBytes = cipher.doFinal(cipherBytes);

    System.out.println("Decrypted: " + new String(decryptedBytes));
    System.out.println();

    // Verify
    assertEquals(plainTextWithPattern, new String(decryptedBytes));
    System.out.println("✓ CBC test passed");
    System.out.println();
  }
}
