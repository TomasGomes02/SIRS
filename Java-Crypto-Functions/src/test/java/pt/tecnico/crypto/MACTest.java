package pt.tecnico.crypto;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Test suite to show how the Java Security API can be used for MAC (Message
 * Authentication Codes).
 */
public class MACTest {

  /** Plain text to protect with the message authentication code. */
  final String plainText = "This is the plain text!";
  /** Plain text bytes. */
  final byte[] plainBytes = plainText.getBytes();

  /** Symmetric cryptography algorithm. */
  private static final String SYM_ALGO = "AES";
  /** Symmetric algorithm key size. */
  private static final int SYM_KEY_SIZE = 128;

  /** Message authentication code algorithm. */
  private static final String MAC_ALGO = "HmacSHA256";

  /**
   * Symmetric cipher: combination of algorithm, block processing, and padding.
   */
  private static final String SYM_CIPHER = "AES/ECB/PKCS5Padding";
  /** Digest algorithm. */
  private static final String DIGEST_ALGO = "SHA-256";

  private static final int NONCE_SIZE = 16; // 16 random bytes

  // Store used nonces to detect replays
  private final Set<String> usedNonces = new HashSet<>();

  /**
   * Generate a Message Authentication Code using the Mac object provided by
   * Java
   */
  @Test
  public void testMACObject() throws Exception {
    System.out.print("TEST '");
    System.out.print(MAC_ALGO);
    System.out.println("' message authentication code.");

    System.out.println("Text:");
    System.out.println(plainText);
    System.out.println("Bytes:");
    System.out.println(printHexBinary(plainBytes));

    // generate AES secret key
    SecretKey key = generateMACKey(SYM_KEY_SIZE);

    // make MAC
    System.out.println("Signing...");
    byte[] cipherDigest = makeMAC(plainBytes, key);
    System.out.println("CipherDigest:");
    System.out.println(printHexBinary(cipherDigest));

    byte[] tamperedBytes = new byte[10];
    // verify the MAC
    System.out.println("Verifying...");

    // boolean result = verifyMAC(cipherDigest, tamperedBytes, key);
    boolean result = verifyMAC(cipherDigest, plainBytes, key);
    System.out.println("MAC is " + (result ? "right" : "wrong"));
    assertTrue(result);

    System.out.println();
    System.out.println();
  }

  @Test
  public void testMACWithNonceFreshness() throws Exception {
    System.out.println("=== TESTING MAC WITH RANDOM NONCE FRESHNESS ===");
    System.out.println("Plaintext: \"" + plainText + "\"");
    System.out.println();

    SecretKey key = generateMACKey(SYM_KEY_SIZE);

    // legit message 1
    System.out.println("--- Sending Message #1 ---");
    byte[] nonce1 = generateRandomNonce();
    byte[] mac1 = makeMACWithNonce(plainBytes, nonce1, key);

    boolean valid1 = verifyMACWithNonce(mac1, plainBytes, nonce1, key);
    System.out.println("Verification: " + (valid1 ? "SUCCESS " : "FAIL "));
    assertTrue(valid1);
    System.out.println();

    // legit message 2 (different nonce)
    System.out.println("--- Sending Message #2 ---");
    byte[] nonce2 = generateRandomNonce();
    byte[] mac2 = makeMACWithNonce(plainBytes, nonce2, key);

    boolean valid2 = verifyMACWithNonce(mac2, plainBytes, nonce2, key);
    System.out.println("Verification: " + (valid2 ? "SUCCESS " : "FAIL "));
    assertTrue(valid2);
    System.out.println();

    // replay attack
    System.out.println("--- Replay Attack: Resending Message #1 ---");
    boolean replayValid = verifyMACWithNonce(mac1, plainBytes, nonce1, key);
    System.out.println("Replay detected: " + (!replayValid ? "YES " : "NO "));
    assertFalse(replayValid, "Should detect replay!");
    System.out.println();

    System.out.println("=== TEST PASSED ===");
  }

  private static byte[] concatenate(byte[] a, byte[] b) {
    byte[] result = new byte[a.length + b.length];
    System.arraycopy(a, 0, result, 0, a.length);
    System.arraycopy(b, 0, result, a.length, b.length);
    return result;
  }

  /** Generate random Nonce */
  private byte[] generateRandomNonce() {
    byte[] nonce = new byte[NONCE_SIZE];
    new SecureRandom().nextBytes(nonce);
    return nonce;
  }

  /** Create MAC with nonce prepended */
  private byte[] makeMACWithNonce(byte[] message, byte[] nonce, SecretKey key)
      throws Exception {
    byte[] dataToMAC = concatenate(nonce, message);

    Mac mac = Mac.getInstance(MAC_ALGO);
    mac.init(key);
    byte[] macBytes = mac.doFinal(dataToMAC);

    System.out.println("  Nonce: " + printHexBinary(nonce));
    System.out.println("  MAC: " + printHexBinary(macBytes));

    return macBytes;
  }

  private boolean verifyMACWithNonce(byte[] receivedMAC, byte[] message,
                                     byte[] nonce, SecretKey key)
      throws Exception {
    String nonceString = printHexBinary(nonce);
    System.out.println("Received nonce: " + nonceString);

    // Step 1: Check if nonce was already used
    if (usedNonces.contains(nonceString)) {
      System.out.println("REPLAY DETECTED! Nonce already used.");
      return false;
    }

    // Step 2: Verify MAC
    byte[] dataToMAC = concatenate(nonce, message);
    Mac mac = Mac.getInstance(MAC_ALGO);
    mac.init(key);
    byte[] recomputedMAC = mac.doFinal(dataToMAC);

    boolean macMatches = Arrays.equals(receivedMAC, recomputedMAC);

    if (macMatches) {
      System.out.println("MAC valid. Storing nonce.");
      usedNonces.add(nonceString);
      return true;
    } else {
      System.out.println("MAC invalid. Message tampered.");
      return false;
    }
  }

  /** Generates a SecretKey for using in message authentication code. */
  private static SecretKey generateMACKey(int keySize) throws Exception {
    KeyGenerator keyGen = KeyGenerator.getInstance(SYM_ALGO);
    keyGen.init(keySize);
    SecretKey key = keyGen.generateKey();

    return key;
  }

  /** Makes a message authentication code. */
  private static byte[] makeMAC(byte[] bytes, SecretKey key) throws Exception {
    Mac mac = Mac.getInstance(MAC_ALGO);
    mac.init(key);
    byte[] macBytes = mac.doFinal(bytes);

    return macBytes;
  }

  /**
   * Calculates new digest from text and compare it to the to deciphered digest.
   */
  private static boolean verifyMAC(byte[] receivedMacBytes, byte[] bytes,
                                   SecretKey key) throws Exception {
    Mac mac = Mac.getInstance(MAC_ALGO);
    mac.init(key);
    byte[] recomputedMacBytes = mac.doFinal(bytes);
    return Arrays.equals(receivedMacBytes, recomputedMacBytes);
  }

  /**
   * Generate a Message Authentication Code by performing all the steps
   * separately (for illustration purposes). It is better to use the Mac object.
   */
  @Test
  public void testSignatureStepByStep() throws Exception {
    System.out.print(
        "TEST step-by-step message authentication code using cipher '");
    System.out.print(SYM_CIPHER);
    System.out.print("' and digest '");
    System.out.print(DIGEST_ALGO);
    System.out.println("'");

    final byte[] plainBytes = plainText.getBytes();

    System.out.println("Text:");
    System.out.println(plainText);
    System.out.println("Bytes:");
    System.out.println(printHexBinary(plainBytes));

    // generate AES secret key
    SecretKey key = generateMACKey(SYM_KEY_SIZE);

    // make MAC
    System.out.println("Signing...");
    byte[] cipherDigest = digestAndCipher(plainBytes, key);
    System.out.println("CipherDigest:");
    System.out.println(printHexBinary(cipherDigest));

    // verify the MAC
    System.out.println("Verifying...");
    boolean result = redigestDecipherAndCompare(cipherDigest, plainBytes, key);
    System.out.println("MAC is " + (result ? "right" : "wrong"));
    assertTrue(result);

    System.out.println();
    System.out.println();
  }

  /** auxiliary method to calculate digest from text and cipher it */
  private static byte[] digestAndCipher(byte[] bytes, SecretKey key)
      throws Exception {

    // get a message digest object using the specified algorithm
    MessageDigest messageDigest = MessageDigest.getInstance(DIGEST_ALGO);

    // calculate the digest and print it out
    messageDigest.update(bytes);
    byte[] digest = messageDigest.digest();
    System.out.println("Digest:");
    System.out.println(printHexBinary(digest));

    // get an AES cipher object
    Cipher cipher = Cipher.getInstance(SYM_CIPHER);

    cipher.init(Cipher.ENCRYPT_MODE, key);
    byte[] cipherDigest = cipher.doFinal(digest);

    return cipherDigest;
  }

  /**
   * auxiliary method to calculate new digest from text and compare it to the to
   * deciphered digest
   */
  private static boolean redigestDecipherAndCompare(byte[] cipherDigest,
                                                    byte[] bytes, SecretKey key)
      throws Exception {

    // get a message digest object using the specified algorithm
    MessageDigest messageDigest = MessageDigest.getInstance(DIGEST_ALGO);

    // calculate the digest and print it out
    messageDigest.update(bytes);
    byte[] digest = messageDigest.digest();
    System.out.println("New digest:");
    System.out.println(printHexBinary(digest));

    // get an AES cipher object
    Cipher cipher = Cipher.getInstance(SYM_CIPHER);

    // decipher digest using the public key
    cipher.init(Cipher.DECRYPT_MODE, key);
    byte[] decipheredDigest = cipher.doFinal(cipherDigest);
    System.out.println("Deciphered Digest:");
    System.out.println(printHexBinary(decipheredDigest));

    // compare digests
    if (digest.length != decipheredDigest.length)
      return false;

    for (int i = 0; i < digest.length; i++)
      if (digest[i] != decipheredDigest[i])
        return false;
    return true;
  }
}
