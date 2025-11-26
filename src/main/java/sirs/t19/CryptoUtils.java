package sirs.t19;

import java.io.File;
import java.nio.file.Files;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoUtils {

  private static final String ALGO = "AES/CBC/PKCS5Padding";

  // Read the Secret Key (AES)
  public static SecretKeySpec readSecretKey(String path) throws Exception {
    byte[] keyBytes = Files.readAllBytes(new File(path).toPath());
    // Assumes the key file contains exactly 16 bytes (128 bit) or 24/32 bytes.
    return new SecretKeySpec(keyBytes, "AES");
  }

  // Encrypts plainText and returns a byte array containing [IV (16 bytes) + CipherText]
  public static byte[] encrypt(SecretKeySpec key, byte[] plainText) throws Exception {
    Cipher cipher = Cipher.getInstance(ALGO);

    // Generate a random IV (Crucial for security in CBC mode)
    byte[] iv = new byte[16];
    new SecureRandom().nextBytes(iv);
    IvParameterSpec ivSpec = new IvParameterSpec(iv);

    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    byte[] cipherText = cipher.doFinal(plainText);

    // Combine IV and CipherText so the reader can separate them later
    byte[] output = new byte[iv.length + cipherText.length];
    System.arraycopy(iv, 0, output, 0, iv.length);
    System.arraycopy(cipherText, 0, output, iv.length, cipherText.length);

    return output;
  }

  // Decrypts the byte array [IV + CipherText]
  public static byte[] decrypt(SecretKeySpec key, byte[] encryptedData) throws Exception {
    Cipher cipher = Cipher.getInstance(ALGO);

    // Extract IV (First 16 bytes)
    byte[] iv = new byte[16];
    System.arraycopy(encryptedData, 0, iv, 0, iv.length);
    IvParameterSpec ivSpec = new IvParameterSpec(iv);

    // Extract CipherText (The rest)
    int cipherTextSize = encryptedData.length - 16;
    byte[] cipherText = new byte[cipherTextSize];
    System.arraycopy(encryptedData, 16, cipherText, 0, cipherTextSize);

    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    return cipher.doFinal(cipherText);
  }
}
