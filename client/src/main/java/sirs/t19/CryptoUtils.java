package sirs.t19;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class CryptoUtils {

  private static final String AES_ALGO = "AES/CBC/PKCS5Padding";
  private static final String RSA_ALGO = "RSA";

  public static KeyPair generateRSAKeyPair() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGO);
    keyGen.initialize(2048);
    return keyGen.generateKeyPair();
  }

  public static SecretKey generateAESKey() throws Exception {
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(128);
    return keyGen.generateKey();
  }

  public static byte[] wrapKey(PublicKey pubKey, SecretKey aesKey) throws Exception {
    Cipher cipher = Cipher.getInstance(RSA_ALGO);
    cipher.init(Cipher.WRAP_MODE, pubKey);
    return cipher.wrap(aesKey);
  }

  public static String hashPassword(String password) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    byte[] hash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
    return Base64.getEncoder().encodeToString(hash);
  }

  public static SecretKey unwrapKey(PrivateKey privKey, byte[] wrappedKey) throws Exception {
    Cipher cipher = Cipher.getInstance(RSA_ALGO);
    cipher.init(Cipher.UNWRAP_MODE, privKey);
    return (SecretKey) cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
  }

  public static byte[] encrypt(SecretKey key, byte[] plainText) throws Exception {
    Cipher cipher = Cipher.getInstance(AES_ALGO);
    byte[] iv = new byte[16];
    new SecureRandom().nextBytes(iv);
    IvParameterSpec ivSpec = new IvParameterSpec(iv);
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    byte[] cipherText = cipher.doFinal(plainText);
    byte[] output = new byte[iv.length + cipherText.length];
    System.arraycopy(iv, 0, output, 0, iv.length);
    System.arraycopy(cipherText, 0, output, iv.length, cipherText.length);
    return output;
  }

  public static byte[] decrypt(SecretKey key, byte[] encryptedData) throws Exception {
    Cipher cipher = Cipher.getInstance(AES_ALGO);
    byte[] iv = new byte[16];
    System.arraycopy(encryptedData, 0, iv, 0, iv.length);
    IvParameterSpec ivSpec = new IvParameterSpec(iv);
    int cipherTextSize = encryptedData.length - 16;
    byte[] cipherText = new byte[cipherTextSize];
    System.arraycopy(encryptedData, 16, cipherText, 0, cipherTextSize);
    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    return cipher.doFinal(cipherText);
  }
}
