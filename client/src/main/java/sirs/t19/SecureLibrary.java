package sirs.t19;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import javax.crypto.SecretKey;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;

public class SecureLibrary {
  private static final String PRIVATE_KEY_DIR = "keys/";
  private static final String PUBLIC_KEY_DIR = "keys/public_keys/";

  private static PrivateKey readPrivateKey(String keyPath) throws Exception {
    byte[] keyBytes = Files.readAllBytes(new File(keyPath).toPath());
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return kf.generatePrivate(spec);
  }

  public static boolean loginUser(String userId, String password) throws Exception {
    File privFile = new File(PRIVATE_KEY_DIR, userId + ".key");
    File hashFile = new File(PRIVATE_KEY_DIR, userId + ".hash");

    if (!privFile.exists() || !hashFile.exists()) {
      return false;
    }

    byte[] storedHashBytes = Files.readAllBytes(hashFile.toPath());
    String storedHash = new String(storedHashBytes);
    String providedHash = CryptoUtils.hashPassword(password);

    return storedHash.equals(providedHash);
  }

  public static boolean registerUser(String userId, String password) throws Exception {
    File privFile = new File(PRIVATE_KEY_DIR, userId + ".key");
    File pubFile = new File(PUBLIC_KEY_DIR, userId + ".pub");
    File hashFile = new File(PRIVATE_KEY_DIR, userId + ".hash");

    if (privFile.exists() || hashFile.exists()) {
      return false;
    }

    System.out.println("Generating keys for '" + userId + "'...");

    KeyPair pair = CryptoUtils.generateRSAKeyPair();

    privFile.getParentFile().mkdirs();
    try (FileOutputStream fos = new FileOutputStream(privFile)) {
      fos.write(pair.getPrivate().getEncoded());
    }

    pubFile.getParentFile().mkdirs();
    try (FileOutputStream fos = new FileOutputStream(pubFile)) {
      fos.write(pair.getPublic().getEncoded());
    }

    String passwordHash = CryptoUtils.hashPassword(password);
    try (FileOutputStream fos = new FileOutputStream(hashFile)) {
      fos.write(passwordHash.getBytes());
    }

    return true;
  }

  public static void protect(String inputFile, String outputFile, String senderPrivPath,
      String senderId) throws Exception {
    Gson gson = new GsonBuilder().setPrettyPrinting().create();
    JsonObject rootJson;

    try (FileReader reader = new FileReader(inputFile)) {
      rootJson = gson.fromJson(reader, JsonObject.class);
    }

    JsonObject header = new JsonObject();
    header.addProperty("author_id", senderId);
    header.addProperty("timestamp", System.currentTimeMillis());
    header.addProperty("nonce", UUID.randomUUID().toString());

    String payloadJson = gson.toJson(rootJson);
    SecretKey sessionKey = CryptoUtils.generateAESKey();
    byte[] encryptedPayload = CryptoUtils.encrypt(sessionKey, payloadJson.getBytes());

    Map<String, PublicKey> destinationKeys = ServerMock.getClientPublicKeys();
    JsonObject recipientsObj = new JsonObject();

    for (Map.Entry<String, PublicKey> entry : destinationKeys.entrySet()) {
      String userId = entry.getKey();
      try {
        byte[] wrappedKey = CryptoUtils.wrapKey(entry.getValue(), sessionKey);
        recipientsObj.addProperty(userId, Base64.getEncoder().encodeToString(wrappedKey));
      } catch (Exception e) {
        System.err.println("Client Warning: Could not wrap key for " + userId);
      }
    }

    JsonObject envelope = new JsonObject();
    envelope.add("header", header);
    envelope.add("recipients", recipientsObj);
    envelope.addProperty("ciphertext", Base64.getEncoder().encodeToString(encryptedPayload));

    String dataToSign =
        header.toString() + recipientsObj.toString() + envelope.get("ciphertext").getAsString();

    PrivateKey senderKey = readPrivateKey(senderPrivPath);
    Signature rsa = Signature.getInstance("SHA256withRSA");
    rsa.initSign(senderKey);
    rsa.update(dataToSign.getBytes());

    envelope.addProperty("signature", Base64.getEncoder().encodeToString(rsa.sign()));

    System.out.println("Client: Submitting report to Server...");
    ServerMock.submitReport(envelope, outputFile);
  }

  public static void unprotect(String inputFile, String outputFile, String recipientPrivPath)
      throws Exception {
    try (FileReader reader = new FileReader(inputFile)) {
      Gson gson = new GsonBuilder().setPrettyPrinting().create();
      JsonObject envelope = gson.fromJson(reader, JsonObject.class);

      check(inputFile, null); // Perform check logic

      PrivateKey recipientKey = readPrivateKey(recipientPrivPath);
      SecretKey sessionKey = null;
      JsonObject recipients = envelope.getAsJsonObject("recipients");

      for (String userId : recipients.keySet()) {
        try {
          byte[] wrappedKey = Base64.getDecoder().decode(recipients.get(userId).getAsString());
          sessionKey = CryptoUtils.unwrapKey(recipientKey, wrappedKey);
          break;
        } catch (Exception e) {
        }
      }

      if (sessionKey == null) {
        throw new RuntimeException(
            "Decryption failed. You are not a valid recipient (or you are the Server).");
      }

      byte[] encryptedBytes = Base64.getDecoder().decode(envelope.get("ciphertext").getAsString());
      byte[] decryptedBytes = CryptoUtils.decrypt(sessionKey, encryptedBytes);

      String decryptedString = new String(decryptedBytes);
      JsonObject rootJson = gson.fromJson(decryptedString, JsonObject.class);

      try (FileWriter writer = new FileWriter(outputFile)) {
        gson.toJson(rootJson, writer);
      }
      System.out.println("Client: Document decrypted.");
    }
  }

  public static boolean check(String inputFile, String ignored) {
    try (FileReader reader = new FileReader(inputFile)) {
      Gson gson = new Gson();
      JsonObject envelope = gson.fromJson(reader, JsonObject.class);
      JsonObject header = envelope.getAsJsonObject("header");

      String authorId = header.get("author_id").getAsString();

      Map<String, PublicKey> keys = ServerMock.getClientPublicKeys();
      if (!keys.containsKey(authorId)) {
        System.err.println("Client Check: Unknown author " + authorId);
        return false;
      }
      PublicKey authorKey = keys.get(authorId);

      String dataToVerify = header.toString() + envelope.get("recipients").toString()
          + envelope.get("ciphertext").getAsString();

      Signature rsa = Signature.getInstance("SHA256withRSA");
      rsa.initVerify(authorKey);
      rsa.update(dataToVerify.getBytes());

      if (!rsa.verify(Base64.getDecoder().decode(envelope.get("signature").getAsString()))) {
        System.err.println("Client Check: Invalid Signature.");
        return false;
      }

      System.out.println("Client Check: Report integrity verified.");
      return true;
    } catch (Exception e) {
      System.err.println("Client Check Error: " + e.getMessage());
      return false;
    }
  }
}
