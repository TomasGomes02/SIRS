package sirs.t19;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;

import javax.crypto.spec.SecretKeySpec;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

public class SecureLibrary {

  // Default to 2 minutes if not specified
  public static final long DEFAULT_FRESHNESS_WINDOW = 120000;
  private static final String NONCE_FILE = ".history/nonce_history.txt";

  // --- Key Loading ---
  private static PrivateKey readPrivateKey(String keyPath) throws Exception {
    byte[] keyBytes = Files.readAllBytes(new File(keyPath).toPath());
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return kf.generatePrivate(spec);
  }

  private static PublicKey readPublicKey(String keyPath) throws Exception {
    byte[] keyBytes = Files.readAllBytes(new File(keyPath).toPath());
    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return kf.generatePublic(spec);
  }

  // --- Nonce Management ---
  private static boolean isNonceUsed(String nonce) {
    File file = new File(NONCE_FILE);
    if (!file.exists())
      return false;

    try (BufferedReader br = new BufferedReader(new FileReader(file))) {
      String line;
      while ((line = br.readLine()) != null) {
        if (line.trim().equals(nonce)) {
          return true;
        }
      }
    } catch (IOException e) {
      System.err.println("Warning: Could not read nonce file.");
    }
    return false;
  }

  private static void saveNonce(String nonce) {
    try (BufferedWriter bw = new BufferedWriter(new FileWriter(NONCE_FILE, true))) {
      bw.write(nonce);
      bw.newLine();
    } catch (IOException e) {
      System.err.println("Warning: Could not save nonce.");
    }
  }

  public static void protect(String inputFile, String outputFile, String privateKeyPath,
      String secretKeyPath) throws Exception {
    Gson gson = new GsonBuilder().setPrettyPrinting().create();
    JsonObject rootJson;
    try (FileReader reader = new FileReader(inputFile)) {
      rootJson = gson.fromJson(reader, JsonObject.class);
    }

    // Add Timestamp & Nonce
    rootJson.addProperty("timestamp", System.currentTimeMillis());
    String nonce = UUID.randomUUID().toString();
    rootJson.addProperty("nonce", nonce);

    // Sign
    JsonObject header = rootJson.get("header").getAsJsonObject();
    StringBuilder sb = new StringBuilder();
    sb.append(header.get("author").getAsString());
    sb.append(header.get("version").getAsInt());
    JsonArray tags = header.getAsJsonArray("tags");
    for (int i = 0; i < tags.size(); i++)
      sb.append(tags.get(i).getAsString());
    sb.append(header.get("title").getAsString());
    sb.append(rootJson.get("body").getAsString());
    sb.append(rootJson.get("status").getAsString());
    sb.append(rootJson.get("timestamp").getAsLong());
    sb.append(rootJson.get("nonce").getAsString());

    PrivateKey privKey = readPrivateKey(privateKeyPath);
    Signature rsa = Signature.getInstance("SHA256withRSA");
    rsa.initSign(privKey);
    rsa.update(sb.toString().getBytes());

    rootJson.addProperty("signature", Base64.getEncoder().encodeToString(rsa.sign()));

    // Encrypt
    SecretKeySpec secretKey = CryptoUtils.readSecretKey(secretKeyPath);
    String jsonString = gson.toJson(rootJson);
    byte[] encryptedBytes = CryptoUtils.encrypt(secretKey, jsonString.getBytes());

    JsonObject envelope = new JsonObject();
    envelope.addProperty("secureEnvelope", Base64.getEncoder().encodeToString(encryptedBytes));

    try (FileWriter writer = new FileWriter(outputFile)) {
      gson.toJson(envelope, writer);
    }
    System.out.println("Document protected (ID: " + nonce + ") and saved to " + outputFile);
  }

  public static boolean check(String inputFile) {
    // NEEDS TO BE CHANGED
    long validityWindow = 1L;
    String secretKeyPath = "";
    String publicKeyPath = "";

    try (FileReader reader = new FileReader(inputFile)) {
      Gson gson = new Gson();
      JsonObject envelope = gson.fromJson(reader, JsonObject.class);

      // Decrypt
      if (!envelope.has("secureEnvelope")) {
        System.err.println("Check Failed: Not a secure envelope.");
        return false;
      }
      byte[] encryptedBytes = Base64.getDecoder().decode(envelope.get("secureEnvelope").getAsString());
      SecretKeySpec secretKey = CryptoUtils.readSecretKey(secretKeyPath);
      byte[] decryptedBytes = CryptoUtils.decrypt(secretKey, encryptedBytes);

      String decryptedString = new String(decryptedBytes);
      JsonObject rootJson = gson.fromJson(decryptedString, JsonObject.class);

      // Check Freshness (User-defined Window)
      if (!rootJson.has("timestamp") || !rootJson.has("nonce")) {
        System.err.println("Check Failed: Missing timestamp or nonce.");
        return false;
      }
      long timestamp = rootJson.get("timestamp").getAsLong();
      long now = System.currentTimeMillis();

      if (now - timestamp > validityWindow) {
        System.err.println("Check Failed: Document expired. (Age: " + (now - timestamp) / 1000
            + "s, Limit: " + validityWindow / 1000 + "s)");
        return false;
      }
      if (timestamp > now) {
        System.err.println("Check Failed: Timestamp is in the future.");
        return false;
      }

      // Check Replay (Nonce)
      String nonce = rootJson.get("nonce").getAsString();
      if (isNonceUsed(nonce)) {
        System.err
            .println("Check Failed: Replay Attack detected! Nonce " + nonce + " already seen.");
        return false;
      }

      // Check Integrity
      JsonObject header = rootJson.get("header").getAsJsonObject();
      StringBuilder sb = new StringBuilder();
      sb.append(header.get("author").getAsString());
      sb.append(header.get("version").getAsInt());
      JsonArray tags = header.getAsJsonArray("tags");
      for (int i = 0; i < tags.size(); i++)
        sb.append(tags.get(i).getAsString());
      sb.append(header.get("title").getAsString());
      sb.append(rootJson.get("body").getAsString());
      sb.append(rootJson.get("status").getAsString());
      sb.append(rootJson.get("timestamp").getAsLong());
      sb.append(rootJson.get("nonce").getAsString());

      PublicKey pubKey = readPublicKey(publicKeyPath);
      Signature rsa = Signature.getInstance("SHA256withRSA");
      rsa.initVerify(pubKey);
      rsa.update(sb.toString().getBytes());

      if (!rsa.verify(Base64.getDecoder().decode(rootJson.get("signature").getAsString()))) {
        System.err.println("Check Failed: Invalid Signature.");
        return false;
      }

      // Save Nonce
      saveNonce(nonce);

      System.out.println("Check Passed: Document is Fresh, Authentic, and Untampered.");
      return true;

    } catch (Exception e) {
      System.err.println("Check Failed: " + e.getMessage());
      return false;
    }
  }

  public static void unprotect(String inputFile, String outputFile, String secretKeyPath, String privateKeyPath)
      throws Exception {
    try (FileReader reader = new FileReader(inputFile)) {
      Gson gson = new GsonBuilder().setPrettyPrinting().create();
      JsonObject envelope = gson.fromJson(reader, JsonObject.class);

      if (!envelope.has("secureEnvelope")) {
        throw new RuntimeException("File does not contain a secureEnvelope");
      }

      // Decrypt
      byte[] encryptedBytes = Base64.getDecoder().decode(envelope.get("secureEnvelope").getAsString());
      SecretKeySpec secretKey = CryptoUtils.readSecretKey(secretKeyPath);
      byte[] decryptedBytes = CryptoUtils.decrypt(secretKey, encryptedBytes);

      String decryptedString = new String(decryptedBytes);
      JsonObject rootJson = gson.fromJson(decryptedString, JsonObject.class);

      try (FileWriter writer = new FileWriter(outputFile)) {
        gson.toJson(rootJson, writer);
      }
      System.out.println("Document unprotected and saved to " + outputFile);
    }
  }
}
