package sirs.t19;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Properties;
import java.util.UUID;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;

public class SecureLibrary {

  private static final String PRIVATE_KEY_DIR = "keys";
  private static final String PUB_KEY_DIR = "keys/public_keys";

  // Read Host from ENV to support Docker/VMs, default to localhost
  private static final String SERVER_HOST =
      System.getenv("CIVIC_SERVER_HOST") != null ? System.getenv("CIVIC_SERVER_HOST") : "localhost";
  private static final int SERVER_PORT = 8443;

  // --- TLS Configuration (Same as before) ---
  static {
    try {
      InputStream trustInput =
          SecureLibrary.class.getClassLoader().getResourceAsStream("client_truststore.jks");
      if (trustInput != null) {
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(trustInput, "clientpass".toCharArray());
        TrustManagerFactory tmf =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), null);
        SSLContext.setDefault(sslContext);
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  // --- Core Functions: Protect, Unprotect & Check ---

  public static void protect(String inputFile, String outputFile, String userId) throws Exception {
    Gson gson = new GsonBuilder().disableHtmlEscaping().create();
    JsonObject rootJson;
    try (FileReader reader = new FileReader(inputFile)) {
      rootJson = gson.fromJson(reader, JsonObject.class);
    }

    // Metadata & Nonce
    long nonce = getNextNonce(userId);
    JsonObject metadata = new JsonObject();
    metadata.addProperty("author_id", userId);
    metadata.addProperty("nonce", nonce);

    byte[] metaHash = MessageDigest.getInstance("SHA-256").digest(gson.toJson(metadata).getBytes());
    rootJson.addProperty("metadataHash", Base64.getEncoder().encodeToString(metaHash));

    // Encrypt
    javax.crypto.SecretKey sessionKey = CryptoUtils.generateAESKey();
    byte[] encryptedData = CryptoUtils.encrypt(sessionKey, gson.toJson(rootJson).getBytes());

    // Recipients (Self + Server/Others)
    JsonObject recipients = new JsonObject();
    // Add Self
    PublicKey myKey = loadPublicKey(userId);
    if (myKey != null) {
      recipients.addProperty(userId,
          Base64.getEncoder().encodeToString(CryptoUtils.wrapKey(myKey, sessionKey)));
    }

    // Build Envelope
    JsonObject envelope = new JsonObject();
    envelope.add("metadata", metadata);
    envelope.add("recipients", recipients);
    envelope.addProperty("ciphertext", Base64.getEncoder().encodeToString(encryptedData));

    // Sign
    String data =
        metadata.toString() + recipients.toString() + envelope.get("ciphertext").getAsString();
    Signature rsa = Signature.getInstance("SHA256withRSA");
    rsa.initSign(loadPrivateKey(userId));
    rsa.update(data.getBytes());
    envelope.addProperty("signature", Base64.getEncoder().encodeToString(rsa.sign()));

    // Send
    System.out.println("Client: Sending to Secure Server...");
    String response = sendNetworkCommand("SUBMIT " + gson.toJson(envelope));
    System.out.println("Server Response: " + response);

    // Also save locally for verification
    try (FileWriter w = new FileWriter(outputFile)) {
      gson.toJson(envelope, w);
    }
  }

  /**
   * Unprotects (Decrypts) a report. 1. Reads the Envelope. 2. Looks for the current User's ID in
   * the 'recipients' list. 3. Uses User's Private Key to unwrap (decrypt) the AES Session Key. 4.
   * Uses the Session Key to decrypt the report content.
   */
  public static void unprotect(String inputFile, String outputFile, String userId)
      throws Exception {
    try (FileReader reader = new FileReader(inputFile)) {
      Gson gson = new GsonBuilder().setPrettyPrinting().create();
      JsonObject envelope = gson.fromJson(reader, JsonObject.class);

      // 1. Verify Structure
      if (!envelope.has("recipients") || !envelope.has("ciphertext")) {
        throw new RuntimeException("Invalid document format: Missing recipients or ciphertext.");
      }

      // 2. Load User's Private Key
      PrivateKey recipientKey = loadPrivateKey(userId);

      // 3. Unwrap Session Key (Hybrid Decryption)
      SecretKey sessionKey = null;
      JsonObject recipients = envelope.getAsJsonObject("recipients");

      if (recipients.has(userId)) {
        String wrappedKeyB64 = recipients.get(userId).getAsString();
        byte[] wrappedKey = Base64.getDecoder().decode(wrappedKeyB64);
        // Decrypt the AES key using RSA
        sessionKey = CryptoUtils.unwrapKey(recipientKey, wrappedKey);
      } else {
        throw new RuntimeException(
            "Access Denied: User '" + userId + "' is not in the recipient list.");
      }

      // 4. Decrypt Payload
      String cipherTextB64 = envelope.get("ciphertext").getAsString();
      byte[] encryptedBytes = Base64.getDecoder().decode(cipherTextB64);
      byte[] decryptedBytes = CryptoUtils.decrypt(sessionKey, encryptedBytes);

      String decryptedString = new String(decryptedBytes);
      JsonObject rootJson = gson.fromJson(decryptedString, JsonObject.class);

      // 5. Save Decrypted File
      try (FileWriter writer = new FileWriter(outputFile)) {
        gson.toJson(rootJson, writer);
      }
      System.out.println("Document decrypted successfully to: " + outputFile);
    }
  }

  /**
   * Checks the Integrity and Authenticity of a report locally. 1. Reads the Envelope. 2. Extracts
   * the Author ID from metadata. 3. Loads the Author's Public Key. 4. Verifies the RSA Signature
   * over (Metadata + Recipients + Ciphertext).
   */
  public static boolean check(String inputFile) {
    try (FileReader reader = new FileReader(inputFile)) {
      Gson gson = new Gson();
      JsonObject envelope = gson.fromJson(reader, JsonObject.class);

      // 1. Extract Metadata
      if (!envelope.has("metadata") || !envelope.has("signature")) {
        System.err.println("Check Failed: Missing metadata or signature.");
        return false;
      }
      JsonObject metadata = envelope.getAsJsonObject("metadata");
      String authorId = metadata.get("author_id").getAsString();

      // 2. Get Author's Public Key
      PublicKey authorKey = loadPublicKey(authorId);
      if (authorKey == null) {
        System.err
            .println("Check Failed: Public key for author '" + authorId + "' not found locally.");
        return false;
      }

      // 3. Reconstruct Signed Data
      String recipientsStr = envelope.get("recipients").toString();
      String ciphertext = envelope.get("ciphertext").getAsString();
      String dataToVerify = metadata.toString() + recipientsStr + ciphertext;

      // 4. Verify Signature
      Signature rsa = Signature.getInstance("SHA256withRSA");
      rsa.initVerify(authorKey);
      rsa.update(dataToVerify.getBytes());

      String signatureB64 = envelope.get("signature").getAsString();
      if (!rsa.verify(Base64.getDecoder().decode(signatureB64))) {
        System.err
            .println("Check Failed: Invalid Signature (Document may have been tampered with).");
        return false;
      }

      System.out.println("Check Passed: Document is authentic. Author: " + authorId);
      return true;

    } catch (Exception e) {
      System.err.println("Check Error: " + e.getMessage());
      return false;
    }
  }

  // --- Auth (Register, Login) ---

  public static String registerUser(String username, String password, String role)
      throws Exception {
    Properties map = loadUserMap();
    if (map.containsKey(username))
      return null;

    String userId = UUID.randomUUID().toString();
    KeyPair pair = CryptoUtils.generateRSAKeyPair();

    saveKey(userId, pair.getPrivate());
    savePublicKey(userId, pair.getPublic());
    saveHash(userId, password);

    map.setProperty(username, userId);
    saveUserMap(map);

    String pubKey = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
    String resp = sendNetworkCommand("REGISTER " + userId + " " + pubKey + " " + role);

    if (!"OK".equals(resp))
      throw new Exception("Server Registration Failed: " + resp);
    return userId;
  }

  public static boolean loginUser(String username, String password) throws Exception {
    Properties map = loadUserMap();
    String userId = map.getProperty(username);
    if (userId == null)
      return false;

    File hashFile = new File(PRIVATE_KEY_DIR, userId + ".hash");
    if (!hashFile.exists())
      return false;

    String stored = new String(Files.readAllBytes(hashFile.toPath()));
    return stored.equals(CryptoUtils.hashPassword(password));
  }

  private static String sendNetworkCommand(String cmd) throws IOException {
    SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
    try (SSLSocket socket = (SSLSocket) sf.createSocket(SERVER_HOST, SERVER_PORT);
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
      socket.startHandshake();
      out.println(cmd);
      return in.readLine();
    }
  }

  // --- File Utils ---
  // TODO: Needs to be changed to query the database instead of using files

  private static PrivateKey loadPrivateKey(String id) throws Exception {
    byte[] bytes = Files.readAllBytes(new File(PRIVATE_KEY_DIR + "/" + id + ".key").toPath());
    return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(bytes));
  }

  private static PublicKey loadPublicKey(String id) throws Exception {
    File f = new File(PUB_KEY_DIR, id + ".pub");
    if (!f.exists())
      return null;
    byte[] bytes = Files.readAllBytes(f.toPath());
    return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes));
  }

  private static void saveKey(String id, PrivateKey key) throws IOException {
    new File(PRIVATE_KEY_DIR).mkdirs();
    try (FileOutputStream fos = new FileOutputStream(PRIVATE_KEY_DIR + "/" + id + ".key")) {
      fos.write(key.getEncoded());
    }
  }

  private static void savePublicKey(String id, PublicKey key) throws IOException {
    new File(PUB_KEY_DIR).mkdirs();
    try (FileOutputStream fos = new FileOutputStream(PUB_KEY_DIR + "/" + id + ".pub")) {
      fos.write(key.getEncoded());
    }
  }

  private static void saveHash(String id, String pass) throws Exception {
    try (FileOutputStream fos = new FileOutputStream(PRIVATE_KEY_DIR + "/" + id + ".hash")) {
      fos.write(CryptoUtils.hashPassword(pass).getBytes());
    }
  }

  private static Properties loadUserMap() throws IOException {
    Properties p = new Properties();
    File f = new File("client/user_map.properties");
    if (f.exists())
      try (FileReader r = new FileReader(f)) {
        p.load(r);
      }
    return p;
  }

  private static void saveUserMap(Properties p) throws IOException {
    new File("client").mkdirs();
    try (FileWriter w = new FileWriter("client/user_map.properties")) {
      p.store(w, null);
    }
  }

  private static long getNextNonce(String id) {
    return System.currentTimeMillis();
  }
}
