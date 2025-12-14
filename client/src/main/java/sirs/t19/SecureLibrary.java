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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
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

  // -- IPs Config --
  private static final String APP_HOST = System.getenv("APP_HOST") != null ? System.getenv("APP_HOST") : "localhost";

  private static final String AUTH_HOST = System.getenv("AUTH_HOST") != null ? System.getenv("AUTH_HOST") : "localhost";

  private static final int APP_PORT = 8443;
  private static final int AUTH_PORT = 8444;
  static {
    try {
      InputStream trustInput = SecureLibrary.class.getClassLoader().getResourceAsStream("client_truststore.jks");
      if (trustInput != null) {
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(trustInput, "changeit".toCharArray());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), null);
        SSLContext.setDefault(sslContext);
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  // --- AUTOMATED FLOW ---

  /**
   * Encrypts, Signs, Submits to App Server, then Refreshes Token with Auth
   * Server. Returns the NEW
   * Token.
   */
  public static String protectAndSubmit(JsonObject reportData, String userId, String currentToken)
      throws Exception {

    // 1. Get Nonce (App Server)
    long nonce = getNextNonce(userId);

    // 2. Crypto (Create Envelope)
    JsonObject envelope = createProtectedEnvelope(reportData, userId, nonce);

    // 3. Wrap in root
    JsonObject root = new JsonObject();
    root.add(reportData.get("report_id").getAsString(), envelope);

    // 4. Submit to APP SERVER with TOKEN
    // Protocol: SUBMIT <json_data> <token>
    System.out.println("Client: Submitting to App Server...");
    String cmd = "SUBMIT " + new Gson().toJson(root) + " " + currentToken;
    String response = sendAppCommand(cmd);

    if (!response.startsWith("OK"))
      throw new Exception("Submission failed: " + response);
    System.out.println("App Server Accepted Report.");

    // 5. Request New Token from AUTH SERVER
    System.out.println("Client: Requesting new token from Auth Server...");
    String authResponse = sendAuthCommand("REQUEST " + userId);

    if (authResponse.startsWith("ERROR"))
      throw new Exception("Token Refresh Failed: " + authResponse);

    // Parse response "TOKEN COUNT"
    String[] parts = authResponse.trim().split(" ");
    if (parts.length < 2)
      throw new Exception("Invalid Auth Response: " + authResponse);

    String newToken = parts[0];
    String count = parts[1];

    System.out.println("Client: Token refreshed. You have " + count + " tokens remaining.");
    return newToken;
  }

  // --- AUTH UTILS ---

  // Returns String[] { userId, token }
  public static String[] registerUser(String username, String password, String role)
      throws Exception {
    KeyPair pair = CryptoUtils.generateRSAKeyPair();
    String pubKeyB64 = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());

    // Protocol: REGISTER <user> <pass> <role> <pubkey>
    String cmd = String.format("REGISTER %s %s %s %s", username, password, role, pubKeyB64);
    String response = sendAuthCommand(cmd);

    if (response.startsWith("ERROR"))
      throw new Exception("Registration Failed: " + response);

    // Expects: "UUID TOKEN"
    String[] parts = response.trim().split(" ");
    String userId = parts[0];
    String token = parts[1];

    saveLocalPrivateKey(userId, pair.getPrivate());
    return new String[] { userId, token };
  }

  // Returns String[] { userId, token } or null
  public static String[] loginUser(String username, String password) throws Exception {
    String resp = sendAuthCommand("LOGIN " + username + " " + password);
    if (resp.startsWith("ERROR"))
      return null;

    // Expects: "UUID TOKEN"
    String[] parts = resp.trim().split(" ");
    return new String[] { parts[0], parts[1] };
  }

  // --- SERVER COMMANDS (Routing) ---

  public static String getUserRole(String userId) throws IOException {
    String resp = sendAppCommand("GET_ROLE " + userId);
    return resp.startsWith("ERROR") ? "citizen" : resp.trim();
  }

  public static List<String> getPendingReports(String userId) throws Exception {
    String resp = sendAppCommand("GET_PENDING_REPORTS " + userId);
    if (resp.startsWith("ERROR") || resp.isEmpty())
      return Collections.emptyList();
    return Arrays.asList(resp.split(","));
  }

  public static JsonObject fetchAndDecryptReport(String reportId, String userId) throws Exception {
    String jsonResp = sendAppCommand("GET_REPORT " + reportId + " " + userId);
    if (jsonResp.startsWith("ERROR"))
      throw new Exception(jsonResp);

    JsonObject envelope = new Gson().fromJson(jsonResp, JsonObject.class);
    if (!checkEnvelopeInMemory(envelope))
      throw new Exception("Integrity Check Failed");
    return decryptEnvelope(envelope, userId);
  }

  public static void submitDecision(String reportId, String decision, String userId)
      throws IOException {
    String resp = sendAppCommand(String.format("UPDATE_STATUS %s %s %s", reportId, decision, userId));
    if (!resp.startsWith("OK"))
      throw new RuntimeException(resp);
  }

  public static boolean checkRemote(String reportId, String userId) {
    try {
      String jsonResp = sendAppCommand("GET_REPORT " + reportId + " " + userId);
      if (jsonResp.startsWith("ERROR")) {
        System.err.println("Report not found or access denied on server.");
        return false;
      }
      JsonObject envelope = new Gson().fromJson(jsonResp, JsonObject.class);
      return checkEnvelopeInMemory(envelope);
    } catch (Exception e) {
      System.err.println("Check failed: " + e.getMessage());
      return false;
    }
  }

  // --- HELPERS ---

  private static long getNextNonce(String userId) throws IOException {
    // Nonce is a counter in DB, represented as long here
    String resp = sendAppCommand("GET_NONCE " + userId);
    try {
      return Long.parseLong(resp.trim());
    } catch (Exception e) {
      return -1;
    }
  }

  private static PublicKey getPublicKeyFromServer(String userId) throws Exception {
    String resp = sendAppCommand("GET_PUBKEY " + userId);
    if (resp.startsWith("ERROR"))
      return null;
    return KeyFactory.getInstance("RSA")
        .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(resp)));
  }

  // --- NETWORK ROUTING ---

  private static String sendAuthCommand(String cmd) throws IOException {
    return sendNetworkCommand(AUTH_HOST, AUTH_PORT, cmd);
  }

  private static String sendAppCommand(String cmd) throws IOException {
    return sendNetworkCommand(APP_HOST, APP_PORT, cmd);
  }

  private static String sendNetworkCommand(String host, int port, String cmd) throws IOException {
    SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
    try (SSLSocket socket = (SSLSocket) sf.createSocket(host, port);
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
      socket.startHandshake();
      out.println(cmd);
      return in.readLine();
    }
  }

  // --- CRYPTO LOGIC ---

  private static JsonObject createProtectedEnvelope(JsonObject reportData, String userId,
      long nonce) throws Exception {
    JsonObject metadata = new JsonObject();
    metadata.addProperty("author_id", userId);
    metadata.addProperty("nonce", nonce);
    metadata.addProperty("status", "WAITING");

    SecretKey sessionKey = CryptoUtils.generateAESKey();
    byte[] encryptedBytes = CryptoUtils.encrypt(sessionKey, new Gson().toJson(reportData).getBytes());

    JsonObject recipients = new JsonObject();
    PublicKey myKey = getPublicKeyFromServer(userId);
    recipients.addProperty(userId,
        Base64.getEncoder().encodeToString(CryptoUtils.wrapKey(myKey, sessionKey)));

    JsonObject envelope = new JsonObject();
    envelope.add("metadata", metadata);
    envelope.add("recipients", recipients);
    envelope.addProperty("ciphertext", Base64.getEncoder().encodeToString(encryptedBytes));

    String dataToSign = metadata.toString() + recipients.toString() + envelope.get("ciphertext").getAsString();
    Signature rsa = Signature.getInstance("SHA256withRSA");
    rsa.initSign(loadLocalPrivateKey(userId));
    rsa.update(dataToSign.getBytes());
    envelope.addProperty("signature", Base64.getEncoder().encodeToString(rsa.sign()));

    return envelope;
  }

  private static PrivateKey loadLocalPrivateKey(String id) throws Exception {
    byte[] bytes = Files.readAllBytes(new File(PRIVATE_KEY_DIR + "/" + id + ".key").toPath());
    return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(bytes));
  }

  private static void saveLocalPrivateKey(String id, PrivateKey key) throws IOException {
    new File(PRIVATE_KEY_DIR).mkdirs();
    try (FileOutputStream fos = new FileOutputStream(PRIVATE_KEY_DIR + "/" + id + ".key")) {
      fos.write(key.getEncoded());
    }
  }

  private static JsonObject decryptEnvelope(JsonObject envelope, String userId) throws Exception {
    if (!envelope.has("recipients") || !envelope.has("ciphertext"))
      throw new Exception("Invalid envelope format");
    JsonObject recipients = envelope.getAsJsonObject("recipients");
    if (!recipients.has(userId))
      throw new Exception("Access Denied");
    PrivateKey myPrivKey = loadLocalPrivateKey(userId);
    byte[] wrappedKey = Base64.getDecoder().decode(recipients.get(userId).getAsString());
    SecretKey sessionKey = CryptoUtils.unwrapKey(myPrivKey, wrappedKey);
    String cipherTextB64 = envelope.get("ciphertext").getAsString();
    byte[] decryptedBytes = CryptoUtils.decrypt(sessionKey, Base64.getDecoder().decode(cipherTextB64));
    return new Gson().fromJson(new String(decryptedBytes), JsonObject.class);
  }

  private static boolean checkEnvelopeInMemory(JsonObject envelope) {
    try {
      JsonObject metadata = envelope.getAsJsonObject("metadata");
      String authorId = metadata.get("author_id").getAsString();
      PublicKey authorKey = getPublicKeyFromServer(authorId);
      if (authorKey == null)
        return false;
      String dataToVerify = metadata.toString() + envelope.get("recipients").toString()
          + envelope.get("ciphertext").getAsString();
      Signature rsa = Signature.getInstance("SHA256withRSA");
      rsa.initVerify(authorKey);
      rsa.update(dataToVerify.getBytes());
      boolean valid = rsa.verify(Base64.getDecoder().decode(envelope.get("signature").getAsString()));

      if (valid)
        System.out.println("Integrity Check: VALID (Signed by " + authorId + ")");
      else
        System.err.println("Integrity Check: INVALID");
      return valid;
    } catch (Exception e) {
      return false;
    }
  }

  // --- MANUAL COMMANDS (Updated to use Network for Crypto Data) ---

  public static void protect(String inputFile, String outputFile, String userId) throws Exception {
    // 1. Read Input File
    Gson gson = new GsonBuilder().disableHtmlEscaping().create();
    JsonObject reportData;
    try (FileReader reader = new FileReader(inputFile)) {
      reportData = gson.fromJson(reader, JsonObject.class);
    }

    // 2. Build Envelope (Uses getNextNonce from Network)
    long nonce = getNextNonce(userId);
    JsonObject envelope = createProtectedEnvelope(reportData, userId, nonce);

    // 3. Save to Output File
    try (FileWriter w = new FileWriter(outputFile)) {
      gson.toJson(envelope, w);
    }
    System.out.println("File protected and saved to: " + outputFile);
  }

  public static void unprotect(String inputFile, String outputFile, String userId)
      throws Exception {
    Gson gson = new GsonBuilder().setPrettyPrinting().create();
    JsonObject envelope;
    try (FileReader reader = new FileReader(inputFile)) {
      envelope = gson.fromJson(reader, JsonObject.class);
    }

    // Uses Network to fetch public key for check, then local private key to decrypt
    if (!checkEnvelopeInMemory(envelope))
      throw new Exception("Integrity Check Failed");
    JsonObject payload = decryptEnvelope(envelope, userId);

    try (FileWriter w = new FileWriter(outputFile)) {
      gson.toJson(payload, w);
    }
    System.out.println("File unprotected and saved to: " + outputFile);
  }

  public static boolean check(String inputFile) {
    try (FileReader reader = new FileReader(inputFile)) {
      Gson gson = new Gson();
      JsonObject envelope = gson.fromJson(reader, JsonObject.class);
      // Uses Network to fetch author's public key
      return checkEnvelopeInMemory(envelope);
    } catch (Exception e) {
      System.err.println("Check failed: " + e.getMessage());
      return false;
    }
  }
}
