package sirs.t19;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
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
import java.security.cert.CertificateFactory;
import java.security.cert.Certificate;
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
  private static final String SERVER_HOST =
      System.getenv("CIVIC_SERVER_HOST") != null ? System.getenv("CIVIC_SERVER_HOST") : "localhost";
  private static final int SERVER_PORT = 8443;

  static {
    try {
      InputStream caInput = SecureLibrary.class.getClassLoader().getResourceAsStream("db-ca.pem");
      
      if (caInput != null) {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate dbCaCert = cf.generateCertificate(caInput);
        
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        trustStore.setCertificateEntry("db-ca", dbCaCert);
        
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), null);
        SSLContext.setDefault(sslContext);
        
        System.out.println("Client: DB CA loaded, will verify App VM certificate");
      } else {
        System.err.println("ERROR: db-ca.pem not found in classpath!");
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  // --- MANUAL COMMANDS (File Based) ---

  /**
   * Encrypts a local file and saves the envelope to an output file. This corresponds to the
   * 'protect <infile> <outfile>' command.
   */
  public static void protect(String inputFile, String outputFile, String userId) throws Exception {
    // 1. Read Input File
    Gson gson = new GsonBuilder().disableHtmlEscaping().create();
    JsonObject reportData;
    try (FileReader reader = new FileReader(inputFile)) {
      reportData = gson.fromJson(reader, JsonObject.class);
    }

    // 2. Build Envelope (Reusing the core logic logic)
    JsonObject envelope = createProtectedEnvelope(reportData, userId);

    // 3. Save to Output File
    try (FileWriter w = new FileWriter(outputFile)) {
      gson.toJson(envelope, w);
    }
    System.out.println("File protected and saved to: " + outputFile);
  }

  /**
   * Decrypts a local envelope file and saves the plaintext to an output file. This corresponds to
   * the 'unprotect <infile> <outfile>' command.
   */
  public static void unprotect(String inputFile, String outputFile, String userId)
      throws Exception {
    // 1. Read Envelope File
    Gson gson = new GsonBuilder().setPrettyPrinting().create();
    JsonObject envelope;
    try (FileReader reader = new FileReader(inputFile)) {
      envelope = gson.fromJson(reader, JsonObject.class);
    }

    // 2. Decrypt (Reusing core logic)
    JsonObject payload = decryptEnvelope(envelope, userId);

    // 3. Save to Output File
    try (FileWriter w = new FileWriter(outputFile)) {
      gson.toJson(payload, w);
    }
    System.out.println("File unprotected and saved to: " + outputFile);
  }

  /**
   * Checks the signature of a local envelope file. This corresponds to the 'check <infile>'
   * command.
   */
  public static boolean check(String inputFile) {
    try (FileReader reader = new FileReader(inputFile)) {
      Gson gson = new Gson();
      JsonObject envelope = gson.fromJson(reader, JsonObject.class);
      return checkEnvelopeInMemory(envelope);
    } catch (Exception e) {
      System.err.println("Check failed: " + e.getMessage());
      return false;
    }
  }

  // --- AUTOMATED FLOW (Report Command) ---

  public static void protectAndSubmit(JsonObject reportData, String userId) throws Exception {
    JsonObject envelope = createProtectedEnvelope(reportData, userId);

    // Wrap in root object for server submission
    JsonObject root = new JsonObject();
    root.add(reportData.get("report_id").getAsString(), envelope);

    System.out.println("Client: Submitting protected report...");
    String response = sendNetworkCommand("SUBMIT " + new Gson().toJson(root));
    if (!response.startsWith("OK"))
      throw new Exception("Submission failed: " + response);

    System.out.println("Success! Server Response: " + response);
  }

  public static boolean checkRemote(String reportId) {
    try {
      String jsonResp = sendNetworkCommand("GET_REPORT " + reportId);
      if (jsonResp.startsWith("ERROR")) {
        System.err.println("Report not found on server.");
        return false;
      }
      JsonObject envelope = new Gson().fromJson(jsonResp, JsonObject.class);
      return checkEnvelopeInMemory(envelope);
    } catch (Exception e) {
      System.err.println("Check failed: " + e.getMessage());
      return false;
    }
  }

  // --- CORE LOGIC (Shared) ---

  private static JsonObject createProtectedEnvelope(JsonObject reportData, String userId)
      throws Exception {
    // Get Nonce from Server
    long nonce = getNextNonce(userId);

    // Prepare Metadata
    JsonObject metadata = new JsonObject();
    metadata.addProperty("author_id", userId);
    metadata.addProperty("nonce", nonce);
    metadata.addProperty("status", "WAITING");

    // Encrypt Payload
    SecretKey sessionKey = CryptoUtils.generateAESKey();
    byte[] encryptedBytes =
        CryptoUtils.encrypt(sessionKey, new Gson().toJson(reportData).getBytes());
    String cipherTextB64 = Base64.getEncoder().encodeToString(encryptedBytes);

    // Handle Recipients (Add Self)
    JsonObject recipients = new JsonObject();
    PublicKey myKey = getPublicKeyFromServer(userId);
    if (myKey == null)
      throw new Exception("Error: Your public key is not registered on the server.");
    recipients.addProperty(userId,
        Base64.getEncoder().encodeToString(CryptoUtils.wrapKey(myKey, sessionKey)));

    // Build Envelope
    JsonObject envelope = new JsonObject();
    envelope.add("metadata", metadata);
    envelope.add("recipients", recipients);
    envelope.addProperty("ciphertext", cipherTextB64);

    // Sign
    String dataToSign = metadata.toString() + recipients.toString() + cipherTextB64;
    Signature rsa = Signature.getInstance("SHA256withRSA");
    rsa.initSign(loadLocalPrivateKey(userId));
    rsa.update(dataToSign.getBytes());
    envelope.addProperty("signature", Base64.getEncoder().encodeToString(rsa.sign()));

    return envelope;
  }

  private static JsonObject decryptEnvelope(JsonObject envelope, String userId) throws Exception {
    if (!envelope.has("recipients") || !envelope.has("ciphertext"))
      throw new Exception("Invalid envelope format");

    JsonObject recipients = envelope.getAsJsonObject("recipients");
    if (!recipients.has(userId))
      throw new Exception("Access Denied: You are not a recipient.");

    PrivateKey myPrivKey = loadLocalPrivateKey(userId);
    byte[] wrappedKey = Base64.getDecoder().decode(recipients.get(userId).getAsString());
    SecretKey sessionKey = CryptoUtils.unwrapKey(myPrivKey, wrappedKey);

    String cipherTextB64 = envelope.get("ciphertext").getAsString();
    byte[] decryptedBytes =
        CryptoUtils.decrypt(sessionKey, Base64.getDecoder().decode(cipherTextB64));

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

      boolean valid =
          rsa.verify(Base64.getDecoder().decode(envelope.get("signature").getAsString()));
      if (valid)
        System.out.println("Integrity Check: VALID (Signed by " + authorId + ")");
      else
        System.err.println("Integrity Check: INVALID SIGNATURE");

      return valid;
    } catch (Exception e) {
      System.err.println("Integrity Check Logic Error: " + e.getMessage());
      return false;
    }
  }

  // --- MUNICIPALITY & NETWORK UTILS (Same as before) ---

  public static List<String> getPendingReports(String userId) throws Exception {
    String resp = sendNetworkCommand("GET_PENDING_REPORTS " + userId);
    if (resp.startsWith("ERROR") || resp.isEmpty())
      return Collections.emptyList();
    return Arrays.asList(resp.split(","));
  }

  public static JsonObject fetchAndDecryptReport(String reportId, String userId) throws Exception {
    String jsonResp = sendNetworkCommand("GET_REPORT " + reportId);
    if (jsonResp.startsWith("ERROR"))
      throw new Exception(jsonResp);

    Gson gson = new Gson();
    JsonObject envelope = gson.fromJson(jsonResp, JsonObject.class);

    if (!checkEnvelopeInMemory(envelope))
      throw new Exception("Integrity Check Failed for " + reportId);

    return decryptEnvelope(envelope, userId);
  }

  public static void submitDecision(String reportId, String decision, String userId)
      throws IOException {
    String cmd = String.format("UPDATE_STATUS %s %s %s", reportId, decision, userId);
    String resp = sendNetworkCommand(cmd);
    if (!resp.startsWith("OK"))
      throw new RuntimeException("Server Error: " + resp);
  }

  // --- AUTH & KEY UTILS ---

  public static String registerUser(String username, String password, String role)
      throws Exception {
    // 1. Generate KeyPair
    KeyPair pair = CryptoUtils.generateRSAKeyPair();
    String pubKeyB64 = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());

    // 2. Send Info to Server
    // Protocol: REGISTER <username> <password> <role> <pubkey>
    String cmd = String.format("REGISTER %s %s %s %s", username, password, role, pubKeyB64);

    String response = sendNetworkCommand(cmd);

    // 3. Process Response
    if (response.startsWith("ERROR")) {
      throw new Exception("Registration Failed: " + response);
    }

    // Server returns the new MongoDB ObjectId
    String newUserId = response.trim();

    // 4. Save Private Key Locally using the Server-Provided ID
    saveLocalPrivateKey(newUserId, pair.getPrivate());

    return newUserId;
  }

  public static String loginUser(String username, String password) throws Exception {
    String resp = sendNetworkCommand("LOGIN " + username + " " + password);
    if (resp.startsWith("ERROR"))
      return null;
    return resp.trim();
  }

  public static String getUserRole(String userId) throws IOException {
    String resp = sendNetworkCommand("GET_ROLE " + userId);
    if (resp.startsWith("ERROR"))
      return "citizen";
    return resp.trim();
  }

  private static PublicKey getPublicKeyFromServer(String userId) throws Exception {
    String resp = sendNetworkCommand("GET_PUBKEY " + userId);
    if (resp.startsWith("ERROR"))
      return null;
    byte[] keyBytes = Base64.getDecoder().decode(resp);
    return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyBytes));
  }

  private static long getNextNonce(String userId) throws IOException {
    String resp = sendNetworkCommand("GET_NONCE " + userId);
    try {
      return Long.parseLong(resp.trim());
    } catch (Exception e) {
      return System.currentTimeMillis();
    }
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
}
