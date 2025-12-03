package sirs.t19;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

public class ServerMock {

  private static final String KEYS_DIR = "client/keys/public_keys";
  private static final String NONCE_DB = ".history/server_nonce_db.txt";
  public static final long SERVER_TOLERANCE_WINDOW = 120000; // 2 minutes

  public static Map<String, PublicKey> getClientPublicKeys() throws Exception {
    Map<String, PublicKey> keyMap = new HashMap<>();
    File folder = new File(KEYS_DIR);

    if (!folder.exists())
      return keyMap;

    try (Stream<Path> paths = Files.walk(Paths.get(KEYS_DIR))) {
      paths.filter(Files::isRegularFile).forEach(path -> {
        try {
          String fileName = path.getFileName().toString();
          String userId =
              fileName.contains(".") ? fileName.substring(0, fileName.lastIndexOf('.')) : fileName;
          keyMap.put(userId, loadPublicKey(path));
        } catch (Exception e) {
          System.err.println("Server: Skipped invalid key " + path);
        }
      });
    }
    return keyMap;
  }

  public static void submitReport(JsonObject envelope, String savePath) throws Exception {
    if (!envelope.has("metadata") || !envelope.has("signature") || !envelope.has("ciphertext")) {
      throw new SecurityException("Server Rejected: Invalid JSON format.");
    }

    JsonObject metadata = envelope.getAsJsonObject("metadata");
    String authorId = metadata.get("author_id").getAsString();
    long timestamp = metadata.get("timestamp").getAsLong();
    String nonce = metadata.get("nonce").getAsString();

    PublicKey authorKey = getUserPublicKey(authorId);

    String recipientsStr = envelope.get("recipients").toString();
    String ciphertext = envelope.get("ciphertext").getAsString();
    String dataToVerify = metadata.toString() + recipientsStr + ciphertext;

    Signature rsa = Signature.getInstance("SHA256withRSA");
    rsa.initVerify(authorKey);
    rsa.update(dataToVerify.getBytes());

    if (!rsa.verify(Base64.getDecoder().decode(envelope.get("signature").getAsString()))) {
      throw new SecurityException(
          "Server Rejected: Invalid Signature (Tampering or Impersonation detected).");
    }

    long now = System.currentTimeMillis();
    if (Math.abs(now - timestamp) > SERVER_TOLERANCE_WINDOW) {
      throw new SecurityException("Server Rejected: Timestamp out of bounds.");
    }
    if (isNonceUsed(nonce)) {
      throw new SecurityException("Server Rejected: Duplicate Report (Replay Attack).");
    }

    saveNonce(nonce);
    try (FileWriter writer = new FileWriter(savePath)) {
      new Gson().toJson(envelope, writer);
    }
    System.out.println("Server: Report accepted and stored. (Server cannot read content)");
  }

  // --- Helpers ---

  private static PublicKey getUserPublicKey(String userId) throws Exception {
    Path keyPath = Paths.get(KEYS_DIR, userId + ".pub");
    if (!Files.exists(keyPath))
      keyPath = Paths.get(KEYS_DIR, userId + ".key");
    if (!Files.exists(keyPath))
      throw new Exception("User " + userId + " unknown.");
    return loadPublicKey(keyPath);
  }

  private static PublicKey loadPublicKey(Path path) throws Exception {
    byte[] keyBytes = Files.readAllBytes(path);
    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return kf.generatePublic(spec);
  }

  private static boolean isNonceUsed(String nonce) {
    File file = new File(NONCE_DB);
    if (!file.exists())
      return false;
    try (BufferedReader br = new BufferedReader(new FileReader(file))) {
      String line;
      while ((line = br.readLine()) != null) {
        if (line.trim().equals(nonce))
          return true;
      }
    } catch (IOException e) {
      return false;
    }
    return false;
  }

  private static void saveNonce(String nonce) {
    File file = new File(NONCE_DB);
    file.getParentFile().mkdirs();
    try (BufferedWriter bw = new BufferedWriter(new FileWriter(file, true))) {
      bw.write(nonce);
      bw.newLine();
    } catch (IOException e) {
    }
  }
}
