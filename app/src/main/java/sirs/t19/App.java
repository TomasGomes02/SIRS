package sirs.t19;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

public class App {

  private static final int PORT = 8443;
  private static DatabaseService db;

  public static void main(String[] args) {
    try {
      System.out.println("Server: Starting...");

      // Setup Identity (Server's Key)
      File storeFile = extractResource("server.p12");
      System.setProperty("javax.net.ssl.keyStore", storeFile.getAbsolutePath());
      System.setProperty("javax.net.ssl.keyStorePassword", "serverpass");
      System.setProperty("javax.net.ssl.keyStoreType", "PKCS12");

      // Setup Trust (DB CA)
      File trustFile = extractResource("server_truststore.jks");
      System.setProperty("javax.net.ssl.trustStore", trustFile.getAbsolutePath());
      System.setProperty("javax.net.ssl.trustStorePassword", "serverpass");

      // Connect DB
      db = new DatabaseService();

      // Listen
      SSLServerSocketFactory ssf = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
      SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(PORT);
      System.out.println("Server: Listening on TLS " + PORT);

      while (true) {
        SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
        new Thread(() -> handleClient(clientSocket)).start();
      }

    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private static File extractResource(String name) {
    try {
      File temp = File.createTempFile(name, ".tmp");
      temp.deleteOnExit();
      try (InputStream is = App.class.getClassLoader().getResourceAsStream(name);
          FileOutputStream os = new FileOutputStream(temp)) {
        if (is == null)
          throw new RuntimeException("Resource " + name + " not found");
        byte[] buffer = new byte[1024];
        int read;
        while ((read = is.read(buffer)) != -1)
          os.write(buffer, 0, read);
      }
      return temp;
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private static void handleClient(SSLSocket socket) {
    try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

      String line = in.readLine();
      if (line == null)
        return;

      if (line.startsWith("REGISTER ")) {
        String[] parts = line.split(" ");
        if (parts.length == 4) {
          db.registerUser(parts[1], parts[2], parts[3]);
          out.println("OK");
        } else
          out.println("ERROR Format");
      } else if (line.startsWith("SUBMIT ")) {
        try {
          processReport(line.substring(7));
          out.println("OK");
        } catch (Exception e) {
          out.println("ERROR " + e.getMessage());
        }
      } else
        out.println("ERROR Unknown");
    } catch (IOException e) {
      System.err.println("IO Error: " + e.getMessage());
    }
  }

  private static void processReport(String json) throws Exception {
    Gson gson = new Gson();
    JsonObject envelope = gson.fromJson(json, JsonObject.class);
    JsonObject meta = envelope.getAsJsonObject("metadata");
    String uid = meta.get("author_id").getAsString();
    long nonce = meta.get("nonce").getAsLong();

    PublicKey pub = db.getUserPublicKey(uid);
    if (pub == null)
      throw new SecurityException("User not found");

    if (!db.validateAndAdvanceNonce(uid, nonce))
      throw new SecurityException("Replay Attack");

    String data = meta.toString() + envelope.get("recipients").toString()
        + envelope.get("ciphertext").getAsString();
    Signature rsa = Signature.getInstance("SHA256withRSA");
    rsa.initVerify(pub);
    rsa.update(data.getBytes());
    if (!rsa.verify(Base64.getDecoder().decode(envelope.get("signature").getAsString())))
      throw new SecurityException("Invalid Signature");

    db.storeReport(envelope, "rep_" + nonce);
  }
}
