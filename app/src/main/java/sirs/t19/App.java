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
import java.util.List;

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
      File storeFile = extractResource("app-server.p12");
      System.setProperty("javax.net.ssl.keyStore", storeFile.getAbsolutePath());
      System.setProperty("javax.net.ssl.keyStorePassword", "appserverpass");
      System.setProperty("javax.net.ssl.keyStoreType", "PKCS12");

      // Setup Trust (DB CA)
      File trustFile = extractResource("server_truststore.jks");
      System.setProperty("javax.net.ssl.trustStore", trustFile.getAbsolutePath());
      System.setProperty("javax.net.ssl.trustStorePassword", "changeit");

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

      System.out.println("CMD: " + line); // Debug logging

      String[] parts = line.split(" ");
      String cmd = parts[0];

      try {
        switch (cmd) {
          case "REGISTER":
            // REGISTER <user> <pass> <role> <pubkey>
            if (parts.length == 5) {
              try {
                String newId = db.registerUser(parts[1], parts[2], parts[3], parts[4]);
                // Send the new ID back to the client
                out.println(newId);
              } catch (Exception e) {
                out.println("ERROR " + e.getMessage());
              }
            } else {
              out.println("ERROR Format");
            }
            break;

          case "LOGIN":
            // LOGIN <user> <pass>
            if (parts.length == 3) {
              String uuid = db.loginUser(parts[1], parts[2]);
              out.println(uuid != null ? uuid : "ERROR Creds");
            } else
              out.println("ERROR Format");
            break;

          case "GET_ROLE":
            // GET_ROLE <uid>
            if (parts.length == 2) {
              out.println(db.getUserRole(parts[1]));
            } else
              out.println("ERROR Format");
            break;

          case "GET_NONCE":
            // GET_NONCE <uid>
            if (parts.length == 2) {
              out.println(db.getNextNonce(parts[1]));
            } else
              out.println("ERROR Format");
            break;

          case "GET_PUBKEY":
            // GET_PUBKEY <uid>
            if (parts.length == 2) {
              PublicKey key = db.getUserPublicKey(parts[1]);
              if (key != null)
                out.println(Base64.getEncoder().encodeToString(key.getEncoded()));
              else
                out.println("ERROR Not Found");
            } else
              out.println("ERROR Format");
            break;

          case "GET_USERS":
            try {
              out.print(String.join(",", db.getAllUsers()));
            } catch (Exception e) {
              out.print("ERROR " + e.getMessage());
            }
            break;

          case "SUBMIT":
            // SUBMIT <json>
            try {
              processReport(line.substring(7));
              out.println("OK");
            } catch (Exception e) {
              e.printStackTrace();
              out.println("ERROR " + e.getMessage());
            }
            break;

          case "GET_PENDING_REPORTS":
            // GET_PENDING_REPORTS <requester_id>
            // Only allow if requester is municipality? (Simplified for now)
            if (parts.length == 2 && "municipality".equals(db.getUserRole(parts[1]))) {
              out.println(String.join(",", db.getPendingReports()));
            } else {
              out.println("ERROR Access Denied or No Reports");
            }
            break;

          case "GET_REPORT":
            // GET_REPORT <report_id> <requester_id>
            // Access Control: Only the municipality or the report author may fetch the
            // report
            if (parts.length == 3) {
              String reportId = parts[1];
              String requester = parts[2];
              String role = db.getUserRole(requester);
              String json = db.getReportJson(reportId);
              if (json == null) {
                out.println("ERROR Not Found");
              } else {
                try {
                  Gson gson = new Gson();
                  JsonObject envelope = gson.fromJson(json, JsonObject.class);
                  JsonObject metadata = envelope.getAsJsonObject("metadata");
                  String author = metadata.get("author_id").getAsString();
                  String status = envelope.get("status").getAsString();

                  boolean isAuthor = author.equals(requester);
                  boolean isMunicipality = "municipality".equals(role);
                  boolean isApproved = "APPROVED".equals(status);

                  if (isMunicipality || isAuthor || isApproved) {
                    out.println(json);
                  } else {
                    out.println("ERROR Access Denied");
                  }
                } catch (Exception e) {
                  out.println("ERROR Invalid Report Format");
                }
              }
            } else
              out.println("ERROR Format");
            break;

          case "GET_VIEWABLE_REPORTS":
            // GET_VIEWABLE_REPORTS <user_id>
            if (parts.length == 2) {
              try {
                List<String> ids = db.getViewableReports(parts[1]);
                out.println(String.join(",", ids));
              } catch (Exception e) {
                out.println("ERROR " + e.getMessage());
              }
            } else {
              out.println("ERROR Format");
            }
            break;

          case "UPDATE_STATUS":
            // UPDATE_STATUS <report_id> <status> <municipality_id>
            if (parts.length == 4) {
              if ("municipality".equals(db.getUserRole(parts[3]))) {
                db.updateReportStatus(parts[1], parts[2]);
                out.println("OK");
              } else {
                out.println("ERROR Access Denied");
              }
            } else
              out.println("ERROR Format");
            break;

          default:
            out.println("ERROR Unknown Command");
        }
      } catch (Exception e) {
        out.println("ERROR " + e.getMessage());
      }
    } catch (IOException e) {
      System.err.println("IO Error: " + e.getMessage());
    }
  }

  private static void processReport(String json) throws Exception {
    Gson gson = new Gson();
    String[] line = json.split(" ");
    JsonObject envelope = gson.fromJson(line[0], JsonObject.class);

    String reportId = envelope.keySet().iterator().next();
    JsonObject inner = envelope.getAsJsonObject(reportId);

    JsonObject meta = inner.getAsJsonObject("metadata");
    String uid = meta.get("author_id").getAsString();
    long nonce = meta.get("nonce").getAsLong();
    String token = meta.get("token").getAsString();

    // 1. Verify User Exists
    PublicKey pub = db.getUserPublicKey(uid);
    if (pub == null)
      throw new SecurityException("User not found");

    // 2. Verify Nonce (Replay Protection)
    if (!db.validateAndAdvanceNonce(uid, nonce))
      throw new SecurityException("Invalid Nonce (Replay Attack)");

    // 3. Verify Signature
    // Reconstruct signed data: metadata + recipients + ciphertext
    String data = meta.toString() + inner.get("recipients").toString()
        + inner.get("ciphertext").getAsString();

    Signature rsa = Signature.getInstance("SHA256withRSA");
    rsa.initVerify(pub);
    rsa.update(data.getBytes());

    if (!rsa.verify(Base64.getDecoder().decode(inner.get("signature").getAsString())))
      throw new SecurityException("Invalid Signature");

    // 4. Verify Token
    if (!(db.getUserCurrentToken(uid).equals(token))) {
      System.out.println("DB TOKEN: " + db.getUserCurrentToken(uid));
      System.out.println("USER TOKEN: " + token);
      throw new SecurityException("Invalid token");
    }

    if (db.getUserTokenAmount(uid) <= 0) {
      throw new SecurityException("No more tokens");
    }

    // 5. Store (Store the inner envelope keyed by ID)
    db.storeReport(inner, reportId);
  }
}
