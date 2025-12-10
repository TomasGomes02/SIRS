package sirs.t19;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.Updates;
import org.bson.Document;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;
import app.src.main.java.sirs.t19.DatabaseService;

public class AuthServer {
  private static final int PORT = 8443;
  private static DatabaseService db;

  public static void main(String[] args) {
    try {
      System.out.println("AuthServer: Starting...");

      // AQUI TROCAR OS NOMES DOS FILES

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
      System.out.println("AuthServer: Listening on TLS " + PORT);

      while (true) {
        SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
        new Thread(() -> handleClient(clientSocket)).start();
      }

    } catch (Exception e) {
      e.printStackTrace();
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
                String newToken = db.issueToken(newId);
                // Send the new ID and the token back to the client
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
              String token = db.getUserCurrentToken(uuid);
              out.println(uuid != null ? uuid : "ERROR Creds");
            } else
              out.println("ERROR Format");
            break;

          case "CONSUME": // consumes user token
            // CONSUME <user>
            if (parts.length == 2) {
              try {
                db.consumeUserToken(parts[1]);
                out.println("CONSUMED TOKEN");
              } catch (Exception e) {
                out.println("ERROR " + e.getMessage());
              }
            } else {
              out.println("ERROR Format");
            }
            break;

          case "REQUEST":
            // REQUEST <user>
            if (parts.length == 2) {
              try {
                String token = db.getUserCurrentToken(parts[1]);
                // send the token to the user
                out.println(token);
              } catch (Exception e) {
                out.println("ERROR " + e.getMessage());
              }
            } else {
              out.println("ERROR Format");
            }
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

}