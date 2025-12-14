package sirs.t19;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class AuthServer {
  private static final int PORT = 8444;
  private static DatabaseService db;

  public static void main(String[] args) {
    try {
      System.out.println("AuthServer (192.168.20.10): Starting...");

      // Load Keys (Standard naming)
      File storeFile = extractResource("auth-server.p12");
      System.setProperty("javax.net.ssl.keyStore", storeFile.getAbsolutePath());
      System.setProperty("javax.net.ssl.keyStorePassword", "authserverpass");
      System.setProperty("javax.net.ssl.keyStoreType", "PKCS12");

      File trustFile = extractResource("server_truststore.jks");
      System.setProperty("javax.net.ssl.trustStore", trustFile.getAbsolutePath());
      System.setProperty("javax.net.ssl.trustStorePassword", "changeit");

      db = new DatabaseService();

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
      System.out.println("CMD: " + line);

      String[] parts = line.split(" ");
      String cmd = parts[0];

      try {
        switch (cmd) {
          case "REGISTER":
            // REGISTER <user> <pass> <role> <pubkey>
            // Returns: <UUID> <TOKEN>
            if (parts.length == 5) {
              String newId = db.registerUser(parts[1], parts[2], parts[3], parts[4]);
              String token = db.getUserCurrentToken(newId);
              out.println(newId + " " + token);
            } else
              out.println("ERROR Format");
            break;

          case "LOGIN":
            // LOGIN <user> <pass>
            // Returns: <UUID> <TOKEN>
            if (parts.length == 3) {
              String uuid = db.loginUser(parts[1], parts[2]);
              if (uuid != null) {
                String token = db.getUserCurrentToken(uuid);
                out.println(uuid + " " + token);
              } else {
                out.println("ERROR Creds");
              }
            } else
              out.println("ERROR Format");
            break;

          case "REQUEST":
            // REQUEST <user_id>
            // Consumes the *current* token and returns the *next* token
            if (parts.length == 2) {
              String newToken = db.consumeUserToken(parts[1]);
              out.println(newToken);
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

  // Helper to load resources
  private static File extractResource(String name) {
    try {
      File temp = File.createTempFile(name, ".tmp");
      temp.deleteOnExit();
      try (InputStream is = AuthServer.class.getClassLoader().getResourceAsStream(name);
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
}
