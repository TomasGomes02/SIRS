package sirs.t19;

import java.util.Arrays;
import java.util.Scanner;

public class App {

  public static void main(String[] args) {
    System.out.println("--------------------------------------------------");
    System.out.println("      CivicEcho Client Terminal (v5.0)            ");
    System.out.println("--------------------------------------------------");

    Scanner scanner = new Scanner(System.in);

    String user = "";

    while (true) {
      String prompt = user.isEmpty() ? "CivicEcho" : "CivicEcho-" + user;
      System.out.printf("\n" + prompt + "> ");
      if (!scanner.hasNextLine())
        break;

      String line = scanner.nextLine().trim();
      if (line.isEmpty())
        continue;

      String[] tokens = line.split("\\s+");
      String command = tokens[0];
      String[] methodArgs = Arrays.copyOfRange(tokens, 1, tokens.length);

      try {
        switch (command) {
          case "exit":
            System.out.println("System exiting...");
            scanner.close();
            return;

          case "help":
            printHelp();
            continue;

          case "login":
            if (methodArgs.length < 2) {
              System.err.println("Usage: login <username> <password>");
            } else {
              if (SecureLibrary.loginUser(methodArgs[0], methodArgs[1])) {
                user = methodArgs[0];
                System.out.println("Login successful.");
              } else
                System.err.println("Wrong credentials.");
            }
            break;

          case "register":
            if (methodArgs.length < 2) {
              System.err.println("Usage: register <username> <password>");
            } else {
              if (SecureLibrary.registerUser(methodArgs[0], methodArgs[1])) {
                user = methodArgs[0];
                System.out.println("Registration successful. Logged in as " + user);
              } else
                System.err.println("User already registered.");
            }

          default:
            System.err.println("Unknown command.");
        }

        if (user.isEmpty()) {
          continue;
        }
        switch (command) {
          case "exit":
            scanner.close();
            return;

          case "protect":
            if (methodArgs.length < 4) {
              System.err.println("Usage: protect <input> <output_on_server> <my_priv_key> <my_id>");
            } else {
              SecureLibrary.protect(methodArgs[0], methodArgs[1], methodArgs[2], methodArgs[3]);
            }
            break;

          case "unprotect":
            if (methodArgs.length < 3) {
              System.err
                  .println("Usage: unprotect <input_from_server> <local_output> <my_priv_key>");
            } else {
              SecureLibrary.unprotect(methodArgs[0], methodArgs[1], methodArgs[2]);
            }
            break;

          case "check":
            if (methodArgs.length < 1) {
              System.err.println("Usage: check <input_from_server>");
            } else {
              SecureLibrary.check(methodArgs[0], null);
            }
            break;

          case "help":
            printHelp();
            break;

          default:
            System.err.println("Unknown command.");
        }
      } catch (Exception e) {
        System.err.println("Error: " + e.getMessage());
      }
    }
  }

  private static void printHelp() {
    System.out.println("Client Commands:");
    System.out.println(
        "  protect   ...  (Submits to Server. Server verifies signature/freshness but CANNOT decrypt)");
    System.out.println(
        "  unprotect ...  (Decrypts content. Fails if you are the Server or not a recipient)");
    System.out.println("  check     ...  (Verifies integrity locally)");
  }
}
