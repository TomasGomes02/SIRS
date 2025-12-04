package sirs.t19;

import java.io.File;
import java.util.Arrays;
import java.util.List;
import org.jline.builtins.Completers.FileNameCompleter;
import org.jline.reader.Completer;
import org.jline.reader.LineReader;
import org.jline.reader.LineReaderBuilder;
import org.jline.reader.ParsedLine;
import org.jline.reader.impl.completer.ArgumentCompleter;
import org.jline.reader.impl.completer.StringsCompleter;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;

public class App {

  private static String currentUser = "";

  public static void main(String[] args) {
    try {
      Terminal terminal = TerminalBuilder.builder().system(true).build();

      // Completers
      Completer fileCompleter = new FileNameCompleter();
      Completer guestCompleter = new StringsCompleter("login", "register", "help", "exit", "quit");

      // User mode supports commands + file paths
      Completer userCompleter = new ArgumentCompleter(new StringsCompleter("protect", "unprotect",
          "check", "report", "logout", "help", "exit", "quit"), fileCompleter);

      Completer dynamicCompleter = new Completer() {
        @Override
        public void complete(LineReader reader, ParsedLine line,
            List<org.jline.reader.Candidate> candidates) {
          if (currentUser.isEmpty()) {
            guestCompleter.complete(reader, line, candidates);
          } else {
            userCompleter.complete(reader, line, candidates);
          }
        }
      };

      LineReader lineReader =
          LineReaderBuilder.builder().terminal(terminal).completer(dynamicCompleter).build();

      System.out.println("--------------------------------------------------");
      System.out.println("      CivicEcho Client Terminal (v11.0)           ");
      System.out.println("--------------------------------------------------");

      while (true) {
        String prompt = currentUser.isEmpty() ? "CivicEcho> " : "CivicEcho-" + currentUser + "> ";
        String line;

        try {
          line = lineReader.readLine(prompt).trim();
        } catch (Exception e) {
          break;
        }

        if (line.isEmpty())
          continue;

        String[] tokens = line.split("\\s+");
        String command = tokens[0];
        String[] argsList = Arrays.copyOfRange(tokens, 1, tokens.length);

        try {
          if (currentUser.isEmpty()) {
            switch (command) {
              case "exit":
                return;
              case "help":
                printAuthHelp();
                break;
              case "login":
                if (argsList.length < 2)
                  System.err.println("Usage: login <user> <pass>");
                else {
                  if (SecureLibrary.loginUser(argsList[0], argsList[1])) {
                    currentUser = argsList[0];
                    System.out.println("Login successful.");
                  } else
                    System.err.println("Wrong credentials.");
                }
                break;
              case "register":
                if (argsList.length < 3)
                  System.err.println("Usage: register <user> <pass> <role:citizen|municipality>");
                else {
                  String id = SecureLibrary.registerUser(argsList[0], argsList[1], argsList[2]);
                  if (id != null) {
                    currentUser = argsList[0]; // Set to username or ID depending on preference
                    System.out.println("Registered. ID: " + id);
                  } else
                    System.err.println("User exists.");
                }
                break;
              default:
                System.out.println("Please login.");
            }
          } else {
            switch (command) {
              case "exit":
                return;
              case "logout":
                currentUser = "";
                break;
              case "report":
                handleReportCreation(lineReader);
                break;
              case "protect":
                if (argsList.length < 2)
                  System.err.println("Usage: protect <in> <server_out>");
                else
                  SecureLibrary.protect(argsList[0], argsList[1], currentUser);
                break;
              case "unprotect":
                if (argsList.length < 2)
                  System.err.println("Usage: unprotect <server_in> <local_out>");
                else
                  SecureLibrary.unprotect(argsList[0], argsList[1], currentUser);
                break;
              case "check":
                if (argsList.length < 1)
                  System.err.println("Usage: check <in>");
                else
                  SecureLibrary.check(argsList[0]);
                break;
              case "help":
                printUserHelp();
                break;
              default:
                System.err.println("Unknown command.");
            }
          }
        } catch (Exception e) {
          System.err.println("Error: " + e.getMessage());
        }
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private static void handleReportCreation(LineReader reader) {
    System.out.println("--- New Citizen Report ---");
    String category = reader.readLine("Category: ").trim();
    String location = reader.readLine("Location: ").trim();
    String desc = reader.readLine("Description: ").trim();

    try {
      new File("client/reports").mkdirs();
      Report r = new Report(category, location, desc);
      r.saveReport();
      System.out.println("Report saved: client/reports/" + r.getReportId() + ".json");
    } catch (Exception e) {
      System.err.println("Failed: " + e.getMessage());
    }
  }

  private static void printAuthHelp() {
    System.out.println("Commands: login, register");
  }

  private static void printUserHelp() {
    System.out.println("Commands: report, protect, unprotect, check, logout");
  }
}
