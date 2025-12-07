package sirs.t19;

import java.util.Arrays;
import java.util.List;
import org.jline.builtins.Completers.FileNameCompleter;
import org.jline.reader.Completer;
import org.jline.reader.EndOfFileException;
import org.jline.reader.LineReader;
import org.jline.reader.LineReaderBuilder;
import org.jline.reader.UserInterruptException;
import org.jline.reader.impl.completer.ArgumentCompleter;
import org.jline.reader.impl.completer.StringsCompleter;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

public class App {

  private static String currentUserId = "";
  private static String currentUsername = "";
  private static String currentRole = "";

  public static void main(String[] args) {
    try {
      Terminal terminal = TerminalBuilder.builder().system(true).build();

      // Completers
      Completer fileCompleter = new FileNameCompleter();
      Completer guestCompleter = new StringsCompleter("login", "register", "help", "exit");

      // Citizen: report (full flow), protect/unprotect (manual files), check (manual file)
      Completer citizenCompleter = new ArgumentCompleter(
          new StringsCompleter("report", "protect", "unprotect", "check", "logout", "help", "exit"),
          fileCompleter);

      // Municipality: analyze (full flow), protect/unprotect (manual files), check (manual file)
      Completer municipalityCompleter = new ArgumentCompleter(new StringsCompleter("analyze",
          "protect", "unprotect", "check", "logout", "help", "exit"), fileCompleter);

      Completer dynamicCompleter = (reader, line, candidates) -> {
        if (currentUserId.isEmpty()) {
          guestCompleter.complete(reader, line, candidates);
        } else if ("municipality".equalsIgnoreCase(currentRole)) {
          municipalityCompleter.complete(reader, line, candidates);
        } else {
          citizenCompleter.complete(reader, line, candidates);
        }
      };

      LineReader lineReader =
          LineReaderBuilder.builder().terminal(terminal).completer(dynamicCompleter).build();

      System.out.println("--------------------------------------------------");
      System.out.println("      CivicEcho Client Terminal (v14.0)           ");
      System.out.println("--------------------------------------------------");

      while (true) {
        String prompt = currentUserId.isEmpty() ? "CivicEcho> "
            : "CivicEcho (" + currentRole + ")-" + currentUsername + "> ";

        String line;
        try {
          line = lineReader.readLine(prompt).trim();
        } catch (UserInterruptException | EndOfFileException e) {
          return;
        }

        if (line.isEmpty())
          continue;

        String[] tokens = line.split("\\s+");
        String command = tokens[0];
        String[] argsList = Arrays.copyOfRange(tokens, 1, tokens.length);

        try {
          if (currentUserId.isEmpty()) {
            // --- GUEST ---
            switch (command) {
              case "exit":
                return;
              case "help":
                System.out.println("Commands: login, register");
                break;
              case "login":
                if (argsList.length < 2)
                  System.err.println("Usage: login <user> <pass>");
                else {
                  String uuid = SecureLibrary.loginUser(argsList[0], argsList[1]);
                  if (uuid != null) {
                    currentUserId = uuid;
                    currentUsername = argsList[0];
                    currentRole = SecureLibrary.getUserRole(uuid);
                    System.out.println("Login successful.");
                  } else
                    System.err.println("Invalid credentials.");
                }
                break;
              case "register":
                if (argsList.length < 3)
                  System.err.println("Usage: register <user> <pass> <role>");
                else {
                  String uuid = SecureLibrary.registerUser(argsList[0], argsList[1], argsList[2]);
                  if (uuid != null) {
                    currentUserId = uuid;
                    currentUsername = argsList[0];
                    currentRole = argsList[2];
                    System.out.println("Registered. UUID: " + uuid);
                  }
                }
                break;
              default:
                System.out.println("Please login.");
            }
          } else {
            // --- LOGGED IN ---
            switch (command) {
              case "exit":
                return;
              case "logout":
                currentUserId = "";
                currentUsername = "";
                currentRole = "";
                break;

              // --- FULL FLOW COMMANDS ---
              case "report":
                if ("municipality".equals(currentRole))
                  System.err.println("Municipalities cannot submit reports.");
                else
                  handleReportFlow(lineReader);
                break;

              case "analyze":
                if (!"municipality".equals(currentRole))
                  System.err.println("Access Denied.");
                else
                  handleAnalyze(lineReader);
                break;

              // --- MANUAL FILE COMMANDS ---
              case "protect":
                if (argsList.length < 2)
                  System.err.println("Usage: protect <in_file> <out_file>");
                else
                  SecureLibrary.protect(argsList[0], argsList[1], currentUserId);
                break;

              case "unprotect":
                if (argsList.length < 2)
                  System.err.println("Usage: unprotect <in_file> <out_file>");
                else
                  SecureLibrary.unprotect(argsList[0], argsList[1], currentUserId);
                break;

              case "check":
                if (argsList.length < 1)
                  System.err.println("Usage: check <in_file> OR check <server_report_id>");
                else {
                  // Quick hack to distinguish file vs ID: try to find file, else check remote
                  java.io.File f = new java.io.File(argsList[0]);
                  if (f.exists()) {
                    System.out.println("Checking local file...");
                    SecureLibrary.check(argsList[0]);
                  } else {
                    System.out.println("Checking remote report ID...");
                    SecureLibrary.checkRemote(argsList[0]);
                  }
                }
                break;

              case "help":
                System.out.println("Commands: protect, unprotect, check, logout, "
                    + (currentRole.equals("municipality") ? "analyze" : "report"));
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

  private static void handleReportFlow(LineReader reader) {
    System.out.println("--- New Citizen Report ---");
    String category = reader.readLine("Category: ").trim();
    String location = reader.readLine("Location: ").trim();
    String desc = reader.readLine("Description: ").trim();

    try {
      // 1. Create Report with UserID
      Report r = new Report(category, location, desc, currentUserId);

      // 2. Convert to JsonObject
      JsonObject reportJson = new Gson().fromJson(r.toJson(), JsonObject.class);

      // 3. Option to save local plaintext (for debugging/grading manual protect)
      r.saveToLocalFile("client/reports/" + r.getReportId() + ".json");

      // 4. Protect & Submit
      SecureLibrary.protectAndSubmit(reportJson, currentUserId);

    } catch (Exception e) {
      System.err.println("Report Failed: " + e.getMessage());
    }
  }

  private static void handleAnalyze(LineReader reader) {
    try {
      List<String> reports = SecureLibrary.getPendingReports(currentUserId);
      if (reports.isEmpty()) {
        System.out.println("No pending reports.");
        return;
      }
      for (String rid : reports) {
        System.out.println("\nReviewing Report: " + rid);
        try {
          JsonObject data = SecureLibrary.fetchAndDecryptReport(rid, currentUserId);
          System.out.println("Description: " + data.get("description").getAsString());

          String action = "";
          while (!action.equals("APPROVED") && !action.equals("DECLINED")
              && !action.equals("SKIP")) {
            action = reader.readLine("Action (APPROVED/DECLINED/SKIP): ").trim().toUpperCase();
          }
          if (!action.equals("SKIP"))
            SecureLibrary.submitDecision(rid, action, currentUserId);

        } catch (Exception e) {
          System.err.println("Skipping " + rid + ": " + e.getMessage());
        }
      }
    } catch (Exception e) {
      System.err.println("Analyze Error: " + e.getMessage());
    }
  }
}
