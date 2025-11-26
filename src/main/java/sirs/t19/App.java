package sirs.t19;

import java.util.Arrays;

public class App {
  public static void main(String[] args) {
    if (args.length < 3) {
      System.err.printf("Usage: %s <input-file> <output-file> <secret-key> <private-key>", args[0]);
      System.exit(1);
    }

    String command = args[0];

    String[] methodArgs = Arrays.copyOfRange(args, 1, args.length);

    try {
      switch (command) {
        case "protect":
          SecureLibrary.protect(methodArgs[1], methodArgs[2], methodArgs[3], methodArgs[4]);
          break;
        case "unprotect":
          SecureLibrary.unprotect(methodArgs[1], methodArgs[2], methodArgs[3], methodArgs[4]);
          break;
        case "check":
          SecureLibrary.check(methodArgs[1]);
          break;

        default:
          System.err.println("Unknown command " + command);
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
