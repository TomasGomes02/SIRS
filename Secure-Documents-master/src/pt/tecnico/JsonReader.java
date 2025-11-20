package pt.tecnico;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.io.FileReader;
import java.io.IOException;

public class JsonReader {
    public static void main(String[] args) throws IOException {
        // Check arguments
        if (args.length < 1) {
            System.err.println("Argument(s) missing!");
            System.err.printf("Usage: java %s file%n", JsonReader.class.getName());
            return;
        }
        final String filename = args[0];

        // Read JSON object from file, and print its contets
        try (FileReader fileReader = new FileReader(filename)) {
            Gson gson = new Gson();
            JsonObject rootJson = gson.fromJson(fileReader, JsonObject.class);
            System.out.println("JSON object: " + rootJson);

            JsonObject headerObject = rootJson.get("header").getAsJsonObject();
            System.out.println("Document header:");
            System.out.println("Author: " + headerObject.get("author").getAsString());
            System.out.println("Version: " + headerObject.get("version").getAsInt());
            JsonArray tagsArray = headerObject.getAsJsonArray("tags");
            System.out.print("Tags: ");
            for (int i = 0; i < tagsArray.size(); i++) {
                System.out.print(tagsArray.get(i).getAsString());
                if (i < tagsArray.size() - 1) {
                    System.out.print(", ");
                } else {
                    System.out.println(); // Print a newline after the final tag
                }
            }

            System.out.println("Document body: " + rootJson.get("body").getAsString());
        }
    }
}
