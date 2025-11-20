package pt.tecnico;

import java.io.FileWriter;
import java.io.IOException;

import com.google.gson.*;

/**
 * Example of JSON writer.
 */
public class JsonWriter {
    public static void main(String[] args) throws IOException {
        // Check arguments
        if (args.length < 1) {
            System.err.println("Argument(s) missing!");
            System.err.printf("Usage: java %s file%n", JsonWriter.class.getName());
            return;
        }
        final String filename = args[0];

        // Create bank statement JSON object
        JsonObject jsonObject = new JsonObject();

        JsonObject headerObject = new JsonObject();
        headerObject.addProperty("author", "Ultron");
        headerObject.addProperty("version", 2);
        JsonArray tagsArray = new JsonArray();
        tagsArray.add("robot");
        tagsArray.add("autonomy");
        headerObject.add("tags", tagsArray);
        jsonObject.add("header", headerObject);

        jsonObject.addProperty("body", "I had strings but now I'm free");

        // Write JSON object to file
        try (FileWriter fileWriter = new FileWriter(filename)) {
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            gson.toJson(jsonObject, fileWriter);
        }
    }
}
