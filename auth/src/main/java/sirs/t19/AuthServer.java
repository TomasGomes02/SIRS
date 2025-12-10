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

public class AuthServer {

  private final MongoCollection<Document> tokensCollection;
  private final Gson gson = new Gson();

  public AuthServer() {
    // Read DB HOST from ENV, default to localhost
    String dbHost = System.getenv("MONGO_HOST") != null ? System.getenv("MONGO_HOST") : "localhost";
    // Ensure the Mongo server is configured for TLS
    String uri = "mongodb://" + dbHost + ":27017/?tls=true";

    try {
      MongoClient mongoClient = MongoClients.create(uri);
      MongoDatabase database = mongoClient.getDatabase("civicecho-tokens");
      this.tokensCollection = database.getCollection("tokens");
      database.runCommand(new Document("ping", 1));
      System.out.println("DB: Secure connection to " + dbHost);
    } catch (Exception e) {
      System.err.println("DB Error: " + e.getMessage());
      throw new RuntimeException(e);
    }
  }

}