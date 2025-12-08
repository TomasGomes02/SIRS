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

public class ReportLimiter {

  private final MongoCollection<Document> tokensCollection;
  private final Gson gson = new Gson();

  public ReportLimiter() {
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

  public Integer getUserTokens(String userId) {
    Document tokenDoc = tokensCollection.find(Filters.eq("_id", userId)).first();
    if (tokenDoc == null)
      return null;
    Integer n_tokens = tokenDoc.getInteger("n_tokens");
    return n_tokens;
  }

  public void issueUserTokens(String userId, Integer n_tokens) {
    tokensCollection.updateOne(
        Filters.eq("_id", userId),
        Updates.inc("n_tokens", n_tokens),
        new com.mongodb.client.model.UpdateOptions().upsert(true)
    );
    System.out.println("DB: Issued " + n_tokens + " tokens for " + userId);
  }

  public void consumeUserToken(String userId) {
    tokensCollection.updateOne(
        Filters.eq("_id", userId),
        Updates.inc("n_tokens", -1)
    );
    System.out.println("DB: Consumed 1 token from " + userId);
  }
}