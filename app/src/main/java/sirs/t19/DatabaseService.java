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

public class DatabaseService {

  private final MongoCollection<Document> usersCollection;
  private final MongoCollection<Document> reportsCollection;
  private final Gson gson = new Gson();

  public DatabaseService() {
    // Read DB HOST from ENV, default to localhost
    String dbHost = System.getenv("MONGO_HOST") != null ? System.getenv("MONGO_HOST") : "localhost";
    // Ensure the Mongo server is configured for TLS
    String uri = "mongodb://" + dbHost + ":27017/?tls=true";

    try {
      MongoClient mongoClient = MongoClients.create(uri);
      MongoDatabase database = mongoClient.getDatabase("civicecho");
      this.usersCollection = database.getCollection("users");
      this.reportsCollection = database.getCollection("reports");
      database.runCommand(new Document("ping", 1));
      System.out.println("DB: Secure connection to " + dbHost);
    } catch (Exception e) {
      System.err.println("DB Error: " + e.getMessage());
      throw new RuntimeException(e);
    }
  }

  public PublicKey getUserPublicKey(String userId) {
    Document user = usersCollection.find(Filters.eq("_id", userId)).first();
    if (user == null)
      return null;
    try {
      byte[] bytes = Base64.getDecoder().decode(user.getString("publicKey"));
      return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes));
    } catch (Exception e) {
      return null;
    }
  }

  public boolean validateAndAdvanceNonce(String userId, long receivedNonce) {
    Document user = usersCollection.find(Filters.eq("_id", userId)).first();
    if (user == null)
      return false;
    long last = user.getLong("lastNonce") != null ? user.getLong("lastNonce") : 0;
    if (receivedNonce > last) {
      usersCollection.updateOne(Filters.eq("_id", userId), Updates.set("lastNonce", receivedNonce));
      return true;
    }
    return false;
  }

  public void storeReport(JsonObject envelope, String reportId) {
    Document doc = Document.parse(gson.toJson(envelope));
    doc.append("_id", reportId);
    doc.append("status", "PENDING");
    reportsCollection.insertOne(doc);
    System.out.println("DB: Persisted " + reportId);
  }

  public void registerUser(String userId, String pubKey, String role) {
    Document doc = new Document("_id", userId).append("publicKey", pubKey).append("role", role)
        .append("lastNonce", 0L);
    usersCollection.replaceOne(Filters.eq("_id", userId), doc,
        new com.mongodb.client.model.ReplaceOptions().upsert(true));
    System.out.println("DB: Registered " + userId);
  }
}
