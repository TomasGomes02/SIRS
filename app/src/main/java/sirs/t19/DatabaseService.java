package sirs.t19;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.bson.Document;
import org.bson.conversions.Bson;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.Updates;

public class DatabaseService {

  private final MongoCollection<Document> usersCollection;
  private final MongoCollection<Document> reportsCollection;
  private final Gson gson = new Gson();

  public DatabaseService() {
    String dbHost = System.getenv("MONGO_HOST") != null ? System.getenv("MONGO_HOST") : "localhost";
    String uri = "mongodb://" + dbHost + ":27017/?tls=true";

    try {
      MongoClient mongoClient = MongoClients.create(uri);
      MongoDatabase database = mongoClient.getDatabase("civicecho");
      this.usersCollection = database.getCollection("users");
      this.reportsCollection = database.getCollection("reports");
      database.runCommand(new Document("ping", 1));
      System.out.println("DB: Connected to " + dbHost);
    } catch (Exception e) {
      System.err.println("DB Error: " + e.getMessage());
      throw new RuntimeException(e);
    }
  }

  // --- User Management (Updated) ---

  /**
   * Registers a user and returns the auto-generated MongoDB ID.
   */
  public String registerUser(String username, String password, String role, String pubKey) {
    // Check for duplicates
    if (usersCollection.find(Filters.eq("name", username)).first() != null) {
      throw new RuntimeException("Username already taken");
    }

    Document doc = new Document() // let Mongo generate _id
        .append("name", username).append("password", password).append("role", role)
        .append("publicKey", pubKey).append("nonce", 0L);

    usersCollection.insertOne(doc);

    // Return the string representation of the auto-generated ObjectId
    String newId = doc.getObjectId("_id").toString();
    System.out.println("DB: Registered User " + username + " with ID: " + newId);
    return newId;
  }

  public String loginUser(String username, String password) {
    Document user = usersCollection.find(Filters.eq("name", username)).first();
    if (user != null && user.getString("password").equals(password)) {
      // Return the MongoDB ObjectId as string
      return user.getObjectId("_id").toString();
    }
    return null;
  }

  public String getUserRole(String userId) {
    try {
      Document user =
          usersCollection.find(Filters.eq("_id", new org.bson.types.ObjectId(userId))).first();
      return (user != null) ? user.getString("role") : "unknown";
    } catch (IllegalArgumentException e) {
      return "unknown"; // Handle invalid ObjectId strings
    }
  }

  public PublicKey getUserPublicKey(String userId) {
    try {
      Document user =
          usersCollection.find(Filters.eq("_id", new org.bson.types.ObjectId(userId))).first();
      if (user == null)
        return null;
      byte[] bytes = Base64.getDecoder().decode(user.getString("publicKey"));
      return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes));
    } catch (Exception e) {
      return null;
    }
  }

  // --- Nonce Handling (Updated for ObjectId) ---

  public long getNextNonce(String userId) {
    try {
      Document user =
          usersCollection.find(Filters.eq("_id", new org.bson.types.ObjectId(userId))).first();
      if (user == null)
        return 0;
      return user.getLong("nonce") + 1;
    } catch (Exception e) {
      return 0;
    }
  }

  public boolean validateAndAdvanceNonce(String userId, long receivedNonce) {
    try {
      Bson filter = Filters.eq("_id", new org.bson.types.ObjectId(userId));
      Document user = usersCollection.find(filter).first();
      if (user == null)
        return false;

      long current = user.getLong("nonce");
      if (receivedNonce > current) {
        usersCollection.updateOne(filter, Updates.set("nonce", receivedNonce));
        return true;
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
    return false;
  }

  // --- Report Management (Unchanged - Keeps Custom ID) ---

  public void storeReport(JsonObject envelope, String reportId) {
    Document doc = Document.parse(gson.toJson(envelope));
    doc.append("_id", reportId); // Keeping Client-Generated ID for Reports

    Document metadata = (Document) doc.get("metadata");
    metadata.put("status", "WAITING");
    doc.put("metadata", metadata);

    reportsCollection.insertOne(doc);
    System.out.println("DB: Stored Report " + reportId);
  }

  public List<String> getPendingReports() {
    List<String> ids = new ArrayList<>();
    Bson filter = Filters.eq("metadata.status", "WAITING");
    reportsCollection.find(filter).forEach(doc -> ids.add(doc.getString("_id")));
    return ids;
  }

  public String getReportJson(String reportId) {
    Document doc = reportsCollection.find(Filters.eq("_id", reportId)).first();
    if (doc == null)
      return null;
    doc.remove("_id");
    return doc.toJson();
  }

  public void updateReportStatus(String reportId, String status) {
    Bson filter = Filters.eq("_id", reportId);
    Bson update = Updates.set("metadata.status", status);
    reportsCollection.updateOne(filter, update);
  }
}
