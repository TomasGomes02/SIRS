package sirs.t19;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
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
    String uri;

    if (dbHost.equals("localhost")) {
      // Local testing
      uri = "mongodb://localhost:27017/?tls=true&tlsAllowInvalidHostnames=true";
    } else {
      // Production (VMs)
      uri = "mongodb://" + dbHost + ":27017/?tls=true&tlsAllowInvalidHostnames=true";
    }

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

  // --- User Management ---

  public String registerUser(String username, String password, String role, String pubKey) {
    if (usersCollection.find(Filters.eq("name", username)).first() != null) {
      throw new RuntimeException("Username already taken");
    }

    // Generate initial token
    String initialToken = UUID.randomUUID().toString();
    int initialTokens = 5; // Default tokens per user

    Document doc = new Document().append("name", username).append("password", password)
        .append("role", role).append("publicKey", pubKey).append("nonce", 0L)
        .append("n_tokens", initialTokens).append("token", initialToken);

    usersCollection.insertOne(doc);

    String newId = doc.getObjectId("_id").toString();
    System.out.println("DB: Registered " + username + " (ID: " + newId + ")");
    return newId;
  }

  public String loginUser(String username, String password) {
    Document user = usersCollection.find(Filters.eq("name", username)).first();
    if (user != null && user.getString("password").equals(password)) {
      return user.getObjectId("_id").toString();
    }
    return null;
  }

  public String getUserRole(String userId) {
    try {
      Document user = usersCollection.find(Filters.eq("_id", new org.bson.types.ObjectId(userId))).first();
      return (user != null) ? user.getString("role") : "unknown";
    } catch (Exception e) {
      return "unknown";
    }
  }

  public PublicKey getUserPublicKey(String userId) {
    try {
      Document user = usersCollection.find(Filters.eq("_id", new org.bson.types.ObjectId(userId))).first();
      if (user == null)
        return null;
      byte[] bytes = Base64.getDecoder().decode(user.getString("publicKey"));
      return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes));
    } catch (Exception e) {
      return null;
    }
  }

  public List<String> getAllMunicipalities() {
    List<String> ids = new ArrayList<>();
    usersCollection.find(Filters.eq("role", "municipality"))
        .forEach(doc -> ids.add(doc.getObjectId("_id").toString()));
    return ids;
  }

  public List<String> getAllCitizens() {
    List<String> ids = new ArrayList<>();
    usersCollection.find(Filters.eq("role", "citizen"))
        .forEach(doc -> ids.add(doc.getObjectId("_id").toString()));
    return ids;
  }

  public List<String> getAllUsers() {
    List<String> ids = new ArrayList<>();
    usersCollection.find()
        .forEach(doc -> ids.add(doc.getObjectId("_id").toString()));
    return ids;
  }

  // --- Token Management ---

  public String getUserCurrentToken(String userId) {
    try {
      Document user = usersCollection.find(Filters.eq("_id", new org.bson.types.ObjectId(userId))).first();
      return (user != null) ? user.getString("token") : null;
    } catch (Exception e) {
      return null;
    }
  }

  public int getUserTokenAmount(String userId) {
    try {
      Document user = usersCollection.find(Filters.eq("_id", new org.bson.types.ObjectId(userId))).first();
      return (user != null) ? user.getInteger("n_tokens") : -1;
    } catch (Exception e) {
      return -1;
    }
  }

  public String consumeUserToken(String userId) {
    try {
      Document user = usersCollection.find(Filters.eq("_id", new org.bson.types.ObjectId(userId))).first();
      if (user == null)
        throw new RuntimeException("User not found");

      Integer n_tokens = user.getInteger("n_tokens");
      if (n_tokens == null || n_tokens <= 0) {
        throw new RuntimeException("No tokens remaining");
      }

      String newToken = UUID.randomUUID().toString();

      usersCollection.updateOne(Filters.eq("_id", new org.bson.types.ObjectId(userId)),
          Updates.combine(Updates.inc("n_tokens", -1), Updates.set("token", newToken)));

      System.out.println("DB: Consumed token for " + userId + ". Remaining: " + (n_tokens - 1));
      return newToken + " " + (n_tokens - 1);
    } catch (Exception e) {
      throw new RuntimeException(e.getMessage());
    }
  }

  // --- Nonce & Report Management ---

  public long getNextNonce(String userId) {
    try {
      Document user = usersCollection.find(Filters.eq("_id", new org.bson.types.ObjectId(userId))).first();
      return (user != null) ? user.getLong("nonce") + 1 : 0;
    } catch (Exception e) {
      return -1;
    }
  }

  public boolean validateAndAdvanceNonce(String userId, long receivedNonce) {
    try {
      Bson filter = Filters.eq("_id", new org.bson.types.ObjectId(userId));
      Document user = usersCollection.find(filter).first();
      if (user == null)
        return false;
      if (receivedNonce > user.getLong("nonce")) {
        usersCollection.updateOne(filter, Updates.set("nonce", receivedNonce));
        return true;
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
    return false;
  }

  public void storeReport(JsonObject envelope, String reportId) {
    Document doc = Document.parse(gson.toJson(envelope));
    doc.append("_id", reportId);
    doc.append("status", "WAITING");
    reportsCollection.insertOne(doc);
  }

  public List<String> getPendingReports() {
    List<String> ids = new ArrayList<>();
    reportsCollection.find(Filters.eq("status", "WAITING"))
        .forEach(doc -> ids.add(doc.getString("_id")));
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
    reportsCollection.updateOne(Filters.eq("_id", reportId),
        Updates.set("status", status));
  }

  public List<String> getViewableReports(String userId) {
    List<String> ids = new ArrayList<>();
    String role = getUserRole(userId);

    if ("municipality".equals(role)) {
      // Municipalities see everything
      reportsCollection.find().forEach(doc -> ids.add(doc.getString("_id")));
    } else {
      // Citizens see their own reports OR approved reports
      Bson filter = Filters.or(
          Filters.eq("metadata.author_id", userId),
          Filters.eq("status", "APPROVED"));

      reportsCollection.find(filter).forEach(doc -> ids.add(doc.getString("_id")));
    }
    return ids;
  }
}
