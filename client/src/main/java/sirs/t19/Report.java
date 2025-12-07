package sirs.t19;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.time.Instant;

public class Report {
  private final String reportId;
  private final String timestamp;
  private final String category;
  private final String location;
  private final double latitude;
  private final double longitude;
  private final String description;
  private final String userId;

  public Report(String category, String location, String description, String userId) {
    this.reportId = "echo_" + String.format("%05d", (int) (Math.random() * 100000));
    this.timestamp = Instant.now().toString();
    this.latitude = (Math.random() * 180) - 90;
    this.longitude = (Math.random() * 360) - 90;
    this.location = location;
    this.category = category;
    this.description = description;
    this.userId = userId;
  }

  public String toJson() {
    return String.format(
        "{\n" + "  \"report_id\": \"%s\",\n" + "  \"timestamp\": \"%s\",\n"
            + "  \"category\": \"%s\",\n" + "  \"location\": \"%s\",\n" + "  \"coordinates\": {\n"
            + "    \"latitude\": %.6f,\n" + "    \"longitude\": %.6f\n" + "  },\n"
            + "  \"description\": \"%s\",\n" + "  \"user_id\": \"%s\"\n" + "}",
        reportId, timestamp, category, location, latitude, longitude, description, userId);
  }

  // Helper to save raw plaintext for manual 'protect' command testing
  public void saveToLocalFile(String filename) throws IOException {
    File file = new File(filename);
    // Ensure parent directories exist
    if (file.getParentFile() != null) {
      file.getParentFile().mkdirs();
    }
    try (FileWriter w = new FileWriter(file)) {
      w.write(toJson());
    }
  }

  public String getReportId() {
    return reportId;
  }
}
