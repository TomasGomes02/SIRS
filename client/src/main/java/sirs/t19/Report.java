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

  public Report(String category, String location, double latitude, double longitude,
      String description) {
    this.reportId = "echo_" + String.format("%05d", (int) (Math.random() * 100000));
    this.timestamp = Instant.now().toString();
    this.category = category;
    this.location = location;
    this.latitude = latitude;
    this.longitude = longitude;
    this.description = description;
  }

  public String toJson() {
    return String.format(
        "{\n" + "  \"report_id\": \"%s\",\n" + "  \"timestamp\": \"%s\",\n"
            + "  \"category\": \"%s\",\n" + "  \"location\": \"%s\",\n" + "  \"coordinates\": {\n"
            + "    \"latitude\": %.6f,\n" + "    \"longitude\": %.6f\n" + "  },\n"
            + "  \"description\": \"%s\"\n" + "}",
        reportId, timestamp, category, location, latitude, longitude, description);
  }

  public void saveReport() throws IOException {
    File file = new File("client/reports/" + reportId + ".json");
    try (FileWriter w = new FileWriter(file)) {
      w.write(toJson());
    }
  }

  public String getReportId() {
    return reportId;
  }
}
