package modchecker.report;

import com.google.gson.*;
import java.time.Instant;
import java.util.List;

/** Явная схема экспорта, без внутренних объектов Path и без ключей API. */
public final class ReportJson {
    private ReportJson() { }
    public static String format(List<ModReport> reports) {
        Gson gson = new GsonBuilder().serializeNulls().setPrettyPrinting().create();
        JsonObject root = new JsonObject();
        root.addProperty("formatVersion", 1);
        root.addProperty("generatedAt", Instant.now().toString());
        JsonArray rows = new JsonArray();
        for (ModReport report : reports) {
            var scan = report.scan();
            JsonObject row = new JsonObject();
            row.addProperty("file", scan.file().toAbsolutePath().toString());
            row.addProperty("name", scan.name());
            row.addProperty("mode", report.fullScan() ? "full" : "sites");
            row.addProperty("status", report.statusLabel());
            row.addProperty("complete", !scan.hasError());
            if (report.fullScan()) row.addProperty("points", scan.points()); else row.add("points", JsonNull.INSTANCE);
            row.addProperty("error", scan.error());
            row.add("online", gson.toJsonTree(report.online()));
            JsonArray findings = new JsonArray();
            for (var finding : scan.findings()) {
                JsonObject item = gson.toJsonTree(finding).getAsJsonObject();
                item.addProperty("source", finding.location().contains("!/") ? "nested-jar" : "main-jar");
                item.add("locations", gson.toJsonTree(scan.evidenceLocations(finding.rule())));
                findings.add(item);
            }
            row.add("findings", findings);
            row.add("links", gson.toJsonTree(scan.links()));
            row.add("entities", gson.toJsonTree(scan.foundEntities()));
            row.add("decodedNotes", gson.toJsonTree(scan.decodedNotes()));
            row.add("nativeFiles", gson.toJsonTree(report.nativeReports()));
            rows.add(row);
        }
        root.add("results", rows);
        return gson.toJson(root);
    }
}
