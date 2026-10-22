package modchecker.selftest;

import com.google.gson.*;
import modchecker.model.ModScanResult;
import modchecker.model.Verdict;
import modchecker.online.*;
import modchecker.report.*;
import modchecker.scan.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Проверка смешанного набора. Не объявляет все образцы безопасными и не загружает их классы. */
public final class CorpusAudit {
    public static void main(String[] args) throws Exception {
        Path input = Path.of(args[0]).toAbsolutePath();
        Path output = Path.of(args[1]).toAbsolutePath();
        Path sitesFile = Path.of(args[2]).toAbsolutePath();
        Files.createDirectories(output.getParent());
        List<Path> files = ModFinder.find(input);
        Gson gson = new GsonBuilder().serializeNulls().setPrettyPrinting().create();
        List<OnlineCheckResult> sites = new ArrayList<>();
        if (Files.isRegularFile(sitesFile)) {
            sites.addAll(Arrays.asList(gson.fromJson(Files.readString(sitesFile), OnlineCheckResult[].class)));
            if (sites.size() != files.size()) throw new IllegalStateException("Изменился состав набора");
        } else {
            System.out.println("Hash/site check: " + files.size() + " files (data only)");
            String key = CurseForgeKeyStore.loadDefault();
            if (key == null) key = OnlineChecker.readDefaultKey();
            sites = new OnlineChecker(key).checkFiles(files, (done, total) -> {
                if (done % 100 == 0 || done == total) System.out.println("Hashes " + done + "/" + total);
            });
            Files.writeString(sitesFile, gson.toJson(sites));
        }
        ScanService scanner = new ScanService();
        List<ModReport> reports = new ArrayList<>();
        JsonArray rows = new JsonArray();
        Map<String, Integer> counts = new TreeMap<>();
        for (int i = 0; i < files.size(); i++) {
            Path file = files.get(i);
            OnlineCheckResult online = sites.get(i);
            if (!Hashes.sha1(file).equals(online.sha1())) throw new IllegalStateException("Изменён файл: " + file.getFileName());
            ModScanResult scan = scanner.scan(file);
            Verdict raw = scan.verdict();
            if (online.confirmed()) scan.markOnlineConfirmed();
            if (online.confirmed() && scan.verdict() == Verdict.DANGEROUS) throw new IllegalStateException("Нарушен предел подтверждённого файла");
            ModReport report = new ModReport(scan, online);
            reports.add(report);
            JsonObject row = new JsonObject();
            row.addProperty("name", scan.name()); row.addProperty("sha1", online.sha1());
            row.addProperty("points", scan.points()); row.addProperty("rawVerdict", raw.name());
            row.addProperty("verdict", scan.verdict().name()); row.addProperty("confirmed", online.confirmed());
            row.addProperty("modrinth", online.modrinth().name()); row.addProperty("curseforge", online.curseForge().name());
            row.addProperty("error", scan.error());
            JsonObject rules = new JsonObject();
            for (var finding : scan.findings()) rules.addProperty(Integer.toString(finding.rule()), finding.points());
            row.add("rules", rules);
            row.addProperty("critical", scan.links().stream().anyMatch(link -> link.name().equals("КРИТИЧЕСКАЯ")));
            rows.add(row);
            counts.merge(scan.verdict().name(), 1, Integer::sum);
            if ((i + 1) % 25 == 0 || i + 1 == files.size()) {
                Files.writeString(output, gson.toJson(rows));
                System.out.println("Static " + (i + 1) + "/" + files.size() + " " + counts);
            }
        }
        Files.writeString(output.resolveSibling(output.getFileName() + ".txt"), ReportPrinter.format(reports), StandardCharsets.UTF_8);
        System.out.println("FINISHED " + files.size() + " " + counts);
    }
}
