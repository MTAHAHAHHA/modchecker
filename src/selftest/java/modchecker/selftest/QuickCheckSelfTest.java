package modchecker.selftest;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import modchecker.app.ScanBatch;
import modchecker.gui.ModTableModel;
import modchecker.model.ModScanResult;
import modchecker.model.Verdict;
import modchecker.online.Hashes;
import modchecker.online.OnlineCheckResult;
import modchecker.online.OnlineChecker;
import modchecker.online.OnlineStatus;
import modchecker.report.ModReport;
import modchecker.report.ReportPrinter;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/** Проверки только на локальном HTTP-сервере. Код модов не выполняется. */
public final class QuickCheckSelfTest {
    private QuickCheckSelfTest() {
    }

    public static void batches(Path temp) throws Exception {
        Path dir = Files.createDirectories(temp.resolve("quick-batches"));
        List<Path> files = new ArrayList<>();
        for (int i = 0; i < 103; i++) {
            Path file = dir.resolve("mod-" + i + ".jar");
            // Намеренно не ZIP: быстрая проверка не должна разбирать архив.
            Files.writeString(file, "not a zip: " + (i == 2 ? 0 : i));
            files.add(file);
        }
        try (Sites sites = new Sites()) {
            sites.modrinth.add(Hashes.sha1(files.get(0)));
            sites.curseforge.put(Hashes.curseForgeFingerprint(files.get(1)), Hashes.sha1(files.get(1)));
            AtomicInteger published = new AtomicInteger();
            AtomicInteger hashed = new AtomicInteger();
            List<ModReport> reports = ScanBatch.checkSites(files, sites.checker("test-key"),
                    (done, total, report) -> published.incrementAndGet(),
                    (done, total) -> hashed.incrementAndGet());
            require(reports.size() == 103 && published.get() == 103 && hashed.get() == 103,
                    "потеряны файлы или события прогресса");
            require(sites.mrRequests.get() == 2 && sites.cfRequests.get() == 2,
                    "ожидалось по два пакетных запроса, а не запрос на каждый файл");
            for (int i = 0; i < reports.size(); i++) {
                ModReport report = reports.get(i);
                require(report.scan().file().equals(files.get(i)), "изменён порядок файлов");
                require(!report.fullScan() && !report.scan().hasError()
                                && report.scan().findings().isEmpty(),
                        "быстрая проверка не должна разбирать даже повреждённый JAR");
                require(report.online().confirmed() == (i <= 2), "неверное подтверждение файла " + i);
                require(report.needsFullScan() == (i > 2), "неверный список для полной проверки");
            }
            require(reports.get(1).online().curseForge() == OnlineStatus.CONFIRMED,
                    "не найден точный ответ CurseForge");
        }
        // Удаление пробелов даёт одинаковый отпечаток, но SHA-1 разный.
        Path spaced = Files.writeString(dir.resolve("spaced.jar"), "a b");
        Path plain = Files.writeString(dir.resolve("plain.jar"), "ab");
        require(Hashes.curseForgeFingerprint(spaced) == Hashes.curseForgeFingerprint(plain),
                "фикстуры должны иметь одинаковый отпечаток");
        try (Sites sites = new Sites()) {
            sites.curseforge.put(Hashes.curseForgeFingerprint(plain), Hashes.sha1(plain));
            List<ModReport> reports = ScanBatch.checkSites(List.of(spaced, plain),
                    sites.checker("test-key"), null, null);
            require(!reports.get(0).online().confirmed() && reports.get(1).online().confirmed(),
                    "совпадения отпечатка без SHA-1 недостаточно для подтверждения");
        }
    }

    public static void failures(Path temp) throws Exception {
        Path file = Files.writeString(temp.resolve("quick-offline.jar"), "sample data");
        try (Sites sites = new Sites()) {
            ModReport report = ScanBatch.checkSites(List.of(file), sites.checker(""), null, null).get(0);
            require(sites.cfRequests.get() == 0, "без ключа запрос к CurseForge запрещён");
            require(report.online().modrinth() == OnlineStatus.NOT_FOUND
                            && report.online().curseForge() == OnlineStatus.SKIPPED
                            && report.statusLabel().equals("НЕТ ПОДТВЕРЖДЕНИЯ"),
                    "пропущенный сайт нельзя называть проверенным");
            require(report.needsFullScan(), "полная проверка должна быть доступна");
        }
        for (boolean malformed : List.of(false, true)) {
            try (Sites sites = new Sites()) {
                sites.status = malformed ? 200 : 503;
                sites.malformed = malformed;
                ModReport report = ScanBatch.checkSites(List.of(file),
                        sites.checker("test-key"), null, null).get(0);
                require(report.online().modrinth() == OnlineStatus.SKIPPED
                                && report.online().curseForge() == OnlineStatus.SKIPPED
                                && report.statusLabel().equals("ПРОВЕРКА НЕДОСТУПНА"),
                        "сбой сети/ответа не означает отсутствие на сайтах");
            }
        }
        try (Sites sites = new Sites()) {
            sites.cfStatus = 403;
            ModReport report = ScanBatch.checkSites(List.of(file),
                    sites.checker("test-key"), null, null).get(0);
            require(report.online().curseForge() == OnlineStatus.INVALID_KEY,
                    "ошибка ключа должна быть отдельным статусом");
        }
        try (Sites sites = new Sites()) {
            Path missing = temp.resolve("missing-quick.jar");
            ModReport report = ScanBatch.checkSites(List.of(missing),
                    sites.checker("test-key"), null, null).get(0);
            require(report.scan().hasError() && sites.mrRequests.get() == 0
                            && sites.cfRequests.get() == 0,
                    "нечитаемый файл должен дать ошибку без сетевых запросов");
        }
    }

    public static void fullScan(Path extraDir) throws Exception {
        Path rat = extraDir.resolve("fake_visual_rat.jar");
        try (Sites sites = new Sites()) {
            ModReport quick = ScanBatch.checkSites(List.of(rat), sites.checker(""), null, null).get(0);
            require(!quick.fullScan() && quick.needsFullScan()
                            && !quick.statusLabel().equals("ОК") && quick.scan().findings().isEmpty(),
                    "проверка хеша не должна выдавать результат анализа RAT");
            ModReport full = ScanBatch.scan(List.of(rat), sites.checker(""), null).get(0);
            require(full.fullScan() && !full.needsFullScan()
                            && full.scan().verdict() == Verdict.DANGEROUS && full.scan().points() == 21,
                    "полная проверка после быстрой должна обнаружить RAT с прежними очками");
        }
    }

    public static void presentation() {
        ModScanResult scan = new ModScanResult(Path.of("confirmed.jar"));
        scan.markOnlineConfirmed();
        ModReport quick = new ModReport(scan, new OnlineCheckResult("a".repeat(40),
                OnlineStatus.CONFIRMED, OnlineStatus.SKIPPED), false);
        ModReport pending = new ModReport(new ModScanResult(Path.of("pending.jar")),
                new OnlineCheckResult("b".repeat(40), OnlineStatus.NOT_FOUND, OnlineStatus.NOT_FOUND), false);
        ModTableModel model = new ModTableModel();
        model.setReports(List.of(quick, pending));
        require(model.getValueAt(0, 1).equals("ПОДТВЕРЖДЁН НА САЙТЕ")
                        && model.getValueAt(0, 2) == null,
                "без анализа нельзя показывать ОК и ноль очков");
        var sorter = ModTableModel.createSorter(model);
        sorter.sort();
        require(sorter.convertRowIndexToModel(0) == 1,
                "неподтверждённый файл должен быть выше подтверждённого");
        String report = ReportPrinter.format(List.of(quick, pending));
        require(report.contains("Код мода не анализировался")
                        && !report.contains("Находки: нет") && !report.contains("Очки: 0")
                        && !report.contains("ОК: 1") && report.contains("Подтверждено на сайтах: 1"),
                "отчёт не должен представлять проверку сайтов как анализ кода");
        ModReport full = new ModReport(scan, quick.online());
        model.setReports(List.of(full));
        require(model.getValueAt(0, 1).equals("ОК") && model.getValueAt(0, 2).equals(0),
                "полная проверка должна сохранять прежнее отображение");
    }

    private static void require(boolean value, String message) {
        if (!value) throw new IllegalStateException(message);
    }

    static final class Sites implements AutoCloseable {
        final Set<String> modrinth = new HashSet<>();
        final Map<Long, String> curseforge = new HashMap<>();
        final AtomicInteger mrRequests = new AtomicInteger();
        final AtomicInteger cfRequests = new AtomicInteger();
        final HttpServer server;
        int status = 200;
        int cfStatus = 200;
        boolean malformed;

        Sites() throws IOException {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/mr", exchange -> respond(exchange, false));
            server.createContext("/cf", exchange -> respond(exchange, true));
            server.start();
        }

        OnlineChecker checker(String key) {
            String base = "http://127.0.0.1:" + server.getAddress().getPort();
            return new OnlineChecker(HttpClient.newHttpClient(), key,
                    URI.create(base + "/mr"), URI.create(base + "/cf"));
        }

        private void respond(HttpExchange exchange, boolean cf) throws IOException {
            try {
                (cf ? cfRequests : mrRequests).incrementAndGet();
                JsonObject request = JsonParser.parseString(new String(
                        exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)).getAsJsonObject();
                JsonObject root = new JsonObject();
                if (cf) {
                    JsonArray matches = new JsonArray();
                    for (var value : request.getAsJsonArray("fingerprints")) {
                        long fingerprint = value.getAsLong();
                        if (curseforge.containsKey(fingerprint)) {
                            JsonObject hash = new JsonObject();
                            hash.addProperty("algo", 1);
                            hash.addProperty("value", curseforge.get(fingerprint));
                            JsonArray hashes = new JsonArray(); hashes.add(hash);
                            JsonObject file = new JsonObject();
                            file.addProperty("fileFingerprint", fingerprint); file.add("hashes", hashes);
                            JsonObject match = new JsonObject(); match.add("file", file); matches.add(match);
                        }
                    }
                    JsonObject data = new JsonObject(); data.add("exactMatches", matches); root.add("data", data);
                } else {
                    for (var hash : request.getAsJsonArray("hashes")) {
                        if (modrinth.contains(hash.getAsString())) root.add(hash.getAsString(), new JsonObject());
                    }
                }
                byte[] body = (malformed ? "not-json" : root.toString()).getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(status != 200 ? status : (cf ? cfStatus : 200), body.length);
                exchange.getResponseBody().write(body);
            } finally {
                exchange.close();
            }
        }

        @Override public void close() { server.stop(0); }
    }
}