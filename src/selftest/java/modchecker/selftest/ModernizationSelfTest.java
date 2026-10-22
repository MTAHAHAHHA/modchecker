package modchecker.selftest;

import com.google.gson.*;
import com.sun.net.httpserver.HttpServer;
import modchecker.gui.ResultFilters;
import modchecker.model.*;
import modchecker.online.*;
import modchecker.report.*;
import modchecker.scan.*;
import java.io.*;
import java.net.*;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import java.util.zip.*;

/** Архивы читаются как данные; сеть заменена локальным HTTP-сервером. */
public final class ModernizationSelfTest {
    private static final Instant NOW = Instant.parse("2026-10-22T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private ModernizationSelfTest() { }

    public static void limits(Path temp, String kind) throws Exception {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        ScanLimits limits;
        switch (kind) {
            case "entry" -> {
                entries.put("large.bin", new byte[2048]);
                limits = new ScanLimits(100, 1024, 100_000, 2, 10_000, 1024);
            }
            case "total" -> {
                entries.put("a.bin", new byte[2048]); entries.put("b.bin", new byte[2048]);
                limits = new ScanLimits(100, 4096, 3000, 2, 10_000, 1024);
            }
            case "count" -> {
                entries.put("a.txt", new byte[0]); entries.put("b.txt", new byte[0]);
                limits = new ScanLimits(1, 4096, 100_000, 2, 10_000, 1024);
            }
            case "class" -> {
                entries.put("Large.class", new byte[2048]);
                limits = new ScanLimits(100, 4096, 100_000, 2, 10_000, 1024);
            }
            case "nested" -> {
                entries.put("META-INF/jars/library.jar", zip(Map.of("bomb/", new byte[4096])));
                limits = new ScanLimits(100, 1024, 100_000, 2, 10_000, 1024);
            }
            default -> throw new IllegalArgumentException(kind);
        }
        Path jar = temp.resolve("limit-" + kind + ".jar");
        Files.write(jar, zip(entries));
        var result = new ScanService(limits).scan(jar);
        require(result.hasError() && result.verdict() == Verdict.ERROR, "лимит ошибочно дал чистый результат: " + kind);
        require(result.error().contains("Проверка не завершена"), "не объяснена неполная проверка");
    }

    public static void timeLimit(Path temp) throws Exception {
        var limits = new ScanLimits(10, 100, 1000, 2, 1, 100);
        boolean timeout = false;
        try { limits.checkTime(System.nanoTime() - 10_000_000); }
        catch (ScanLimitException e) { timeout = true; }
        require(timeout, "не сработал бюджет времени");
        Path jar = temp.resolve("interrupted.jar"); Files.write(jar, zip(Map.of("a", new byte[1])));
        Thread.currentThread().interrupt();
        try { require(new ScanService().scan(jar).hasError(), "прерванная проверка выглядит успешной"); }
        finally { Thread.interrupted(); }
    }

    public static void nativeFiles(Path temp) throws Exception {
        byte[] nativeBytes = "MZ test bytes; never execute".getBytes(StandardCharsets.UTF_8);
        Path jar = temp.resolve("natives.jar");
        Files.write(jar, zip(Map.of("lib/test.DLL", nativeBytes, "lib/test.so", nativeBytes,
                "readme.txt", nativeBytes, "META-INF/jars/lib.jar", zip(Map.of("bin/test.exe", nativeBytes)))));
        var files = NativeFileScanner.collect(jar);
        String sha = Hashes.toHex(MessageDigest.getInstance("SHA-256").digest(nativeBytes));
        require(files.size() == 3 && files.stream().allMatch(file -> file.sha256().equals(sha) && file.size() == nativeBytes.length), "ошибка хеша нативных файлов");
        require(files.stream().anyMatch(file -> file.location().contains("!/bin/test.exe")), "потерян путь вложенного файла");
        var result = new ScanService().scan(jar);
        require(result.hasEvidenceRule(17) && !result.hasEvidenceRule(24), "изменена логика легальных вложенных библиотек");
    }

    public static void vtFound(Path temp) throws Exception {
        try (var mock = new VtMock()) {
            Path cache = Files.createTempDirectory(temp, "vt-found");
            var client = mock.client(cache, CLOCK);
            var result = client.check(sha(1));
            require(result.status() == VtResult.Status.FOUND && result.malicious() == 2 && result.suspicious() == 1 && result.total() == 10, "потеряны счётчики VirusTotal");
            require(mock.requests == 1 && mock.getOnly && mock.correctKey, "нужен только GET по хешу с ключом");
            require(client.check(sha(1)).cached() && mock.requests == 1, "кэш не исключает повторный запрос");
            require(mock.client(cache, CLOCK).check(sha(1)).cached() && mock.requests == 1, "кэш потерян между экземплярами");
        }
    }
    public static void vtMissing(Path temp) throws Exception {
        try (var mock = new VtMock()) {
            mock.status = 404;
            Path cache = Files.createTempDirectory(temp, "vt-missing");
            var client = mock.client(cache, CLOCK);
            require(client.check(sha(2)).status() == VtResult.Status.NOT_FOUND, "404 должен означать отсутствие данных");
            require(client.check(sha(2)).cached() && mock.requests == 1, "не кэшируется отсутствие данных");
            mock.client(cache, Clock.fixed(NOW.plusSeconds(3601), ZoneOffset.UTC)).check(sha(2));
            require(mock.requests == 2, "кэш отсутствующих данных не истёк через час");
            var noKey = new VirusTotalClient(HttpClient.newHttpClient(), "", mock.uri(), Files.createTempDirectory(temp, "vt-no-key"), CLOCK);
            require(noKey.check(sha(2)).status() == VtResult.Status.NO_KEY && mock.requests == 2, "ушёл запрос без ключа");
        }
    }
    public static void vtErrors(Path temp) throws Exception {
        try (var mock = new VtMock()) {
            for (int status : new int[]{401, 403, 429, 500}) {
                mock.status = status;
                var result = mock.client(Files.createTempDirectory(temp, "vt-error-" + status), CLOCK).check(sha(3));
                var expected = status == 429 ? VtResult.Status.RATE_LIMITED : status == 500 ? VtResult.Status.UNAVAILABLE : VtResult.Status.INVALID_KEY;
                require(result.status() == expected, "ошибочный статус " + status);
            }
            mock.status = 200; mock.body = "not-json";
            require(mock.client(Files.createTempDirectory(temp, "vt-bad-json"), CLOCK).check(sha(3)).status() == VtResult.Status.INVALID_RESPONSE, "испорченный JSON выглядит успешным");
            mock.body = "{\"data\":{\"id\":\"wrong\",\"attributes\":{}}}";
            require(mock.client(Files.createTempDirectory(temp, "vt-wrong-hash"), CLOCK).check(sha(3)).status() == VtResult.Status.INVALID_RESPONSE, "принят чужой хеш");
        }
    }
    public static void vtQuota(Path temp) throws Exception {
        try (var mock = new VtMock()) {
            Path cache = Files.createTempDirectory(temp, "vt-quota");
            for (int i = 0; i < 4; i++) require(mock.client(cache, CLOCK).check(sha(10 + i)).status() == VtResult.Status.FOUND, "раннее ограничение");
            require(mock.client(cache, CLOCK).check(sha(20)).status() == VtResult.Status.RATE_LIMITED && mock.requests == 4, "превышен лимит 4/мин между экземплярами");
            require(mock.client(cache, CLOCK).check(sha(10)).cached() && mock.requests == 4, "лимит заблокировал доступный кэш");
            require(mock.client(cache, Clock.fixed(NOW.plusSeconds(61), ZoneOffset.UTC)).check(sha(20)).status() == VtResult.Status.FOUND, "лимит не освобождается");
            Path daily = Files.createTempDirectory(temp, "vt-daily");
            JsonArray budget = new JsonArray();
            for (int i = 0; i < 500; i++) budget.add(NOW.minusSeconds(120 + i).toEpochMilli());
            Files.writeString(daily.resolve("request-budget.json"), budget.toString());
            require(mock.client(daily, CLOCK).check(sha(30)).status() == VtResult.Status.RATE_LIMITED && mock.requests == 5, "превышен дневной бюджет");
        }
    }
    public static void vtNoVerdict(Path temp) throws Exception {
        var scan = new ModScanResult(Path.of("library.jar"));
        scan.addFinding(new Finding(17, "DLL", 4, "файл lib.dll", "dll"));
        var report = new ModReport(scan, new OnlineCheckResult("abc", OnlineStatus.NOT_FOUND, OnlineStatus.SKIPPED));
        var verdict = scan.verdict();
        var updated = report.withNativeReports(List.of(new NativeFileReport(new NativeFileInfo("lib.dll", sha(1), 10),
                new VtResult(VtResult.Status.FOUND, 0, 0, 70, 1, CLOCK.millis(), false))));
        require(updated.scan().points() == 4 && updated.scan().verdict() == verdict && updated.scan().hasEvidenceRule(17), "VirusTotal изменил правило/вердикт");
        require(ReportPrinter.formatMod(updated).contains("SHA-256") && ReportPrinter.formatMod(updated).contains("не гарантирует безопасность"), "нет пояснения VirusTotal");
    }
    public static void filtersAndExport() {
        var scan = new ModScanResult(Path.of("library[1].jar"));
        scan.addFinding(new Finding(12, "Загрузка", 4, "Main.class", "main"));
        scan.addFinding(new Finding(17, "Нативный файл", 4, "META-INF/jars/lib.jar!/native.dll", "dll"));
        var report = new ModReport(scan, new OnlineCheckResult("abc", OnlineStatus.CONFIRMED, OnlineStatus.SKIPPED));
        require(ResultFilters.matches(report, "[1]", "Все результаты", 17, "Вложенные JAR"), "буквальный поиск или источник потерян");
        require(!ResultFilters.matches(report, "", "Все результаты", 12, "Вложенные JAR"), "правило и источник относятся к разным находкам");
        require(ResultFilters.matches(report, "NATIVE.DLL", "Все результаты", 0, "Любой источник"), "поиск не видит место");
        var quick = new ModReport(new ModScanResult(Path.of("quick.jar")), report.online(), false);
        require(!ResultFilters.matches(quick, "", "Только полная проверка", 0, "Любой источник"), "быстрая строка видна в полной");
        JsonArray rows = JsonParser.parseString(ReportJson.format(List.of(report, quick))).getAsJsonObject().getAsJsonArray("results");
        require(rows.size() == 2 && rows.get(1).getAsJsonObject().get("points").isJsonNull(), "JSON приписал очки быстрой проверке");
        require(rows.get(0).getAsJsonObject().getAsJsonArray("findings").get(1).getAsJsonObject().get("source").getAsString().equals("nested-jar"), "JSON потерял источник");
        require(scan.points() == 8 && quick.scan().findings().isEmpty(), "фильтрация изменила результат");
    }
    public static void streamingHash(Path temp) throws Exception {
        Random random = new Random(42); Path file = temp.resolve("stream-hash.bin");
        for (int size : new int[]{0, 1, 2, 3, 4, 5, 8191, 65535, 65536, 65537, 1_000_000}) {
            byte[] data = new byte[size]; random.nextBytes(data); Files.write(file, data);
            require(Hashes.curseForgeFingerprint(file) == Hashes.curseForgeFingerprint(data), "изменён Murmur2 при длине " + size);
        }
        Files.write(file, new byte[]{9, 10, 13, 32});
        require(Hashes.curseForgeFingerprint(file) == Hashes.curseForgeFingerprint(new byte[0]), "пробельные байты учтены в длине");
    }

    private static byte[] zip(Map<String, byte[]> entries) throws IOException {
        var bytes = new ByteArrayOutputStream();
        try (var out = new ZipOutputStream(bytes)) {
            for (var entry : entries.entrySet()) { out.putNextEntry(new ZipEntry(entry.getKey())); out.write(entry.getValue()); out.closeEntry(); }
        }
        return bytes.toByteArray();
    }
    private static String sha(int number) { return String.format("%064x", number); }
    private static void require(boolean value, String message) { if (!value) throw new IllegalStateException(message); }
    private static final class VtMock implements AutoCloseable {
        final HttpServer server;
        int status = 200, requests;
        String body;
        boolean getOnly = true, correctKey = true;
        VtMock() throws IOException {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/files/", exchange -> {
                requests++; getOnly &= exchange.getRequestMethod().equals("GET") && exchange.getRequestBody().readAllBytes().length == 0;
                correctKey &= "test-only-key".equals(exchange.getRequestHeaders().getFirst("x-apikey"));
                String hash = exchange.getRequestURI().getPath().substring("/files/".length());
                String response = body != null ? body : "{\"data\":{\"id\":\"" + hash + "\",\"attributes\":{\"last_analysis_date\":1700000000,\"last_analysis_stats\":{\"malicious\":2,\"suspicious\":1,\"undetected\":7}}}}";
                byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(status, bytes.length);
                try (var out = exchange.getResponseBody()) { out.write(bytes); }
            });
            server.start();
        }
        URI uri() { return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/files/"); }
        VirusTotalClient client(Path cache, Clock clock) { return new VirusTotalClient(HttpClient.newHttpClient(), "test-only-key", uri(), cache, clock); }
        public void close() { server.stop(0); }
    }
}
