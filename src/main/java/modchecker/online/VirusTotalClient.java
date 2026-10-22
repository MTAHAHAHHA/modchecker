package modchecker.online;

import com.google.gson.*;
import java.io.IOException;
import java.net.URI;
import java.net.http.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Clock;
import java.time.Duration;

/** Только GET по SHA-256. Нет загрузки, запуска или отправки образцов. */
public final class VirusTotalClient {
    private static final Object BUDGET_LOCK = new Object();
    private static final Gson JSON = new Gson();
    private final HttpClient http;
    private final URI endpoint;
    private final String key;
    private final Path cache;
    private final Clock clock;
    private boolean unavailable;

    public VirusTotalClient(String key) {
        this(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build(), key,
                URI.create("https://www.virustotal.com/api/v3/files/"),
                LocalFiles.directory().resolve("virustotal-cache"), Clock.systemUTC());
    }

    public VirusTotalClient(HttpClient http, String key, URI endpoint, Path cache, Clock clock) {
        this.http = http; this.key = key == null ? "" : key.trim();
        this.endpoint = endpoint; this.cache = cache; this.clock = clock;
    }

    public synchronized VtResult check(String sha256) {
        if (sha256 == null || !sha256.matches("[a-fA-F0-9]{64}")) {
            return VtResult.status(VtResult.Status.INVALID_RESPONSE);
        }
        String sha = sha256.toLowerCase(java.util.Locale.ROOT);
        VtResult cached = readCache(sha);
        if (cached != null) return cached;
        if (key.isBlank()) return VtResult.status(VtResult.Status.NO_KEY);
        if (unavailable) return VtResult.status(VtResult.Status.UNAVAILABLE);
        try {
            if (!reserveRequest()) return VtResult.status(VtResult.Status.RATE_LIMITED);
            HttpRequest request = HttpRequest.newBuilder(endpoint.resolve(sha))
                    .timeout(Duration.ofSeconds(15)).header("x-apikey", key)
                    .header("User-Agent", OnlineChecker.USER_AGENT).header("Accept", "application/json")
                    .GET().build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            VtResult result;
            if (response.statusCode() == 404) {
                result = new VtResult(VtResult.Status.NOT_FOUND, 0, 0, 0, 0, clock.millis(), false);
            } else if (response.statusCode() == 401 || response.statusCode() == 403) {
                return VtResult.status(VtResult.Status.INVALID_KEY);
            } else if (response.statusCode() == 429) {
                return VtResult.status(VtResult.Status.RATE_LIMITED);
            } else if (response.statusCode() != 200) {
                unavailable = true;
                return VtResult.status(VtResult.Status.UNAVAILABLE);
            } else {
                if (response.body().length() > 2_000_000) return VtResult.status(VtResult.Status.INVALID_RESPONSE);
                JsonObject data = JsonParser.parseString(response.body()).getAsJsonObject().getAsJsonObject("data");
                if (!sha.equalsIgnoreCase(data.get("id").getAsString())) return VtResult.status(VtResult.Status.INVALID_RESPONSE);
                JsonObject attributes = data.getAsJsonObject("attributes");
                JsonObject stats = attributes.getAsJsonObject("last_analysis_stats");
                int total = 0;
                for (var item : stats.entrySet()) total = Math.addExact(total, count(item.getValue()));
                int malicious = count(stats.get("malicious"));
                int suspicious = count(stats.get("suspicious"));
                if (malicious + suspicious > total) return VtResult.status(VtResult.Status.INVALID_RESPONSE);
                long analyzed = attributes.has("last_analysis_date") ? attributes.get("last_analysis_date").getAsLong() : 0;
                result = new VtResult(VtResult.Status.FOUND, malicious, suspicious, total, analyzed, clock.millis(), false);
            }
            writeCache(sha, result);
            return result;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return VtResult.status(VtResult.Status.UNAVAILABLE);
        } catch (IOException e) {
            unavailable = true;
            return VtResult.status(VtResult.Status.UNAVAILABLE);
        } catch (RuntimeException e) {
            return VtResult.status(VtResult.Status.INVALID_RESPONSE);
        }
    }

    private static int count(JsonElement value) {
        if (value == null) return 0;
        if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isNumber()) throw new IllegalArgumentException();
        int number = value.getAsBigDecimal().intValueExact();
        if (number < 0 || number > 1_000_000) throw new IllegalArgumentException();
        return number;
    }

    /** Журнал не содержит ключа. Блокировка действует и между экземплярами программы. */
    private boolean reserveRequest() throws IOException {
        synchronized (BUDGET_LOCK) {
            Files.createDirectories(cache);
            try (FileChannel channel = FileChannel.open(cache.resolve("request-budget.json"),
                    StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE);
                 var lock = channel.lock()) {
                if (channel.size() > 50_000) throw new IOException("Некорректный журнал лимита");
                ByteBuffer buffer = ByteBuffer.allocate((int) channel.size());
                while (buffer.hasRemaining() && channel.read(buffer) != -1) { }
                String text = new String(buffer.array(), StandardCharsets.UTF_8);
                JsonArray old;
                try { old = text.isBlank() ? new JsonArray() : JsonParser.parseString(text).getAsJsonArray(); }
                catch (RuntimeException e) { throw new IOException("Некорректный журнал лимита"); }
                long now = clock.millis();
                JsonArray active = new JsonArray(); int minute = 0;
                for (JsonElement item : old) {
                    long timestamp = item.getAsLong();
                    if (timestamp > now - 86_400_000L) {
                        active.add(timestamp);
                        if (timestamp > now - 60_000L) minute++;
                    }
                }
                if (minute >= 4 || active.size() >= 500) return false;
                active.add(now);
                byte[] bytes = active.toString().getBytes(StandardCharsets.UTF_8);
                channel.position(0); channel.truncate(0);
                ByteBuffer data = ByteBuffer.wrap(bytes);
                while (data.hasRemaining()) channel.write(data);
                channel.force(true);
                return true;
            }
        }
    }

    private VtResult readCache(String sha) {
        Path file = cache.resolve(sha + ".json");
        try {
            if (!Files.isRegularFile(file) || Files.size(file) > 16_384) return null;
            JsonObject root = JsonParser.parseString(Files.readString(file)).getAsJsonObject();
            if (!sha.equals(root.get("sha256").getAsString())) return null;
            VtResult value = JSON.fromJson(root.get("result"), VtResult.class);
            if (value.status() != VtResult.Status.FOUND && value.status() != VtResult.Status.NOT_FOUND) return null;
            long age = clock.millis() - value.checkedAt();
            long ttl = value.status() == VtResult.Status.FOUND ? 86_400_000L : 3_600_000L;
            if (age < 0 || age > ttl || value.malicious() < 0 || value.suspicious() < 0
                    || value.total() < value.malicious() + value.suspicious()) return null;
            return new VtResult(value.status(), value.malicious(), value.suspicious(), value.total(),
                    value.analyzedAt(), value.checkedAt(), true);
        } catch (IOException | RuntimeException e) { return null; }
    }

    private void writeCache(String sha, VtResult result) {
        try {
            Files.createDirectories(cache);
            JsonObject root = new JsonObject(); root.addProperty("sha256", sha); root.add("result", JSON.toJsonTree(result));
            Path temporary = Files.createTempFile(cache, sha, ".tmp");
            try {
                Files.writeString(temporary, root.toString());
                Files.move(temporary, cache.resolve(sha + ".json"), StandardCopyOption.REPLACE_EXISTING);
            } finally { Files.deleteIfExists(temporary); }
        } catch (IOException ignored) { /* Сбой кэша не меняет полученный отчёт. */ }
    }
}
