package modchecker.online;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import modchecker.model.ModScanResult;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;

/**
 * Проверка SHA-1 и отпечатка CurseForge через официальные API.
 *
 * Сетевые ошибки и отсутствие ключа не считаются подтверждением:
 * в таких случаях сайт получает статус "проверка пропущена".
 */
public final class OnlineChecker {

    public static final String USER_AGENT = "modchecker/1.0";

    private static final URI MODRINTH_URI =
            URI.create("https://api.modrinth.com/v2/version_files");
    private static final URI CURSEFORGE_URI =
            URI.create("https://api.curseforge.com/v1/fingerprints/432");
    private static final URI CURSEFORGE_KEY_TEST_URI =
            URI.create("https://api.curseforge.com/v1/games/432");

    private final HttpClient http;
    private final String curseForgeKey;
    private final URI modrinthUri;
    private final URI curseForgeUri;

    private boolean modrinthUnavailable;
    private boolean curseForgeUnavailable;
    private boolean curseForgeKeyRejected;

    public OnlineChecker() {
        this(newHttpClient(), readDefaultKey(), MODRINTH_URI, CURSEFORGE_URI);
    }

    public OnlineChecker(Path keyFile) {
        this(newHttpClient(), readKey(keyFile), MODRINTH_URI, CURSEFORGE_URI);
    }

    /**
     * GUI передаёт ключ из поля. Пустая строка означает "без ключа",
     * старый поиск по файлам при этом не используется.
     */
    public OnlineChecker(String curseForgeKey) {
        this(newHttpClient(), normalizeKey(curseForgeKey), MODRINTH_URI, CURSEFORGE_URI);
    }

    private static String normalizeKey(String key) {
        if (key == null) {
            return null;
        }
        String normalized = key.replace("\uFEFF", "").trim();
        return normalized.isEmpty() ? null : normalized;
    }

    private static HttpClient newHttpClient() {
        return HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    private OnlineChecker(HttpClient http, String curseForgeKey,
                          URI modrinthUri, URI curseForgeUri) {
        this.http = http;
        this.curseForgeKey = curseForgeKey;
        this.modrinthUri = modrinthUri;
        this.curseForgeUri = curseForgeUri;
    }

    public OnlineCheckResult check(Path jar, ModScanResult scan) {
        String sha1 = null;
        try {
            sha1 = Hashes.sha1(jar);
        } catch (IOException ignored) {
            // В отчёте будет "не удалось вычислить".
        }

        if (scan.hasError()) {
            return new OnlineCheckResult(
                    sha1, OnlineStatus.SKIPPED, OnlineStatus.SKIPPED);
        }

        OnlineStatus modrinth = checkModrinth(sha1);

        OnlineStatus curseForge = OnlineStatus.SKIPPED;
        try {
            long fingerprint = Hashes.curseForgeFingerprint(jar);
            curseForge = checkCurseForge(fingerprint);
        } catch (IOException ignored) {
            // Файл уже прочитан сканером; если хеш не посчитался, проверка пропущена.
        }

        OnlineCheckResult result = new OnlineCheckResult(sha1, modrinth, curseForge);
        if (result.confirmed()) {
            scan.markOnlineConfirmed();
        }
        return result;
    }

    private OnlineStatus checkModrinth(String sha1) {
        if (sha1 == null || sha1.isBlank() || modrinthUnavailable) {
            return OnlineStatus.SKIPPED;
        }

        JsonObject body = new JsonObject();
        JsonArray hashes = new JsonArray();
        hashes.add(sha1);
        body.add("hashes", hashes);
        body.addProperty("algorithm", "sha1");

        HttpRequest request = HttpRequest.newBuilder(modrinthUri)
                .timeout(Duration.ofSeconds(5))
                .header("User-Agent", USER_AGENT)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        body.toString(), StandardCharsets.UTF_8))
                .build();

        try {
            HttpResponse<String> response = http.send(
                    request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() == 200) {
                return parseModrinthResponse(sha1, response.body());
            }
            if (response.statusCode() == 404) {
                return OnlineStatus.NOT_FOUND;
            }
            return OnlineStatus.SKIPPED;
        } catch (IOException e) {
            modrinthUnavailable = true;
            return OnlineStatus.SKIPPED;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            modrinthUnavailable = true;
            return OnlineStatus.SKIPPED;
        }
    }

    /**
     * Публичный метод нужен для автотеста отсутствия ключа: сеть при этом
     * не используется.
     */
    public OnlineStatus checkCurseForge(long fingerprint) {
        if (curseForgeKey == null || curseForgeKey.isBlank()) {
            return OnlineStatus.SKIPPED;
        }
        if (curseForgeKeyRejected) {
            return OnlineStatus.INVALID_KEY;
        }
        if (curseForgeUnavailable) {
            return OnlineStatus.SKIPPED;
        }

        JsonObject body = new JsonObject();
        JsonArray fingerprints = new JsonArray();
        fingerprints.add(fingerprint);
        body.add("fingerprints", fingerprints);

        HttpRequest request = HttpRequest.newBuilder(curseForgeUri)
                .timeout(Duration.ofSeconds(5))
                .header("User-Agent", USER_AGENT)
                .header("x-api-key", curseForgeKey)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        body.toString(), StandardCharsets.UTF_8))
                .build();

        try {
            HttpResponse<String> response = http.send(
                    request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            int statusCode = response.statusCode();
            if (statusCode == 403) {
                curseForgeKeyRejected = true;
                return OnlineStatus.INVALID_KEY;
            }
            if (statusCode == 200) {
                return parseCurseForgeResponse(statusCode, response.body());
            }
            return OnlineStatus.SKIPPED;
        } catch (IOException e) {
            curseForgeUnavailable = true;
            return OnlineStatus.SKIPPED;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            curseForgeUnavailable = true;
            return OnlineStatus.SKIPPED;
        }
    }

    /**
     * Тестовый запрос для кнопки "Проверить ключ". Ключ не попадает
     * ни в сообщения, ни в исключения.
     */
    public KeyCheckStatus checkKey() {
        if (curseForgeKey == null || curseForgeKey.isBlank()) {
            return KeyCheckStatus.EMPTY;
        }

        HttpRequest request = HttpRequest.newBuilder(CURSEFORGE_KEY_TEST_URI)
                .timeout(Duration.ofSeconds(5))
                .header("User-Agent", USER_AGENT)
                .header("x-api-key", curseForgeKey)
                .header("Accept", "application/json")
                .GET()
                .build();

        try {
            HttpResponse<String> response = http.send(
                    request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return parseKeyCheckResponse(response.statusCode());
        } catch (IOException e) {
            return KeyCheckStatus.NO_NETWORK;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return KeyCheckStatus.NO_NETWORK;
        }
    }

    public static KeyCheckStatus parseKeyCheckResponse(int statusCode) {
        if (statusCode == 200) {
            return KeyCheckStatus.WORKING;
        }
        if (statusCode == 403) {
            return KeyCheckStatus.INVALID;
        }
        return KeyCheckStatus.ERROR;
    }

    /**
     * Был ли сетевой сбой при проверке Modrinth или CurseForge.
     */
    public boolean hadNetworkError() {
        return modrinthUnavailable || curseForgeUnavailable;
    }

    public static OnlineStatus parseModrinthResponse(String sha1, String responseBody) {
        if (sha1 == null || sha1.isBlank()
                || responseBody == null || responseBody.isBlank()) {
            return OnlineStatus.SKIPPED;
        }

        try {
            JsonElement parsed = JsonParser.parseString(responseBody);
            if (!parsed.isJsonObject()) {
                return OnlineStatus.SKIPPED;
            }

            JsonObject root = parsed.getAsJsonObject();
            if (root.has(sha1) && root.get(sha1).isJsonObject()) {
                return OnlineStatus.CONFIRMED;
            }

            for (Map.Entry<String, JsonElement> entry : root.entrySet()) {
                if (entry.getKey().equalsIgnoreCase(sha1)
                        && entry.getValue().isJsonObject()) {
                    return OnlineStatus.CONFIRMED;
                }
            }
            return OnlineStatus.NOT_FOUND;
        } catch (RuntimeException e) {
            return OnlineStatus.SKIPPED;
        }
    }

    public static OnlineStatus parseCurseForgeResponse(int statusCode, String responseBody) {
        if (statusCode == 403) {
            return OnlineStatus.INVALID_KEY;
        }
        if (statusCode != 200 || responseBody == null || responseBody.isBlank()) {
            return OnlineStatus.SKIPPED;
        }

        try {
            JsonElement parsed = JsonParser.parseString(responseBody);
            if (!parsed.isJsonObject()) {
                return OnlineStatus.SKIPPED;
            }

            JsonObject data = parsed.getAsJsonObject().getAsJsonObject("data");
            if (data == null) {
                return OnlineStatus.SKIPPED;
            }

            JsonArray exactMatches = data.getAsJsonArray("exactMatches");
            if (exactMatches == null) {
                return OnlineStatus.SKIPPED;
            }
            return exactMatches.size() > 0
                    ? OnlineStatus.CONFIRMED
                    : OnlineStatus.NOT_FOUND;
        } catch (RuntimeException e) {
            return OnlineStatus.SKIPPED;
        }
    }

    /**
     * Основной поиск: сначала curseforge_key.txt в папке запуска,
     * затем ~/.modchecker/curseforge_key.txt (переживает gradlew clean).
     */
    public static String readDefaultKey() {
        Path workingDirectory = Path.of("").toAbsolutePath().normalize();
        String home = System.getProperty("user.home");
        Path userHome = home == null || home.isBlank() ? null : Path.of(home);
        return readKeyFrom(workingDirectory, userHome);
    }

    public static String readKeyFrom(Path workingDirectory, Path userHome) {
        if (workingDirectory == null) {
            return null;
        }

        String local = readKey(workingDirectory.resolve("curseforge_key.txt"));
        if (local != null) {
            return local;
        }
        if (userHome == null) {
            return null;
        }
        return readKey(userHome.resolve(".modchecker").resolve("curseforge_key.txt"));
    }

    public static String readKey(Path keyFile) {
        try {
            if (!Files.isRegularFile(keyFile)) {
                return null;
            }
            String key = Files.readString(keyFile, StandardCharsets.UTF_8)
                    .replace("\uFEFF", "")
                    .trim();
            return key.isEmpty() ? null : key;
        } catch (IOException e) {
            return null;
        }
    }
}
