package modchecker.online;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * Сохранённый ключ CurseForge для GUI.
 *
 * Windows: %APPDATA%\modchecker\curseforge_key.txt
 * Остальные системы: ~/.modchecker/curseforge_key.txt
 *
 * Файл лежит вне build и не удаляется при gradlew clean.
 */
public final class CurseForgeKeyStore {

    private static final String FILE_NAME = "curseforge_key.txt";

    private CurseForgeKeyStore() {
    }

    public static Path defaultKeyFile() {
        String appData = System.getenv("APPDATA");
        if (appData != null && !appData.isBlank()) {
            return Path.of(appData, "modchecker", FILE_NAME);
        }

        String home = System.getProperty("user.home");
        if (home == null || home.isBlank()) {
            home = ".";
        }
        return Path.of(home, ".modchecker", FILE_NAME);
    }

    public static String loadDefault() {
        return load(defaultKeyFile());
    }

    public static String load(Path keyFile) {
        return OnlineChecker.readKey(keyFile);
    }

    public static void saveDefault(String key) throws IOException {
        save(defaultKeyFile(), key);
    }

    public static void save(Path keyFile, String key) throws IOException {
        String normalized = key == null
                ? ""
                : key.replace("\uFEFF", "").trim();

        if (normalized.isEmpty()) {
            Files.deleteIfExists(keyFile);
            return;
        }

        Path absolute = keyFile.toAbsolutePath().normalize();
        Path parent = absolute.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        Files.writeString(absolute, normalized + System.lineSeparator(),
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE);
    }

    public static boolean deleteDefault() throws IOException {
        return delete(defaultKeyFile());
    }

    public static boolean delete(Path keyFile) throws IOException {
        return Files.deleteIfExists(keyFile);
    }
}
