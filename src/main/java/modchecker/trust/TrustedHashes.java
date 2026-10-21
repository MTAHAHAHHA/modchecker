package modchecker.trust;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * Ручной список доверенных SHA-1.
 *
 * Читаются два файла:
 * - trusted_hashes.txt рядом с проверяемым jar;
 * - %APPDATA%\modchecker\trusted_hashes.txt
 *   (на других системах ~/.modchecker/trusted_hashes.txt).
 *
 * Формат строки: "SHA-1  комментарий". Пустые строки и строки с # пропускаются.
 * Доверие меняет только вердикт: все находки остаются в отчёте.
 */
public final class TrustedHashes {

    public static final String FILE_NAME = "trusted_hashes.txt";

    private static final String HASH_PATTERN = "[0-9a-f]{40}";

    private TrustedHashes() {
    }

    public record TrustEntry(
            String sha1,
            String comment,
            Path source
    ) {
    }

    /**
     * Файл рядом с модом. Для папки без родителя используется текущая папка.
     */
    public static Path fileNear(Path modFile) {
        Path absolute = modFile.toAbsolutePath().normalize();
        Path parent = absolute.getParent();
        return (parent == null ? Path.of(".") : parent).resolve(FILE_NAME);
    }

    /**
     * Общий файл, который заполняет кнопка "Доверять этому файлу" в GUI.
     */
    public static Path defaultFile() {
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

    /**
     * Ищет хеш сначала рядом с jar, затем в общем файле.
     */
    public static Optional<TrustEntry> find(Path modFile, String sha1) throws IOException {
        String normalized = normalizeHash(sha1);
        if (normalized == null) {
            return Optional.empty();
        }

        Optional<TrustEntry> near = findInFile(fileNear(modFile), normalized);
        if (near.isPresent()) {
            return near;
        }
        return findInFile(defaultFile(), normalized);
    }

    public static Optional<TrustEntry> findInFile(Path file, String sha1)
            throws IOException {
        String normalized = normalizeHash(sha1);
        if (normalized == null || !Files.isRegularFile(file)) {
            return Optional.empty();
        }

        Path source = file.toAbsolutePath().normalize();
        for (String line : Files.readAllLines(source, StandardCharsets.UTF_8)) {
            TrustEntry entry = parseLine(line, source);
            if (entry != null && entry.sha1().equals(normalized)) {
                return Optional.of(entry);
            }
        }
        return Optional.empty();
    }

    /**
     * Добавляет запись, если такого хеша ещё нет. Возвращает true, если файл
     * изменился.
     */
    public static boolean add(Path file, String sha1, String comment) throws IOException {
        String normalized = normalizeHash(sha1);
        if (normalized == null) {
            throw new IOException("неверный SHA-1");
        }

        Path absolute = file.toAbsolutePath().normalize();
        List<String> lines = readLines(absolute);
        if (containsHash(lines, normalized)) {
            return false;
        }

        String safeComment = sanitizeComment(comment);
        lines.add(normalized + (safeComment.isEmpty() ? "" : "  " + safeComment));
        writeLines(absolute, lines);
        return true;
    }

    /**
     * Удаляет все строки с указанным хешем из одного файла.
     */
    public static boolean remove(Path file, String sha1) throws IOException {
        String normalized = normalizeHash(sha1);
        if (normalized == null || !Files.isRegularFile(file)) {
            return false;
        }

        Path absolute = file.toAbsolutePath().normalize();
        List<String> lines = readLines(absolute);
        List<String> remaining = new ArrayList<>();
        boolean removed = false;
        for (String line : lines) {
            TrustEntry entry = parseLine(line, absolute);
            if (entry != null && entry.sha1().equals(normalized)) {
                removed = true;
            } else {
                remaining.add(line);
            }
        }

        if (removed) {
            writeLines(absolute, remaining);
        }
        return removed;
    }

    /**
     * Убирает хеш и из файла рядом с модом, и из общего файла.
     */
    public static int removeEverywhere(Path modFile, String sha1) throws IOException {
        Set<Path> files = new LinkedHashSet<>();
        files.add(fileNear(modFile));
        files.add(defaultFile());

        int removed = 0;
        for (Path file : files) {
            if (remove(file, sha1)) {
                removed++;
            }
        }
        return removed;
    }

    public static boolean isTrusted(Path modFile, String sha1) throws IOException {
        return find(modFile, sha1).isPresent();
    }

    private static TrustEntry parseLine(String line, Path source) {
        if (line == null) {
            return null;
        }
        String value = line.replace("\uFEFF", "").strip();
        if (value.isEmpty() || value.startsWith("#")) {
            return null;
        }

        int separator = firstWhitespace(value);
        String hashPart = separator < 0 ? value : value.substring(0, separator);
        String hash = normalizeHash(hashPart);
        if (hash == null) {
            return null;
        }
        String comment = separator < 0 ? "" : value.substring(separator).strip();
        return new TrustEntry(hash, comment, source);
    }

    private static int firstWhitespace(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (Character.isWhitespace(value.charAt(i))) {
                return i;
            }
        }
        return -1;
    }

    private static boolean containsHash(List<String> lines, String sha1) {
        for (String line : lines) {
            TrustEntry entry = parseLine(line, Path.of(FILE_NAME));
            if (entry != null && entry.sha1().equals(sha1)) {
                return true;
            }
        }
        return false;
    }

    private static List<String> readLines(Path file) throws IOException {
        if (!Files.isRegularFile(file)) {
            return new ArrayList<>();
        }
        return new ArrayList<>(Files.readAllLines(file, StandardCharsets.UTF_8));
    }

    private static void writeLines(Path file, List<String> lines) throws IOException {
        Path parent = file.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.write(file, lines, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE);
    }

    private static String normalizeHash(String sha1) {
        if (sha1 == null) {
            return null;
        }
        String normalized = sha1.replace("\uFEFF", "").strip()
                .toLowerCase(Locale.ROOT);
        return normalized.matches(HASH_PATTERN) ? normalized : null;
    }

    private static String sanitizeComment(String comment) {
        if (comment == null) {
            return "";
        }
        return comment.replace('\r', ' ').replace('\n', ' ').strip();
    }
}
