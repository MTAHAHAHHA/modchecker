package modchecker.scan;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

/**
 * Читает jar как обычный архив. Вложенные jar тоже читаются как данные,
 * максимум на два уровня вглубь. Никакие классы здесь не загружаются.
 */
final class JarWalker {

    private static final int MAX_NESTED_DEPTH = 2;

    private JarWalker() {
    }

    static List<ArchiveFile> read(Path jarFile) throws IOException {
        List<ArchiveFile> files = new ArrayList<>();

        try (ZipFile zip = new ZipFile(jarFile.toFile())) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.isDirectory()) {
                    continue;
                }
                byte[] data;
                try (InputStream input = zip.getInputStream(entry)) {
                    data = input.readAllBytes();
                }
                handleEntry(entry.getName(), data, "", 0, files);
            }
        }

        return files;
    }

    private static void handleEntry(String entryName, byte[] data, String prefix,
                                    int depth, List<ArchiveFile> files) {
        String location = prefix + entryName;

        if (isJar(entryName)) {
            if (depth < MAX_NESTED_DEPTH) {
                readNestedJar(data, location + "!/", depth + 1, files);
            }
            return;
        }

        files.add(new ArchiveFile(entryName, location, data));
    }

    private static void readNestedJar(byte[] jarBytes, String prefix, int depth,
                                      List<ArchiveFile> files) {
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(jarBytes))) {
            boolean hasEntry = false;
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                hasEntry = true;
                if (entry.isDirectory()) {
                    continue;
                }
                byte[] data = zip.readAllBytes();
                handleEntry(entry.getName(), data, prefix, depth, files);
            }

            if (!hasEntry && !looksLikeZip(jarBytes)) {
                throw new IOException("вложенный файл не является zip");
            }
        } catch (IOException ignored) {
            // Битый вложенный jar не должен ломать проверку всего мода.
        }
    }

    private static boolean isJar(String entryName) {
        return entryName.toLowerCase(Locale.ROOT).endsWith(".jar");
    }

    private static boolean looksLikeZip(byte[] data) {
        return data.length >= 2 && data[0] == 'P' && data[1] == 'K';
    }
}
