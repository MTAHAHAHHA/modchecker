package modchecker.scan;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
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
 * Читает jar как обычный архив. Вложенные jar и .jar.sample тоже читаются
 * как данные, максимум на два уровня вглубь. Никакие классы здесь не загружаются.
 */
final class JarWalker {

    private JarWalker() {
    }

    static JarContents read(Path jarFile) throws IOException {
        return read(jarFile, ScanLimits.DEFAULT, System.nanoTime());
    }

    static JarContents read(Path jarFile, ScanLimits limits, long started) throws IOException {
        Budget budget = new Budget(limits, started);
        if (java.nio.file.Files.size(jarFile) > limits.maxTotalBytes()) {
            throw new ScanLimitException("архив превышает допустимый размер");
        }
        List<ArchiveFile> files = new ArrayList<>();
        List<String> suspiciousJars = new ArrayList<>();

        try (ZipFile zip = new ZipFile(jarFile.toFile())) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                budget.entry();
                if (entry.isDirectory()) {
                    continue;
                }
                byte[] data;
                try (InputStream input = zip.getInputStream(entry)) {
                    data = budget.read(input, entry);
                }
                handleEntry(entry.getName(), data, "", 0, files, suspiciousJars, budget);
            }
        }

        return new JarContents(List.copyOf(files), List.copyOf(suspiciousJars));
    }

    private static void handleEntry(String entryName, byte[] data, String prefix,
                                    int depth, List<ArchiveFile> files,
                                    List<String> suspiciousJars, Budget budget) throws IOException {
        String location = prefix + entryName;

        if (isJar(entryName)) {
            if (isSuspiciousJarLocation(entryName)) {
                suspiciousJars.add(location);
            }
            if (depth < budget.limits.maxNestedDepth()) {
                readNestedJar(data, location + "!/", depth + 1, files, suspiciousJars, budget);
            }
            return;
        }

        files.add(new ArchiveFile(entryName, location, data));
    }

    private static void readNestedJar(byte[] jarBytes, String prefix, int depth,
                                      List<ArchiveFile> files,
                                      List<String> suspiciousJars, Budget budget) throws IOException {
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(jarBytes))) {
            boolean hasEntry = false;
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                hasEntry = true;
                budget.entry();
                if (entry.isDirectory()) {
                    budget.read(zip, entry);
                    continue;
                }
                byte[] data = budget.read(zip, entry);
                handleEntry(entry.getName(), data, prefix, depth, files, suspiciousJars, budget);
            }

            if (!hasEntry && !looksLikeZip(jarBytes)) {
                throw new IOException("вложенный файл не является zip");
            }
        } catch (ScanLimitException limit) {
            throw limit;
        } catch (IOException ignored) {
            // Битый вложенный jar не должен ломать проверку всего мода.
        }
    }

    private static final class Budget {
        private final ScanLimits limits;
        private final long started;
        private int entries;
        private long expanded;

        Budget(ScanLimits limits, long started) { this.limits = limits; this.started = started; }

        void entry() throws ScanLimitException {
            limits.checkTime(started);
            if (++entries > limits.maxEntries()) {
                throw new ScanLimitException("слишком много файлов в архиве (лимит " + limits.maxEntries() + ")");
            }
        }

        byte[] read(InputStream input, ZipEntry entry) throws IOException {
            long maximum = entry.getName().toLowerCase(Locale.ROOT).endsWith(".class")
                    ? Math.min(limits.maxEntryBytes(), limits.maxClassBytes()) : limits.maxEntryBytes();
            if (entry.getSize() > maximum) {
                throw new ScanLimitException("слишком большой файл в архиве: " + entry.getName());
            }
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            long size = 0;
            int count;
            while ((count = input.read(buffer)) != -1) {
                limits.checkTime(started);
                size += count;
                expanded += count;
                if (size > maximum) throw new ScanLimitException("превышен размер файла: " + entry.getName());
                if (expanded > limits.maxTotalBytes()) throw new ScanLimitException("превышен суммарный размер распакованных данных");
                output.write(buffer, 0, count);
            }
            return output.toByteArray();
        }
    }
    private static boolean isJar(String entryName) {
        return ModFinder.isModFileName(entryName);
    }

    /**
     * Легальные вложенные jar лежат в META-INF/jars и META-INF/jarjar.
     * Jar в assets, data, resources или прямо в корне - признак маскировки.
     */
    private static boolean isSuspiciousJarLocation(String entryName) {
        String lower = entryName.replace('\\', '/').toLowerCase(Locale.ROOT);
        if (lower.startsWith("meta-inf/jars/")
                || lower.startsWith("meta-inf/jarjar/")) {
            return false;
        }
        return lower.startsWith("assets/")
                || lower.startsWith("data/")
                || lower.startsWith("resources/")
                || !lower.contains("/");
    }

    private static boolean looksLikeZip(byte[] data) {
        return data.length >= 2 && data[0] == 'P' && data[1] == 'K';
    }
}
