package modchecker.app;

import modchecker.online.LocalFiles;
import modchecker.scan.ScanLimits;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

/** Локальные настройки GUI, отдельно от ключей и результатов проверки. */
public record ScanSettings(boolean unlimitedArchives) {
    public static Path defaultFile() { return LocalFiles.directory().resolve("scan-settings.properties"); }

    public static ScanSettings load(Path file) {
        try {
            if (Files.size(file) > 4096) return new ScanSettings(false);
            Properties values = new Properties();
            try (var reader = Files.newBufferedReader(file)) { values.load(reader); }
            return new ScanSettings("true".equalsIgnoreCase(values.getProperty("unlimitedArchives", "false").trim()));
        } catch (IOException | IllegalArgumentException e) { return new ScanSettings(false); }
    }

    public void save(Path file) throws IOException {
        Path target = file.toAbsolutePath().normalize();
        Files.createDirectories(target.getParent());
        Files.writeString(target, "unlimitedArchives=" + unlimitedArchives + "\n");
    }

    public ScanLimits limits() { return unlimitedArchives ? ScanLimits.UNLIMITED : ScanLimits.DEFAULT; }
}
