package modchecker.online;

import java.nio.file.Path;

public final class LocalFiles {
    private LocalFiles() { }
    public static Path directory() {
        String appData = System.getenv("APPDATA");
        return appData != null && !appData.isBlank() ? Path.of(appData, "modchecker")
                : Path.of(System.getProperty("user.home", "."), ".modchecker");
    }
}