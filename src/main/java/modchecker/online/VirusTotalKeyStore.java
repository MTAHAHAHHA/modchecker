package modchecker.online;

import java.io.IOException;
import java.nio.file.Path;

public final class VirusTotalKeyStore {
    private VirusTotalKeyStore() { }
    public static Path defaultKeyFile() { return LocalFiles.directory().resolve("virustotal_key.txt"); }
    public static String loadDefault() { return OnlineChecker.readKey(defaultKeyFile()); }
    public static void saveDefault(String key) throws IOException { CurseForgeKeyStore.save(defaultKeyFile(), key); }
    public static boolean deleteDefault() throws IOException { return CurseForgeKeyStore.delete(defaultKeyFile()); }
}