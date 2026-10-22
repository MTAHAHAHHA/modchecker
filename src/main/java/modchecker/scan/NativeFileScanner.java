package modchecker.scan;

import modchecker.online.Hashes;
import java.io.IOException;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class NativeFileScanner {
    private NativeFileScanner() { }
    public static List<NativeFileInfo> collect(Path jar) throws IOException {
        List<NativeFileInfo> result = new ArrayList<>();
        for (ArchiveFile file : JarWalker.read(jar).files()) {
            String name = file.entryName().toLowerCase(Locale.ROOT);
            if (!(name.endsWith(".exe") || name.endsWith(".dll") || name.endsWith(".so") || name.endsWith(".dylib"))) continue;
            try {
                result.add(new NativeFileInfo(file.location(), Hashes.toHex(
                        MessageDigest.getInstance("SHA-256").digest(file.data())), file.data().length));
            } catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
        }
        return List.copyOf(result);
    }
}