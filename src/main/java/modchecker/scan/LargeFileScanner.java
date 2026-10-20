package modchecker.scan;

import modchecker.model.Finding;
import modchecker.model.ModScanResult;
import modchecker.util.Entropy;

import java.util.Locale;
import java.util.Set;

/**
 * Правило 19: большой файл неизвестного типа с очень высокой энтропией.
 */
final class LargeFileScanner {

    private static final Set<String> KNOWN_EXTENSIONS = Set.of(
            ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ogg", ".mp3", ".wav",
            ".woff", ".woff2", ".jar", ".zip", ".gz",
            ".nbt", ".ttf", ".otf", ".class"
    );

    private static final Set<String> SIGNATURE_EXTENSIONS = Set.of(
            ".rsa", ".dsa", ".ec"
    );

    private final ModScanResult result;

    LargeFileScanner(ModScanResult result) {
        this.result = result;
    }

    void inspect(ArchiveFile file) {
        if (result.hasRule(19) || file.data().length < 4096) {
            return;
        }

        String lowerName = file.entryName().toLowerCase(Locale.ROOT);
        if (KNOWN_EXTENSIONS.stream().anyMatch(lowerName::endsWith)
                || isSignatureFile(lowerName)) {
            return;
        }

        double entropy = Entropy.ofBytes(file.data());
        if (entropy >= 7.5) {
            result.addFinding(new Finding(
                    19,
                    "Большой файл с высокой энтропией",
                    2,
                    "файл " + file.location(),
                    String.format(Locale.ROOT,
                            "размер: %d байт, энтропия: %.2f бит",
                            file.data().length, entropy)
            ));
        }
    }

    private static boolean isSignatureFile(String lowerName) {
        return lowerName.startsWith("meta-inf/")
                && SIGNATURE_EXTENSIONS.stream().anyMatch(lowerName::endsWith);
    }
}
