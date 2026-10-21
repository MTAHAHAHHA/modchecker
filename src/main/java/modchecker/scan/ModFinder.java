package modchecker.scan;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * Общий поиск модов для консольного и графического режимов.
 */
public final class ModFinder {

    private ModFinder() {
    }

    /**
     * Обычный мод или образец, который нельзя запустить двойным кликом.
     */
    public static boolean isModFileName(String fileName) {
        String lowerName = fileName.toLowerCase(Locale.ROOT);
        return lowerName.endsWith(".jar") || lowerName.endsWith(".jar.sample");
    }

    /**
     * Если передан файл - возвращаем его. Если папка - ищем в ней .jar
     * и .jar.sample без захода в подпапки.
     */
    public static List<Path> find(Path target) throws IOException {
        if (!Files.exists(target)) {
            throw new IOException("путь не существует");
        }
        if (Files.isRegularFile(target)) {
            return List.of(target);
        }
        if (!Files.isDirectory(target)) {
            throw new IOException("путь не является файлом или папкой");
        }

        List<Path> result = new ArrayList<>();
        try (var stream = Files.list(target)) {
            stream.filter(Files::isRegularFile)
                    .filter(path -> isModFileName(path.getFileName().toString()))
                    .sorted(Comparator.comparing(path -> path.getFileName().toString()))
                    .forEach(result::add);
        }
        return result;
    }
}
