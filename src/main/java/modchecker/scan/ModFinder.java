package modchecker.scan;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Общий поиск модов для консольного и графического режимов.
 */
public final class ModFinder {

    private ModFinder() {
    }

    /**
     * Если передан файл - возвращаем его. Если папка - ищем в ней .jar
     * без захода в подпапки.
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
                    .filter(path -> path.getFileName().toString()
                            .toLowerCase(java.util.Locale.ROOT).endsWith(".jar"))
                    .sorted(Comparator.comparing(path -> path.getFileName().toString()))
                    .forEach(result::add);
        }
        return result;
    }
}
