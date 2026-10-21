package modchecker.scan;

import modchecker.model.Finding;
import modchecker.model.ModScanResult;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Правила 20 и 21: слишком короткие имена классов и не-ASCII имена.
 */
final class ClassNameScanner {

    private ClassNameScanner() {
    }

    static void inspect(List<ArchiveFile> files, ModScanResult result) {
        List<String> names = new ArrayList<>();

        for (ArchiveFile file : files) {
            String lowerName = file.entryName().toLowerCase(Locale.ROOT);
            if (!lowerName.endsWith(".class")) {
                continue;
            }

            String name = file.entryName().replace('\\', '/');
            int slash = name.lastIndexOf('/');
            String simpleName = slash >= 0 ? name.substring(slash + 1) : name;
            simpleName = simpleName.substring(0, simpleName.length() - ".class".length());
            names.add(simpleName);
        }

        if (names.isEmpty()) {
            return;
        }

        if (names.size() >= 10) {
            long shortNames = names.stream().filter(name -> name.length() <= 2).count();
            if (shortNames * 2 >= names.size()) {
                result.addFinding(new Finding(
                        20,
                        "Короткие имена классов",
                        1,
                        "все .class файлы мода",
                        shortNames + " из " + names.size()
                                + " классов имеют имя не длиннее 2 символов: "
                                + summarize(names, 10)
                ));
            }
        }

        List<String> nonAsciiNames = names.stream()
                .filter(name -> name.chars().anyMatch(character -> character > 127))
                .toList();

        if (!nonAsciiNames.isEmpty() && nonAsciiNames.size() * 5 >= names.size()) {
            result.addFinding(new Finding(
                    21,
                    "Не-ASCII символы в именах классов",
                    1,
                    "все .class файлы мода",
                    nonAsciiNames.size() + " из " + names.size()
                            + " классов содержат странные символы: "
                            + summarize(nonAsciiNames, 10)
            ));
        }
    }

    private static String summarize(List<String> names, int limit) {
        if (names.size() <= limit) {
            return String.join(", ", names);
        }
        return String.join(", ", names.subList(0, limit)) + ", ...";
    }
}
