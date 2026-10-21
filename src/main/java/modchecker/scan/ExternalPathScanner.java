package modchecker.scan;

import modchecker.model.Finding;
import modchecker.model.ModScanResult;

import java.util.List;
import java.util.Locale;

/**
 * Правило 15: строки путей к данным пользователя вне игры
 * (APPDATA, AppData, user.home).
 */
final class ExternalPathScanner {

    private static final List<PathMarker> MARKERS = List.of(
            new PathMarker("appdata", "APPDATA / AppData"),
            new PathMarker("user.home", "user.home")
    );

    private final ModScanResult result;

    ExternalPathScanner(ModScanResult result) {
        this.result = result;
    }

    void inspect(String content, String location) {
        if (content == null || content.isEmpty() || result.hasRule(15)) {
            return;
        }

        String lowerCase = content.toLowerCase(Locale.ROOT);
        for (PathMarker marker : MARKERS) {
            if (lowerCase.contains(marker.needle())) {
                result.addFinding(new Finding(
                        15,
                        "Путь к данным пользователя",
                        2,
                        location,
                        "найден путь: " + marker.title()
                ));
                return;
            }
        }
    }

    private record PathMarker(String needle, String title) {
    }
}
