package modchecker.scan;

import modchecker.model.Finding;
import modchecker.model.ModScanResult;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Правила 25, 26 и 28: имена-улики (заметка), командные строки RAT
 * и кража токенов Discord.
 */
final class RatScanner {

    private static final List<String> COMMANDS = List.of(
            "PASSWORD_STEAL",
            "DISCORD_STEAL",
            "TELEGRAM_STEAL",
            "STREAM_START",
            "STREAM_STOP",
            "WEBCAM_START",
            "MIC_START"
    );

    private static final List<String> THEFT_COMMANDS = List.of(
            "PASSWORD_STEAL", "DISCORD_STEAL", "TELEGRAM_STEAL"
    );

    private static final List<String> NAME_MARKERS = List.of(
            "keylog", "grabber", "hvnc", "exfil", "backdoor"
    );

    private static final Set<String> NAME_TOKENS = Set.of("steal", "rat", "c2");

    private static final Pattern DISCORD_TOKEN = Pattern.compile(
            "(?:mfa\\.[\\w-]{20,}|[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27})");

    private static final String TOKEN_REGEX_TEXT =
            "[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}";

    private final ModScanResult result;
    private final Map<String, String> commandLocations = new LinkedHashMap<>();
    private String fileUploadLocation;
    private String fileDownloadLocation;
    private String pathMarker;
    private String pathMarkerLocation;
    private String tokenLocation;
    private boolean namesReported;
    private boolean finished;

    RatScanner(ModScanResult result) {
        this.result = result;
    }

    void inspectNames(String className, List<String> methodNames, String fileLocation) {
        if (namesReported) {
            return;
        }

        String classLocation = "класс " + className + " - " + fileLocation;
        if (matchingName(className) != null) {
            namesReported = true;
            result.addFinding(new Finding(
                    25,
                    "Имена-улики RAT (заметка)",
                    0,
                    classLocation,
                    "имя класса: " + className
            ));
            markTheftName(className, classLocation);
            return;
        }

        for (String methodName : methodNames) {
            if (matchingName(methodName) != null) {
                namesReported = true;
                String location = "класс " + className + ", метод " + methodName
                        + " - " + fileLocation;
                result.addFinding(new Finding(
                        25,
                        "Имена-улики RAT (заметка)",
                        0,
                        location,
                        "имя метода: " + methodName
                ));
                markTheftName(methodName, location);
                return;
            }
        }
    }

    void inspectString(String value, String location) {
        if (value == null || value.isEmpty()) {
            return;
        }

        String lower = value.toLowerCase(Locale.ROOT);
        for (String command : COMMANDS) {
            if (lower.contains(command.toLowerCase(Locale.ROOT))) {
                commandLocations.putIfAbsent(command, location);
            }
        }
        if (lower.contains("file_upload")) {
            if (fileUploadLocation == null) {
                fileUploadLocation = location;
            }
        }
        if (lower.contains("file_download")) {
            if (fileDownloadLocation == null) {
                fileDownloadLocation = location;
            }
        }

        for (String command : THEFT_COMMANDS) {
            if (lower.contains(command.toLowerCase(Locale.ROOT))) {
                result.markCriticalHarm(location);
            }
        }

        if (pathMarker == null) {
            if (lower.contains("local storage")) {
                pathMarker = "Local Storage";
                pathMarkerLocation = location;
            } else if (lower.contains("leveldb")) {
                pathMarker = "leveldb";
                pathMarkerLocation = location;
            } else if (lower.contains(".ldb")) {
                pathMarker = ".ldb";
                pathMarkerLocation = location;
            }
        }

        if (tokenLocation == null
                && (DISCORD_TOKEN.matcher(value).find()
                || value.contains(TOKEN_REGEX_TEXT)
                || value.contains("mfa\\."))) {
            tokenLocation = location;
        }
    }

    void finish() {
        if (finished) {
            return;
        }
        finished = true;

        boolean filePair = fileUploadLocation != null && fileDownloadLocation != null;
        int commandCount = commandLocations.size() + (filePair ? 1 : 0);
        if (commandCount >= 3) {
            String firstLocation = commandLocations.values().stream()
                    .findFirst()
                    .orElse(fileUploadLocation);
            List<String> found = new ArrayList<>(commandLocations.keySet());
            if (filePair) {
                found.add("FILE_UPLOAD + FILE_DOWNLOAD");
            }
            result.addFinding(new Finding(
                    26,
                    "Командные строки RAT",
                    6,
                    firstLocation,
                    "3+ команд: " + String.join(", ", found)
            ));
        }

        if (pathMarker != null && tokenLocation != null) {
            result.addFinding(new Finding(
                    28,
                    "Кража токенов Discord",
                    5,
                    pathMarkerLocation,
                    "маркер: " + pathMarker + "; найден шаблон токена Discord"
            ));
        }
    }

    private void markTheftName(String value, String location) {
        String lower = value.toLowerCase(Locale.ROOT);
        if (lower.contains("stealpassword")
                || lower.contains("stealtoken")
                || lower.contains("stealdiscordtoken")
                || lower.contains("stealtelegramtoken")) {
            result.markCriticalHarm(location);
        }
    }

    private static String matchingName(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String lower = value.toLowerCase(Locale.ROOT);
        for (String marker : NAME_MARKERS) {
            if (lower.contains(marker)) {
                return value;
            }
        }
        for (String token : tokens(value)) {
            if (NAME_TOKENS.contains(token)) {
                return value;
            }
        }
        return null;
    }

    /**
     * Делит имя по разделителям и границам camelCase. Нужно, чтобы
     * stealTelegramData и RATClient ловились, а Generator и Stealer - нет.
     */
    private static List<String> tokens(String value) {
        String spaced = value
                .replaceAll("([a-z])([A-Z])", "$1 $2")
                .replaceAll("([A-Z]+)([A-Z][a-z])", "$1 $2");
        List<String> tokens = new ArrayList<>();
        for (String part : spaced.split("[^A-Za-z0-9]+")) {
            if (!part.isEmpty()) {
                tokens.add(part.toLowerCase(Locale.ROOT));
            }
        }
        return tokens;
    }
}
