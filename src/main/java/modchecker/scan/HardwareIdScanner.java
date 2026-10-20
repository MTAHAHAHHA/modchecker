package modchecker.scan;

import modchecker.model.Finding;
import modchecker.model.ModScanResult;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Правила 22 и 23: сбор ID железа и его частичная маскировка.
 *
 * Правило 22 ищет вызовы OSHI, MAC-адрес через NetworkInterface и строки
 * Windows-команд/реестра. Правило 23 добавляет 2 очка, если сбор найден
 * в коротком или обфусцированном классе, а большинство классов мода
 * названы нормально.
 */
final class HardwareIdScanner {

    private static final List<Marker> STRING_MARKERS = List.of(
            new Marker("wmic", "wmic", false),
            new Marker("csproduct", "csproduct", false),
            new Marker("baseboard", "baseboard", true),
            new Marker("diskdrive", "diskdrive", true),
            new Marker("machineguid", "MachineGuid", false)
    );

    private final ModScanResult result;
    private final Set<String> classes = new LinkedHashSet<>();
    private String firstLocation;
    private String firstEvidence;

    HardwareIdScanner(ModScanResult result) {
        this.result = result;
    }

    void inspectClassConstant(String value, String className, String location) {
        if (value == null || value.isEmpty()) {
            return;
        }

        String lowerCase = value.toLowerCase(Locale.ROOT);
        boolean commandContext = lowerCase.contains("wmic")
                || lowerCase.contains("csproduct")
                || lowerCase.contains("machineguid");
        for (Marker marker : STRING_MARKERS) {
            if (!lowerCase.contains(marker.needle())) {
                continue;
            }
            // "diskdrive" и "baseboard" сами по себе часто встречаются
            // в конфигах. Считаем их признаком только рядом с wmic/реестром.
            if (marker.weak() && !commandContext) {
                continue;
            }
            remember(className, location, "строка: " + marker.title());
            return;
        }
    }

    void inspectCall(HardwareCall call, String fileLocation) {
        remember(
                call.className(),
                "класс " + call.className()
                        + ", метод " + call.methodName()
                        + " - " + fileLocation,
                "вызов: " + call.owner().replace('/', '.')
                        + "." + call.calledName()
        );
    }

    void finish(List<String> classNames) {
        if (firstLocation == null) {
            return;
        }

        result.addFinding(new Finding(
                22,
                "Сбор ID железа",
                3,
                firstLocation,
                firstEvidence
        ));

        if (classNames == null || classNames.isEmpty()) {
            return;
        }

        String shortClass = classes.stream()
                .filter(HardwareIdScanner::isShortOrObfuscatedName)
                .findFirst()
                .orElse(null);
        if (shortClass == null) {
            return;
        }

        long normalClasses = classNames.stream()
                .filter(HardwareIdScanner::isNormalName)
                .count();
        if (normalClasses * 2 <= classNames.size()) {
            return;
        }

        result.addFinding(new Finding(
                23,
                "Спрятанный сбор",
                2,
                "класс " + shortClass,
                "правило 22 в классе с коротким именем; нормальных классов "
                        + normalClasses + " из " + classNames.size()
        ));
    }

    private void remember(String className, String location, String evidence) {
        classes.add(className);
        if (firstLocation == null) {
            firstLocation = location;
            firstEvidence = evidence;
        }
    }

    private static boolean isNormalName(String className) {
        String simple = simpleName(className);
        if (simple.length() <= 2) {
            return false;
        }
        if (simple.chars().anyMatch(character -> character > 0x7F)) {
            return false;
        }
        return !isObfuscatedName(simple);
    }

    private static boolean isShortOrObfuscatedName(String className) {
        String simple = simpleName(className);
        return simple.length() <= 2 || isObfuscatedName(simple);
    }

    /**
     * O004 и Il1 - короткие токены без нормального слова. Обычные имена
     * вроде Mod1 или FeatureA сюда не попадают: в них есть читаемое слово.
     */
    private static boolean isObfuscatedName(String name) {
        if (name.length() > 4) {
            return false;
        }

        boolean hasDigit = false;
        boolean hasLetter = false;
        long lowerCase = 0;
        for (int i = 0; i < name.length(); i++) {
            char character = name.charAt(i);
            if (Character.isDigit(character)) {
                hasDigit = true;
            } else if (Character.isLetter(character)) {
                hasLetter = true;
                if (Character.isLowerCase(character)) {
                    lowerCase++;
                }
            }
        }
        return hasDigit && hasLetter && lowerCase <= 1;
    }

    private static String simpleName(String className) {
        int dot = className.lastIndexOf('.');
        String simple = dot >= 0 ? className.substring(dot + 1) : className;
        int dollar = simple.lastIndexOf('$');
        return dollar >= 0 ? simple.substring(dollar + 1) : simple;
    }

    private record Marker(String needle, String title, boolean weak) {
    }
}
