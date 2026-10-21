package modchecker.selftest;

import modchecker.model.Finding;
import modchecker.model.LinkFinding;
import modchecker.model.ModScanResult;
import modchecker.model.Verdict;
import modchecker.scan.ScanService;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Проверка на реальных модах: новые правила 24-29 не должны давать
 * ОПАСНО или очки на легальных модах. Файлы не входят в репозиторий,
 * поэтому тест запускается отдельной задачей realModsTest с папкой.
 */
public final class RealModsTest {

    private static final List<String> MODS = List.of(
            "fancymenu",
            "modern-industrialization",
            "crashassistant",
            "appliedenergistics2",
            "kubejs",
            "create",
            "valkyrienskies",
            "guideme",
            "immersive-portals",
            "journeymap",
            "kotlinforforge"
    );

    private RealModsTest() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            throw new IllegalArgumentException(
                    "Укажите папку с реальными модами: realModsTest -PrealModsDir=...");
        }
        Path dir = Path.of(args[0]).toAbsolutePath().normalize();
        if (!Files.isDirectory(dir)) {
            throw new IllegalArgumentException("Папка не найдена: " + dir);
        }

        ScanService scanner = new ScanService();
        int checks = 0;
        int failed = 0;
        for (String mod : MODS) {
            Path jar = dir.resolve(mod + ".jar");
            checks++;
            if (!Files.isRegularFile(jar)) {
                failed++;
                System.out.println("[FAIL] " + mod + ": файл не найден - " + jar);
                continue;
            }

            ModScanResult result = scanner.scan(jar);
            Set<Integer> rules = new LinkedHashSet<>();
            for (Finding finding : result.findings()) {
                rules.add(finding.rule());
            }
            int newRulePoints = result.findings().stream()
                    .filter(finding -> finding.rule() >= 24 && finding.rule() <= 29)
                    .mapToInt(Finding::points)
                    .sum();
            boolean critical = result.links().stream()
                    .anyMatch(link -> link.name().equals("КРИТИЧЕСКАЯ"));
            boolean ok = !result.hasError()
                    && result.verdict() != Verdict.DANGEROUS
                    && !critical
                    && newRulePoints == 0;

            System.out.println((ok ? "[OK]   " : "[FAIL] ") + mod
                    + ": " + result.verdict().label()
                    + ", очки " + result.points()
                    + ", новые правила " + newRulePoints
                    + ", правила " + rules);
            if (!ok) {
                failed++;
                if (result.hasError()) {
                    System.out.println("       ошибка: " + result.error());
                }
                for (Finding finding : result.findings()) {
                    if (finding.rule() >= 24 && finding.rule() <= 29) {
                        System.out.println("       [" + finding.rule() + "] "
                                + finding.title() + ": +" + finding.points()
                                + " - " + finding.location()
                                + " (" + finding.evidence() + ")");
                    }
                }
                for (LinkFinding link : result.links()) {
                    System.out.println("       связка " + link.name()
                            + ": +" + link.points() + " - " + link.evidence());
                }
            }
        }

        System.out.println();
        System.out.println("Проверок: " + checks + ", провалов: " + failed + ".");
        if (failed > 0) {
            System.exit(1);
        }
    }
}
