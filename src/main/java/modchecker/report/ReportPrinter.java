package modchecker.report;

import modchecker.model.DecodedNote;
import modchecker.model.Finding;
import modchecker.model.FoundEntity;
import modchecker.model.LinkFinding;
import modchecker.model.ModScanResult;
import modchecker.model.Verdict;
import modchecker.online.OnlineCheckResult;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Comparator;
import java.util.List;

/**
 * Печатает отчёт по каждому моду, общие итоги и обязательные строки в конце.
 */
public final class ReportPrinter {

    private static final String CRITICAL_LINK = "КРИТИЧЕСКАЯ";

    private ReportPrinter() {
    }

    public static void print(List<ModReport> reports, PrintStream out) {
        for (ModReport report : reports) {
            printMod(report, out);
        }
        printTotals(reports, out);

        out.println();
        out.println("Подтверждение с сайта = файл тот же, что на официальной странице.");
        out.println("ПОДОЗРИТЕЛЬНО = проверь сам, это не приговор.");
    }

    /**
     * Тот же текст, что и console-режим, но строкой. Нужен для GUI и файла.
     */
    public static String format(List<ModReport> reports) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (PrintStream out = new PrintStream(
                bytes, true, StandardCharsets.UTF_8)) {
            print(reports, out);
        }
        return bytes.toString(StandardCharsets.UTF_8);
    }

    /**
     * Подробности одного мода для нижней панели GUI.
     */
    public static String formatMod(ModReport report) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (PrintStream out = new PrintStream(
                bytes, true, StandardCharsets.UTF_8)) {
            printMod(report, out);
        }
        return bytes.toString(StandardCharsets.UTF_8);
    }

    private static void printMod(ModReport report, PrintStream out) {
        ModScanResult scan = report.scan();
        OnlineCheckResult online = report.online();

        out.println();
        out.println("=== " + scan.name() + " ===");
        out.println("Вердикт: " + scan.verdict().label());
        out.println("Очки: " + scan.points()
                + " (находки " + scan.findingPoints()
                + " + связки " + scan.linkPoints() + ")");
        if (scan.isManuallyTrusted()) {
            out.println("Доверие: вручную - " + scan.trustSource());
        }
        out.println("SHA-1: " + online.sha1OrUnknown());
        out.println("Modrinth: " + online.modrinth().label());
        out.println("CurseForge: " + online.curseForge().label());

        if (scan.hasError()) {
            out.println(scan.verdict().label() + ": " + scan.error());
            return;
        }

        if (scan.findings().isEmpty()) {
            out.println("Находки: нет");
        } else {
            out.println("Находки:");
            scan.findings().stream()
                    .sorted(Comparator.comparingInt(Finding::rule))
                    .forEach(finding -> {
                        out.println("  [" + finding.rule() + "] "
                                + finding.title() + ": +" + finding.points());
                        out.println("      место: " + finding.location());
                        if (!finding.evidence().isBlank()) {
                            out.println("      " + finding.evidence());
                        }
                    });
        }

        out.println("Ссылки, домены, IP и токены:");
        if (scan.foundEntities().isEmpty()) {
            out.println("  нет");
        } else {
            for (FoundEntity entity : scan.foundEntities()) {
                out.println("  " + entity.kind() + ": " + entity.value()
                        + " - " + entity.location());
            }
        }

        if (scan.isOnlineConfirmed() && scan.isDangerous()) {
            out.println("Примечание: файл подтверждён на сайте, вердикт ограничен "
                    + "ПОДОЗРИТЕЛЬНО.");
        }

        LinkFinding critical = scan.links().stream()
                .filter(link -> CRITICAL_LINK.equals(link.name()))
                .findFirst()
                .orElse(null);
        if (critical != null) {
            out.println();
            out.println("!!! КРИТИЧЕСКАЯ СВЯЗКА (RAT): +" + critical.points() + " !!!");
            out.println("      " + critical.location());
            out.println("      часть 1: " + critical.firstLocation());
            out.println("      часть 2: " + critical.secondLocation());
            out.println("      " + critical.evidence());
        }

        List<LinkFinding> regularLinks = scan.links().stream()
                .filter(link -> !CRITICAL_LINK.equals(link.name()))
                .toList();
        if (regularLinks.isEmpty()) {
            if (critical == null) {
                out.println("Связки: нет");
            } else {
                out.println("Связки: критическая выше");
            }
        } else {
            out.println("Связки:");
            for (LinkFinding link : regularLinks) {
                out.println("  " + link.name() + ": +" + link.points());
                out.println("      " + link.location());
                out.println("      часть 1: " + link.firstLocation());
                out.println("      часть 2: " + link.secondLocation());
                out.println("      " + link.evidence());
            }
        }

        if (!scan.decodedNotes().isEmpty()) {
            out.println("Заметка: раскрытые строки");
            for (DecodedNote note : scan.decodedNotes()) {
                out.println("  " + note.value());
                out.println("      место: " + note.location());
            }
        }
    }

    private static void printTotals(List<ModReport> reports, PrintStream out) {
        int dangerous = 0;
        int suspicious = 0;
        int unknown = 0;
        int trusted = 0;
        int ok = 0;
        int errors = 0;
        int findings = 0;
        int links = 0;
        int totalPoints = 0;

        for (ModReport report : reports) {
            ModScanResult scan = report.scan();
            Verdict verdict = scan.verdict();
            if (verdict == Verdict.DANGEROUS) {
                dangerous++;
            } else if (verdict == Verdict.SUSPICIOUS) {
                suspicious++;
            } else if (verdict == Verdict.UNKNOWN) {
                unknown++;
            } else if (verdict == Verdict.TRUSTED) {
                trusted++;
            } else if (verdict == Verdict.OK) {
                ok++;
            } else {
                errors++;
            }

            findings += scan.findings().size();
            links += scan.links().size();
            totalPoints += scan.points();
        }

        out.println();
        out.println("=== ИТОГО ===");
        out.println("Проверено модов: " + reports.size());
        out.println("ОПАСНО: " + dangerous);
        out.println("ПОДОЗРИТЕЛЬНО: " + suspicious);
        out.println("НЕИЗВЕСТНО: " + unknown);
        out.println("ДОВЕРЕН (вручную): " + trusted);
        out.println("ОК: " + ok);
        out.println("ОШИБКА: " + errors);
        out.println("Находок: " + findings);
        out.println("Связок: " + links);
        out.println("Сумма очков: " + totalPoints);
    }
}
