package modchecker.report;

import modchecker.model.Finding;
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

        if (scan.links().isEmpty()) {
            out.println("Связки: нет");
        } else {
            out.println("Связки:");
            for (LinkFinding link : scan.links()) {
                out.println("  " + link.name() + ": +" + link.points());
                out.println("      место: " + link.location());
                out.println("      " + link.evidence());
            }
        }
    }

    private static void printTotals(List<ModReport> reports, PrintStream out) {
        int suspicious = 0;
        int unknown = 0;
        int ok = 0;
        int errors = 0;
        int findings = 0;
        int links = 0;
        int totalPoints = 0;

        for (ModReport report : reports) {
            ModScanResult scan = report.scan();
            Verdict verdict = scan.verdict();
            if (verdict == Verdict.SUSPICIOUS) {
                suspicious++;
            } else if (verdict == Verdict.UNKNOWN) {
                unknown++;
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
        out.println("ПОДОЗРИТЕЛЬНО: " + suspicious);
        out.println("НЕИЗВЕСТНО: " + unknown);
        out.println("ОК: " + ok);
        out.println("ОШИБКА: " + errors);
        out.println("Находок: " + findings);
        out.println("Связок: " + links);
        out.println("Сумма очков: " + totalPoints);
    }
}
