package modchecker.gui;

import modchecker.report.ModReport;
import modchecker.model.Verdict;
import java.util.Locale;

/** Фильтры только меняют представление; результат сканирования не изменяется. */
public final class ResultFilters {
    private ResultFilters() { }
    public static boolean matches(ModReport report, String query, String result, int rule, String source) {
        if (result.equals("Требуют внимания") && !(report.needsFullScan() || report.scan().hasError()
                || (report.fullScan() && (report.scan().verdict() == Verdict.DANGEROUS
                    || report.scan().verdict() == Verdict.SUSPICIOUS || report.scan().verdict() == Verdict.UNKNOWN)))) return false;
        if (result.equals("Только полная проверка") && !report.fullScan()) return false;
        if (result.equals("Только быстрая проверка") && report.fullScan()) return false;
        if (result.equals("Подтверждены на сайтах") && !report.online().confirmed()) return false;
        if (result.equals("Без подтверждения") && report.online().confirmed()) return false;
        if (result.startsWith("Вердикт: ") && (!report.fullScan() || !report.statusLabel().equals(result.substring(9)))) return false;
        if (rule > 0 && !report.scan().hasEvidenceRule(rule)) return false;
        if (!source.equals("Любой источник")) {
            boolean nested = source.equals("Вложенные JAR");
            if (report.scan().findings().stream().filter(f -> rule == 0 || f.rule() == rule).noneMatch(f ->
                    report.scan().evidenceLocations(f.rule()).stream().anyMatch(location -> location.location().contains("!/") == nested))) return false;
        }
        String needle = query.strip().toLowerCase(Locale.ROOT);
        if (needle.isEmpty()) return true;
        if (report.scan().name().toLowerCase(Locale.ROOT).contains(needle)) return true;
        return report.scan().findings().stream().anyMatch(f ->
                (f.title() + " " + f.location() + " " + f.evidence()).toLowerCase(Locale.ROOT).contains(needle));
    }
}
