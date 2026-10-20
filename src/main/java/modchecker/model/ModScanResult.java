package modchecker.model;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Результат проверки одного jar-файла: находки, связки и вердикт.
 * Статусы Modrinth/CurseForge хранятся рядом, в отчёте.
 */
public final class ModScanResult {

    public static final int SUSPICIOUS_THRESHOLD = 10;

    private final Path file;
    private final Map<Integer, Finding> findings = new LinkedHashMap<>();
    private final List<LinkFinding> links = new ArrayList<>();
    private final Set<Integer> evidenceRules = new HashSet<>();
    private boolean onlineConfirmed;
    private String error;

    public ModScanResult(Path file) {
        this.file = file;
    }

    public Path file() {
        return file;
    }

    public String name() {
        return file.getFileName().toString();
    }

    public List<Finding> findings() {
        return List.copyOf(findings.values());
    }

    public List<LinkFinding> links() {
        return List.copyOf(links);
    }

    public boolean hasRule(int rule) {
        return findings.containsKey(rule);
    }

    /**
     * Отмечает базовое правило 1-8, даже если строка была спрятана.
     * Это понадобится для связки КРАЖА: скрытый вебхук тоже считается вебхуком.
     */
    public void markEvidenceRule(int rule) {
        evidenceRules.add(rule);
    }

    public boolean hasEvidenceRule(int rule) {
        return evidenceRules.contains(rule);
    }

    public Set<Integer> evidenceRules() {
        return Set.copyOf(evidenceRules);
    }

    public void addFinding(Finding finding) {
        findings.putIfAbsent(finding.rule(), finding);
    }

    /**
     * Для правил с переменными очками (9 и 10) оставляем находку
     * с максимальным значением, а не первую встреченную.
     */
    public void addOrUpgradeFinding(Finding finding) {
        Finding existing = findings.get(finding.rule());
        if (existing == null || finding.points() > existing.points()) {
            findings.put(finding.rule(), finding);
        }
    }

    public void addLink(LinkFinding link) {
        boolean alreadyPresent = links.stream()
                .anyMatch(existing -> existing.name().equals(link.name()));
        if (!alreadyPresent) {
            links.add(link);
        }
    }

    public int findingPoints() {
        int total = 0;
        for (Finding finding : findings.values()) {
            total += finding.points();
        }
        return total;
    }

    public int linkPoints() {
        int total = 0;
        for (LinkFinding link : links) {
            total += link.points();
        }
        return total;
    }

    public int points() {
        return findingPoints() + linkPoints();
    }

    /**
     * Порог 10 очков важнее подтверждения сайта: подозрительный мод
     * остаётся подозрительным, даже если файл совпал с официальной страницей.
     * Ниже порога без подтверждения сайта вердикт неизвестен.
     */
    public Verdict verdict() {
        if (hasError()) {
            return Verdict.ERROR;
        }
        if (points() >= SUSPICIOUS_THRESHOLD) {
            return Verdict.SUSPICIOUS;
        }
        if (onlineConfirmed) {
            return Verdict.OK;
        }
        return Verdict.UNKNOWN;
    }

    public boolean isOnlineConfirmed() {
        return onlineConfirmed;
    }

    /**
     * Вызывается после успешного совпадения SHA-1 с Modrinth или CurseForge.
     */
    public void markOnlineConfirmed() {
        onlineConfirmed = true;
    }

    public String error() {
        return error;
    }

    public boolean hasError() {
        return error != null;
    }

    public void markError(String message) {
        error = message;
        findings.clear();
        links.clear();
        evidenceRules.clear();
        onlineConfirmed = false;
    }
}
