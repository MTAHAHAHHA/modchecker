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

    private static final int MAX_DECODED_NOTES = 10;
    private static final String MAIN_SCOPE = "основной код";

    private final Path file;
    private final Map<Integer, Finding> findings = new LinkedHashMap<>();
    private final Map<Integer, List<EvidenceLocation>> evidenceLocations =
            new LinkedHashMap<>();
    private final List<LinkFinding> links = new ArrayList<>();
    private final List<DecodedNote> decodedNotes = new ArrayList<>();
    private final Set<Integer> evidenceRules = new HashSet<>();
    private boolean onlineConfirmed;
    private boolean manuallyTrusted;
    private String trustSource;
    private String trustComment;
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

    /**
     * Base64-строки, раскрывшиеся в обычный текст. Это не находки и не очки,
     * а подсказки для ручной проверки. Не больше 10 на мод.
     */
    public List<DecodedNote> decodedNotes() {
        return List.copyOf(decodedNotes);
    }

    public void addDecodedNote(String value, String location) {
        if (value == null || value.isBlank() || decodedNotes.size() >= MAX_DECODED_NOTES) {
            return;
        }
        boolean alreadyPresent = decodedNotes.stream()
                .anyMatch(note -> note.value().equals(value));
        if (!alreadyPresent) {
            decodedNotes.add(new DecodedNote(value, location));
        }
    }

    public boolean hasRule(int rule) {
        return findings.containsKey(rule);
    }

    /**
     * Отмечает базовое правило 1-8, даже если строка была спрятана.
     * Это нужно для связки КРАЖА: скрытый вебхук тоже считается вебхуком.
     */
    public void markEvidenceRule(int rule, String location) {
        evidenceRules.add(rule);
        addEvidenceLocation(rule, location);
    }

    public boolean hasEvidenceRule(int rule) {
        return evidenceRules.contains(rule);
    }

    public Set<Integer> evidenceRules() {
        return Set.copyOf(evidenceRules);
    }

    /**
     * Все места, где встречалось правило. В отличие от findings(), здесь
     * сохраняются повторы из основного кода и разных вложенных jar.
     */
    public List<EvidenceLocation> evidenceLocations(int rule) {
        List<EvidenceLocation> locations = evidenceLocations.get(rule);
        return locations == null ? List.of() : List.copyOf(locations);
    }

    public void addFinding(Finding finding) {
        recordFindingEvidence(finding);
        findings.putIfAbsent(finding.rule(), finding);
    }

    /**
     * Для правил с переменными очками (9, 10 и 13) оставляем находку
     * с максимальным значением, а не первую встреченную.
     */
    public void addOrUpgradeFinding(Finding finding) {
        recordFindingEvidence(finding);
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
     * Ручное доверие важнее очков, но не отменяет показ находок.
     */
    public Verdict verdict() {
        if (hasError()) {
            return Verdict.ERROR;
        }
        if (manuallyTrusted) {
            return Verdict.TRUSTED;
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

    public boolean isManuallyTrusted() {
        return manuallyTrusted;
    }

    public String trustSource() {
        return trustSource;
    }

    public String trustComment() {
        return trustComment;
    }

    public void markManuallyTrusted(String source, String comment) {
        manuallyTrusted = true;
        trustSource = source;
        trustComment = comment;
    }

    public void clearManualTrust() {
        manuallyTrusted = false;
        trustSource = null;
        trustComment = null;
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
        evidenceLocations.clear();
        links.clear();
        decodedNotes.clear();
        evidenceRules.clear();
        onlineConfirmed = false;
        clearManualTrust();
    }

    private void recordFindingEvidence(Finding finding) {
        evidenceRules.add(finding.rule());
        addEvidenceLocation(finding.rule(), finding.location());
    }

    private void addEvidenceLocation(int rule, String location) {
        String safeLocation = location == null ? "" : location;
        EvidenceLocation entry = new EvidenceLocation(
                rule, safeLocation, scopeOf(safeLocation));
        List<EvidenceLocation> locations = evidenceLocations.computeIfAbsent(
                rule, ignored -> new ArrayList<>());
        if (!locations.contains(entry)) {
            locations.add(entry);
        }
    }

    /**
     * Находка в основном jar получает scope "основной код". Находка внутри
     * вложенного jar - путь этого jar, например level1.jar!/level2.jar.
     */
    private static String scopeOf(String location) {
        int nested = location.lastIndexOf("!/");
        if (nested < 0) {
            return MAIN_SCOPE;
        }
        return location.substring(0, nested);
    }
}
