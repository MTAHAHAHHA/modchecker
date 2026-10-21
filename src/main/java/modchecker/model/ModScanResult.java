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
    private static final int MAX_FOUND_ENTITIES = 100;
    private static final String MAIN_SCOPE = "основной код";

    private final Path file;
    private final Map<Integer, Finding> findings = new LinkedHashMap<>();
    private final Map<Integer, List<EvidenceLocation>> evidenceLocations =
            new LinkedHashMap<>();
    private final List<LinkFinding> links = new ArrayList<>();
    private final List<DecodedNote> decodedNotes = new ArrayList<>();
    private final List<FoundEntity> foundEntities = new ArrayList<>();
    private final List<EvidenceLocation> criticalHarm = new ArrayList<>();
    private final Set<Integer> evidenceRules = new HashSet<>();
    private boolean onlineConfirmed;
    private boolean manuallyTrusted;
    private boolean dangerous;
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

    /**
     * Ссылки, домены, IP-адреса и токены для ручной проверки.
     */
    public List<FoundEntity> foundEntities() {
        return List.copyOf(foundEntities);
    }

    public void addFoundEntity(String kind, String value, String location) {
        if (kind == null || value == null || value.isBlank()
                || foundEntities.size() >= MAX_FOUND_ENTITIES) {
            return;
        }
        boolean alreadyPresent = foundEntities.stream()
                .anyMatch(entity -> entity.kind().equals(kind)
                        && entity.value().equals(value));
        if (!alreadyPresent) {
            foundEntities.add(new FoundEntity(kind, value, location));
        }
    }

    /**
     * Высоконадёжная вредная часть для критической связки. Правило 25
     * (имена-улики) сюда не попадает: оно остаётся только заметкой.
     */
    public List<EvidenceLocation> criticalHarmLocations() {
        return List.copyOf(criticalHarm);
    }

    public void markCriticalHarm(String location) {
        String safeLocation = location == null ? "" : location;
        EvidenceLocation entry = new EvidenceLocation(
                0, safeLocation, scopeOf(safeLocation));
        if (!criticalHarm.contains(entry)) {
            criticalHarm.add(entry);
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

    /**
     * Как markEvidenceRule, но с явной областью. Нужно правилу 24: сам
     * спрятанный jar лежит в родительском архиве, а связка должна считаться
     * с находками внутри этого jar.
     */
    public void markEvidenceRule(int rule, String location, String scope) {
        evidenceRules.add(rule);
        addEvidenceLocation(rule, location, scope);
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
     * Добавляет находку с заданной областью. Используется для правила 24,
     * чтобы спрятанный jar был виден связке как отдельная область.
     */
    public void addFindingWithScope(Finding finding, String scope) {
        evidenceRules.add(finding.rule());
        addEvidenceLocation(finding.rule(), finding.location(), scope);
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
     * Подтверждение на Modrinth или CurseForge ограничивает вердикт:
     * официальный файл не может быть ОПАСНО. Ручное доверие по-прежнему
     * не отменяет критическую связку у неподтверждённого файла.
     */
    public Verdict verdict() {
        if (hasError()) {
            return Verdict.ERROR;
        }
        if (dangerous && !onlineConfirmed) {
            return Verdict.DANGEROUS;
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

    /**
     * Критическая связка высоконадёжной вредной части с правилом 24 или 29.
     * У файла, подтверждённого на сайте, вердикт всё равно не выше
     * ПОДОЗРИТЕЛЬНО.
     */
    public boolean isDangerous() {
        return dangerous;
    }

    public void markDangerous() {
        dangerous = true;
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
        foundEntities.clear();
        criticalHarm.clear();
        evidenceRules.clear();
        onlineConfirmed = false;
        dangerous = false;
        clearManualTrust();
    }

    private void recordFindingEvidence(Finding finding) {
        evidenceRules.add(finding.rule());
        addEvidenceLocation(finding.rule(), finding.location());
    }

    private void addEvidenceLocation(int rule, String location) {
        String safeLocation = location == null ? "" : location;
        addEvidenceLocation(rule, safeLocation, scopeOf(safeLocation));
    }

    private void addEvidenceLocation(int rule, String location, String scope) {
        String safeLocation = location == null ? "" : location;
        String safeScope = scope == null || scope.isBlank()
                ? scopeOf(safeLocation) : scope;
        EvidenceLocation entry = new EvidenceLocation(rule, safeLocation, safeScope);
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
        String path = location;
        int prefix = path.indexOf(" - ");
        if (prefix >= 0) {
            path = path.substring(prefix + 3);
        } else if (path.startsWith("файл ")) {
            path = path.substring("файл ".length());
        }

        int nested = path.lastIndexOf("!/");
        if (nested < 0) {
            return MAIN_SCOPE;
        }
        return path.substring(0, nested);
    }
}
