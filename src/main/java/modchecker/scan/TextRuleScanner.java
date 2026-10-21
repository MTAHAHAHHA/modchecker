package modchecker.scan;

import modchecker.model.Finding;
import modchecker.model.ModScanResult;

import java.util.Locale;

/**
 * Проверяет строки правилами 1-8. Одно и то же правило добавляется только
 * один раз, даже если строка встретилась в десяти файлах.
 */
final class TextRuleScanner {

    private final ModScanResult result;

    TextRuleScanner(ModScanResult result) {
        this.result = result;
    }

    void inspect(String content, String location) {
        if (content == null || content.isEmpty()) {
            return;
        }

        String lowerCase = content.toLowerCase(Locale.ROOT);
        for (SignatureRule rule : SignatureRules.all()) {
            if (result.hasRule(rule.id())) {
                continue;
            }
            if (rule.matches(lowerCase)) {
                result.markEvidenceRule(rule.id());
                result.addFinding(new Finding(
                        rule.id(),
                        rule.title(),
                        rule.points(),
                        location,
                        "сигнатура: " + rule.evidence()
                ));
            }
        }
    }
}
