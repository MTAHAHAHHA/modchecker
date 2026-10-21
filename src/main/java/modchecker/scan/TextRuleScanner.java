package modchecker.scan;

import modchecker.model.Finding;
import modchecker.model.ModScanResult;

import java.util.Locale;

/**
 * Проверяет строки правилами 1-8. Одно и то же правило добавляется только
 * один раз, даже если строка встретилась в десяти файлах.
 *
 * Правила 4 (Данные браузера) и 5 (Cookies) проверяются только в строковых
 * константах .class: в переводах, refmap и других текстовых файлах это
 * обычно обычные слова.
 */
final class TextRuleScanner {

    private final ModScanResult result;

    TextRuleScanner(ModScanResult result) {
        this.result = result;
    }

    void inspectClassConstant(String content, String location) {
        inspect(content, location, true);
    }

    void inspectText(String content, String location) {
        inspect(content, location, false);
    }

    private void inspect(String content, String location, boolean classConstant) {
        if (content == null || content.isEmpty()) {
            return;
        }

        String lowerCase = content.toLowerCase(Locale.ROOT);
        for (SignatureRule rule : SignatureRules.all()) {
            if (!classConstant && SignatureRules.isClassConstantOnly(rule.id())) {
                continue;
            }
            if (rule.matches(lowerCase)) {
                result.markEvidenceRule(rule.id(), location);
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
