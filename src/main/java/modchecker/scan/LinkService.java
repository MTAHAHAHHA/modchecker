package modchecker.scan;

import modchecker.model.LinkFinding;
import modchecker.model.ModScanResult;

/**
 * Связки - дополнительные очки за опасное сочетание находок.
 *
 * Для КРАЖИ используются evidenceRules: скрытая (правило 9) или
 * восстановленная из байткода (правило 10) строка тоже считается
 * вебхуком/Telegram или файлами аккаунтов/браузера.
 */
final class LinkService {

    private static final String LOADER = "ЗАГРУЗЧИК";
    private static final String THEFT = "КРАЖА";

    // Правило 18 - эвристика длинных строк, а не признак загрузчика.
    private static final int[] LOADER_SOURCE_RULES = {9, 10, 11, 19};
    private static final int[] THEFT_CHANNEL_RULES = {1, 2};
    private static final int[] THEFT_DATA_RULES = {3, 4, 6};

    private LinkService() {
    }

    static void apply(ModScanResult result) {
        if (result.hasError()) {
            return;
        }

        int loaderSource = firstFinding(result, LOADER_SOURCE_RULES);
        if (loaderSource != 0 && result.hasRule(12)) {
            result.addLink(new LinkFinding(
                    LOADER,
                    3,
                    "мод целиком",
                    "правила " + loaderSource + " + 12"
            ));
        }

        int theftChannel = firstEvidence(result, THEFT_CHANNEL_RULES);
        int theftData = firstEvidence(result, THEFT_DATA_RULES);
        if (theftChannel != 0 && theftData != 0) {
            result.addLink(new LinkFinding(
                    THEFT,
                    4,
                    "мод целиком",
                    "правила " + theftChannel + " + " + theftData
            ));
        }
    }

    private static int firstFinding(ModScanResult result, int[] rules) {
        for (int rule : rules) {
            if (result.hasRule(rule)) {
                return rule;
            }
        }
        return 0;
    }

    /**
     * Для базовых правил 1-8 проверяем и обычную находку, и доказательство
     * из скрытой/восстановленной строки.
     */
    private static int firstEvidence(ModScanResult result, int[] rules) {
        for (int rule : rules) {
            if (result.hasEvidenceRule(rule) || result.hasRule(rule)) {
                return rule;
            }
        }
        return 0;
    }
}
