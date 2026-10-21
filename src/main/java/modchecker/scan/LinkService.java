package modchecker.scan;

import modchecker.model.EvidenceLocation;
import modchecker.model.LinkFinding;
import modchecker.model.ModScanResult;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Связки - дополнительные очки за опасное сочетание находок.
 *
 * Связка собирается только внутри одной области: либо в основном коде мода,
 * либо в одном и том же вложенном jar. Иначе Telegram из кода мода мог бы
 * сложиться с "Local Storage" из чужой библиотеки.
 */
final class LinkService {

    private static final String LOADER = "ЗАГРУЗЧИК";
    private static final String THEFT = "КРАЖА";
    private static final String MAIN_SCOPE = "основной код";

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

        LinkPair loader = findPair(result, LOADER_SOURCE_RULES, new int[]{12});
        if (loader != null) {
            result.addLink(toLink(LOADER, 3, loader));
        }

        LinkPair theft = findPair(result, THEFT_CHANNEL_RULES, THEFT_DATA_RULES);
        if (theft != null) {
            result.addLink(toLink(THEFT, 4, theft));
        }
    }

    private static LinkPair findPair(ModScanResult result, int[] firstRules,
                                     int[] secondRules) {
        for (String scope : scopes(result, firstRules, secondRules)) {
            EvidenceLocation first = firstInScope(result, firstRules, scope);
            if (first == null) {
                continue;
            }
            EvidenceLocation second = firstInScope(result, secondRules, scope);
            if (second != null) {
                return new LinkPair(first, second);
            }
        }
        return null;
    }

    private static Set<String> scopes(ModScanResult result, int[]... ruleGroups) {
        Set<String> scopes = new LinkedHashSet<>();
        for (int[] rules : ruleGroups) {
            for (int rule : rules) {
                for (EvidenceLocation location : result.evidenceLocations(rule)) {
                    scopes.add(location.scope());
                }
            }
        }
        return scopes;
    }

    private static EvidenceLocation firstInScope(ModScanResult result, int[] rules,
                                                  String scope) {
        for (int rule : rules) {
            List<EvidenceLocation> locations = result.evidenceLocations(rule);
            for (EvidenceLocation location : locations) {
                if (location.scope().equals(scope)) {
                    return location;
                }
            }
        }
        return null;
    }

    private static LinkFinding toLink(String name, int points, LinkPair pair) {
        return new LinkFinding(
                name,
                points,
                "область: " + scopeLabel(pair.first().scope()),
                "правила " + pair.first().rule() + " + " + pair.second().rule(),
                "правило " + pair.first().rule() + ": " + pair.first().location(),
                "правило " + pair.second().rule() + ": " + pair.second().location()
        );
    }

    private static String scopeLabel(String scope) {
        return MAIN_SCOPE.equals(scope) ? MAIN_SCOPE : "вложенный jar: " + scope;
    }

    private record LinkPair(EvidenceLocation first, EvidenceLocation second) {
    }
}
