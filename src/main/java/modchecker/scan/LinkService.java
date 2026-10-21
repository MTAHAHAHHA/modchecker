package modchecker.scan;

import modchecker.model.EvidenceLocation;
import modchecker.model.LinkFinding;
import modchecker.model.ModScanResult;

import java.util.ArrayList;
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
    private static final String CRITICAL = "КРИТИЧЕСКАЯ";
    private static final String MAIN_SCOPE = "основной код";
    private static final int CRITICAL_POINTS = 10;

    // Правило 18 - эвристика длинных строк, а не признак загрузчика.
    private static final int[] LOADER_SOURCE_RULES = {9, 10, 11, 19};
    private static final int[] THEFT_CHANNEL_RULES = {1, 2};
    private static final int[] THEFT_DATA_RULES = {3, 4, 6};
    private static final int[] RAT_CONTAINER_RULES = {29, 24};

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

        // Критическая связка собирается только из высоконадёжных частей:
        // реальная кража/слежка или правило 26 (3+ команд) плюс туннель/C2
        // или спрятанный jar в той же области. Имена-улики (25) и микрофон
        // сюда не входят.
        List<EvidenceLocation> harm = new ArrayList<>(result.criticalHarmLocations());
        harm.addAll(result.evidenceLocations(26));
        harm.addAll(result.evidenceLocations(28));
        LinkPair critical = findPair(result, harm, RAT_CONTAINER_RULES);
        if (critical != null) {
            result.addLink(toLink(CRITICAL, CRITICAL_POINTS, critical));
            result.markDangerous();
        }
    }

    private static LinkPair findPair(ModScanResult result,
                                     List<EvidenceLocation> firstLocations,
                                     int[] secondRules) {
        for (String scope : scopes(firstLocations, result, secondRules)) {
            EvidenceLocation first = firstInScope(firstLocations, scope);
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

    private static Set<String> scopes(List<EvidenceLocation> firstLocations,
                                      ModScanResult result, int[] secondRules) {
        Set<String> scopes = new LinkedHashSet<>();
        for (EvidenceLocation location : firstLocations) {
            scopes.add(location.scope());
        }
        for (int rule : secondRules) {
            for (EvidenceLocation location : result.evidenceLocations(rule)) {
                scopes.add(location.scope());
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

    private static EvidenceLocation firstInScope(List<EvidenceLocation> locations,
                                                  String scope) {
        for (EvidenceLocation location : locations) {
            if (location.scope().equals(scope)) {
                return location;
            }
        }
        return null;
    }

    private static LinkFinding toLink(String name, int points, LinkPair pair) {
        String firstLabel = partLabel(pair.first());
        String secondLabel = partLabel(pair.second());
        String evidence = pair.first().rule() > 0 && pair.second().rule() > 0
                ? "правила " + pair.first().rule() + " + " + pair.second().rule()
                : firstLabel + " + " + secondLabel;
        return new LinkFinding(
                name,
                points,
                "область: " + scopeLabel(pair.first().scope()),
                evidence,
                firstLabel + ": " + pair.first().location(),
                secondLabel + ": " + pair.second().location()
        );
    }

    private static String partLabel(EvidenceLocation location) {
        return location.rule() == 0
                ? "высоконадёжная вредная часть"
                : "правило " + location.rule();
    }

    private static String scopeLabel(String scope) {
        return MAIN_SCOPE.equals(scope) ? MAIN_SCOPE : "вложенный jar: " + scope;
    }

    private record LinkPair(EvidenceLocation first, EvidenceLocation second) {
    }
}
