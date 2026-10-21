package modchecker.scan;

import java.util.List;
import java.util.Locale;

/**
 * Описание правил поиска подозрительных строк (правила 1-8).
 */
record SignatureRule(int id, String title, int points, List<String> patterns) {

    boolean matches(String lowerCaseContent) {
        for (String pattern : patterns) {
            if (lowerCaseContent.contains(pattern)) {
                return true;
            }
        }
        return false;
    }

    String evidence() {
        return String.join(" / ", patterns);
    }
}

final class SignatureRules {

    private static final List<SignatureRule> ALL = List.of(
            new SignatureRule(1, "Discord-вебхук", 4,
                    List.of("discord.com/api/webhooks", "discordapp.com/api/webhooks")),
            new SignatureRule(2, "Telegram Bot API", 3,
                    List.of("api.telegram.org")),
            new SignatureRule(3, "Файлы аккаунтов Minecraft", 3,
                    List.of("launcher_accounts", "launcher_profiles")),
            new SignatureRule(4, "Данные браузера", 4,
                    List.of("local storage", "leveldb", "login data")),
            new SignatureRule(5, "Cookies", 1,
                    List.of("cookies")),
            new SignatureRule(6, "Bitcoin-кошелёк", 3,
                    List.of("wallet.dat")),
            new SignatureRule(7, "Fractureiser", 10,
                    List.of("dev/neko", "skyrage")),
            new SignatureRule(8, "Pastebin", 1,
                    List.of("pastebin.com"))
    );

    private SignatureRules() {
    }

    static List<SignatureRule> matching(String content) {
        String lowerCase = content.toLowerCase(Locale.ROOT);
        return ALL.stream().filter(rule -> rule.matches(lowerCase)).toList();
    }

    static List<SignatureRule> all() {
        return ALL;
    }

    /**
     * Правила 4 и 5 ищем только в строковых константах .class: в переводах,
     * refmap и других текстовых файлах это обычно обычные слова.
     */
    static boolean isClassConstantOnly(int ruleId) {
        return ruleId == 4 || ruleId == 5;
    }
}
