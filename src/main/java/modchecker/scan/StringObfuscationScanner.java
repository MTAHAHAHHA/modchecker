package modchecker.scan;

import modchecker.model.Finding;
import modchecker.model.ModScanResult;
import modchecker.util.Entropy;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Ищет маскировку строк: Base64, hex, перевёрнутый текст, а длинные
 * случайные строки - только в строковых константах .class. Очки за
 * правило 9 зависят от того, какая опасная сигнатура была спрятана.
 */
final class StringObfuscationScanner {

    private static final Pattern BASE64_CANDIDATE =
            Pattern.compile("[A-Za-z0-9+/=_-]{16,}");
    private static final Pattern HEX_CANDIDATE =
            Pattern.compile("[0-9A-Fa-f]{16,}");
    private static final Pattern LONG_TOKEN =
            Pattern.compile("[^\\s/;]{64,}");

    private final ModScanResult result;

    StringObfuscationScanner(ModScanResult result) {
        this.result = result;
    }

    /**
     * Маскировка и длинные случайные строки в строковых константах .class.
     */
    void inspectClassConstant(String content, String location) {
        if (content == null || content.isEmpty()) {
            return;
        }

        inspectHidden(content, location);
        inspectLongToken(content, location);
    }

    /**
     * В .json/.txt/.properties/.cfg ищем только скрытые строки.
     * Правило 18 к текстовым файлам не применяется: там бывают
     * переводы, анимации и длинные mixins.
     */
    void inspectText(String content, String location) {
        if (content == null || content.isEmpty()) {
            return;
        }

        inspectHidden(content, location);
    }

    private void inspectHidden(String content, String location) {
        inspectBase64(content, location);
        inspectHex(content, location);
        inspectReversed(content, location);
    }

    private void inspectBase64(String content, String location) {
        Matcher matcher = BASE64_CANDIDATE.matcher(content);
        while (matcher.find()) {
            String decoded = decodeBase64(matcher.group());
            if (decoded != null) {
                reportSignatures(decoded, "Base64", location);
            }
        }
    }

    private void inspectHex(String content, String location) {
        Matcher matcher = HEX_CANDIDATE.matcher(content);
        while (matcher.find()) {
            String hex = matcher.group();
            if ((hex.length() & 1) != 0) {
                continue;
            }
            String decoded = decodeHex(hex);
            if (decoded != null) {
                reportSignatures(decoded, "hex", location);
            }
        }
    }

    private void inspectReversed(String content, String location) {
        String lowerCase = content.toLowerCase(Locale.ROOT);

        for (SignatureRule rule : SignatureRules.all()) {
            for (String pattern : rule.patterns()) {
                String reversedPattern = reverse(pattern);
                if (lowerCase.contains(reversedPattern)) {
                    reportHidden(rule, "перевёрнутая строка", location);
                    break;
                }
            }
        }
    }

    private void inspectLongToken(String content, String location) {
        if (result.hasRule(18)) {
            return;
        }

        Matcher matcher = LONG_TOKEN.matcher(content);
        while (matcher.find()) {
            String token = matcher.group();
            if (!isAscii(token)) {
                continue;
            }
            if (isAlphabetLike(token)) {
                continue;
            }
            double entropy = Entropy.ofString(token);
            if (entropy >= 4.8) {
                result.addFinding(new Finding(
                        18,
                        "Длинная случайная строка",
                        1,
                        location,
                        String.format(Locale.ROOT,
                                "длина: %d, энтропия: %.2f бит", token.length(), entropy)
                ));
                return;
            }
        }
    }

    private void reportSignatures(String decoded, String encoding, String location) {
        for (SignatureRule rule : SignatureRules.matching(decoded)) {
            reportHidden(rule, encoding, location);
        }
    }

    private void reportHidden(SignatureRule baseRule, String encoding, String location) {
        result.markEvidenceRule(baseRule.id());

        result.addOrUpgradeFinding(new Finding(
                9,
                "Спрятанная строка",
                baseRule.points() + 3,
                location,
                encoding + " -> " + baseRule.title()
        ));
    }

    private static String decodeBase64(String candidate) {
        String value = candidate;
        int remainder = value.length() % 4;
        if (remainder == 1) {
            return null;
        }
        if (remainder != 0) {
            value = value + "=".repeat(4 - remainder);
        }

        try {
            Base64.Decoder decoder = value.indexOf('-') >= 0 || value.indexOf('_') >= 0
                    ? Base64.getUrlDecoder()
                    : Base64.getDecoder();
            byte[] bytes = decoder.decode(value);
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }

    private static String decodeHex(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            int high = Character.digit(hex.charAt(i * 2), 16);
            int low = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) {
                return null;
            }
            bytes[i] = (byte) ((high << 4) | low);
        }
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static String reverse(String text) {
        return new StringBuilder(text).reverse().toString();
    }

    private static boolean isAscii(String text) {
        return text.chars().allMatch(character -> character <= 0x7F);
    }

    /**
     * Таблицы вида "ABC...xyz0-9" в парсерах - это алфавиты, а не
     * случайные строки. Если почти каждый символ уникален, пропускаем.
     */
    private static boolean isAlphabetLike(String text) {
        long unique = text.chars().distinct().count();
        return unique * 10L >= text.length() * 9L;
    }
}
