package modchecker.scan;

import modchecker.model.Finding;
import modchecker.model.ModScanResult;
import modchecker.util.Entropy;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
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
    private static final int MAX_NOTE_LENGTH = 300;

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

        inspectHidden(content, location, true);
        inspectLongToken(content, location);
    }

    /**
     * В .json/.txt/.properties/.cfg ищем только скрытые строки.
     * Правило 18 к текстовым файлам не применяется: там бывают
     * переводы, анимации и длинные mixins. Правило 5 тоже только для .class.
     */
    void inspectText(String content, String location) {
        if (content == null || content.isEmpty()) {
            return;
        }

        inspectHidden(content, location, false);
    }

    private void inspectHidden(String content, String location, boolean classConstant) {
        inspectBase64(content, location, classConstant);
        inspectHex(content, location, classConstant);
        inspectReversed(content, location, classConstant);
    }

    private void inspectBase64(String content, String location,
                               boolean classConstant) {
        Matcher matcher = BASE64_CANDIDATE.matcher(content);
        while (matcher.find()) {
            byte[] bytes = decodeBase64Bytes(matcher.group());
            if (bytes == null) {
                continue;
            }

            String decoded = new String(bytes, StandardCharsets.UTF_8);
            List<SignatureRule> matches = SignatureRules.matching(decoded);
            if (!matches.isEmpty()) {
                for (SignatureRule rule : matches) {
                    if (classConstant || rule.id() != 5) {
                        reportHidden(rule, "Base64", location);
                    }
                }
                continue;
            }

            String text = decodeUtf8(bytes);
            if (text != null && isPlainText(text)) {
                result.addDecodedNote(normalizeNote(text), location);
            }
        }
    }

    private void inspectHex(String content, String location, boolean classConstant) {
        Matcher matcher = HEX_CANDIDATE.matcher(content);
        while (matcher.find()) {
            String hex = matcher.group();
            if ((hex.length() & 1) != 0) {
                continue;
            }
            String decoded = decodeHex(hex);
            if (decoded != null) {
                reportSignatures(decoded, "hex", location, classConstant);
            }
        }
    }

    private void inspectReversed(String content, String location,
                                 boolean classConstant) {
        String lowerCase = content.toLowerCase(Locale.ROOT);

        for (SignatureRule rule : SignatureRules.all()) {
            if (!classConstant && rule.id() == 5) {
                continue;
            }
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

    private void reportSignatures(String decoded, String encoding, String location,
                                  boolean classConstant) {
        for (SignatureRule rule : SignatureRules.matching(decoded)) {
            if (classConstant || rule.id() != 5) {
                reportHidden(rule, encoding, location);
            }
        }
    }

    private void reportHidden(SignatureRule baseRule, String encoding, String location) {
        result.markEvidenceRule(baseRule.id(), location);

        result.addOrUpgradeFinding(new Finding(
                9,
                "Спрятанная строка",
                baseRule.points() + 3,
                location,
                encoding + " -> " + baseRule.title()
        ));
    }

    private static byte[] decodeBase64Bytes(String candidate) {
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
            return decoder.decode(value);
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }

    /**
     * Для заметки нужен настоящий текст, а не двоичные данные, которые
     * случайно заменились на U+FFFD при обычном new String(bytes, UTF_8).
     */
    private static String decodeUtf8(byte[] bytes) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                    .toString();
        } catch (CharacterCodingException ignored) {
            return null;
        }
    }

    private static boolean isPlainText(String text) {
        String value = text.strip();
        if (value.length() < 8) {
            return false;
        }

        int visible = 0;
        int lettersOrDigits = 0;
        for (int i = 0; i < value.length(); i++) {
            char character = value.charAt(i);
            if (character == '\r' || character == '\n' || character == '\t') {
                continue;
            }
            if (Character.isISOControl(character)) {
                return false;
            }
            visible++;
            if (Character.isLetterOrDigit(character)) {
                lettersOrDigits++;
            }
        }

        return visible > 0 && lettersOrDigits * 2 >= visible;
    }

    private static String normalizeNote(String text) {
        String oneLine = text.strip()
                .replace("\r\n", "\\n")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
        if (oneLine.length() <= MAX_NOTE_LENGTH) {
            return oneLine;
        }
        return oneLine.substring(0, MAX_NOTE_LENGTH) + "...";
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
