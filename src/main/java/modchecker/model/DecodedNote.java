package modchecker.model;

/**
 * Строка, раскрытая из Base64 и похожая на обычный текст. Очков не даёт,
 * нужна для ручной проверки в отчёте.
 */
public record DecodedNote(String value, String location) {
}
