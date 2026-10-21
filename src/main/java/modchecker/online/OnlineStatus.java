package modchecker.online;

/**
 * Результат проверки файла на конкретном сайте.
 */
public enum OnlineStatus {

    CONFIRMED("подтверждено"),
    NOT_FOUND("не найдено"),
    SKIPPED("проверка пропущена"),
    INVALID_KEY("ключ недействителен или не одобрен (403)");

    private final String label;

    OnlineStatus(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
