package modchecker.model;

/**
 * Итоговый статус проверки мода.
 */
public enum Verdict {

    SUSPICIOUS("ПОДОЗРИТЕЛЬНО"),
    UNKNOWN("НЕИЗВЕСТНО"),
    OK("ОК"),
    ERROR("ОШИБКА");

    private final String label;

    Verdict(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
