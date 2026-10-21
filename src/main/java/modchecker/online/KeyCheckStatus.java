package modchecker.online;

/**
 * Результат тестового запроса к CurseForge. Сообщения не содержат ключ.
 */
public enum KeyCheckStatus {

    WORKING("ключ работает"),
    INVALID("ключ неверный или не одобрен (403)"),
    NO_NETWORK("нет сети"),
    EMPTY("ключ не введён"),
    ERROR("не удалось проверить ключ");

    private final String label;

    KeyCheckStatus(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
