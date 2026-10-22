package modchecker.online;

public record VtResult(Status status, int malicious, int suspicious, int total,
                       long analyzedAt, long checkedAt, boolean cached) {
    public enum Status { FOUND, NOT_FOUND, NO_KEY, RATE_LIMITED, INVALID_KEY, UNAVAILABLE, INVALID_RESPONSE }
    public static VtResult status(Status status) { return new VtResult(status, 0, 0, 0, 0, System.currentTimeMillis(), false); }
    public String label() {
        return switch (status) {
            case FOUND -> "Срабатывания: " + malicious + " из " + total + ", подозрительных: " + suspicious;
            case NOT_FOUND -> "Нет данных по этому хешу";
            case NO_KEY -> "Ключ VirusTotal не задан";
            case RATE_LIMITED -> "Лимит запросов; повторите позже (4/мин, 500/сутки)";
            case INVALID_KEY -> "Ключ не принят VirusTotal";
            case UNAVAILABLE -> "VirusTotal недоступен";
            case INVALID_RESPONSE -> "Некорректный ответ VirusTotal";
        };
    }
}