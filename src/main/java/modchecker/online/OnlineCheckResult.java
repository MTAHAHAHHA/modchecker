package modchecker.online;

/**
 * SHA-1 мода и статусы проверки на двух сайтах.
 */
public record OnlineCheckResult(
        String sha1,
        OnlineStatus modrinth,
        OnlineStatus curseForge
) {

    public boolean confirmed() {
        return modrinth == OnlineStatus.CONFIRMED
                || curseForge == OnlineStatus.CONFIRMED;
    }

    public String sha1OrUnknown() {
        if (sha1 == null || sha1.isBlank()) {
            return "не удалось вычислить";
        }
        return sha1;
    }
}
