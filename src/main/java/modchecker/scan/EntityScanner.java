package modchecker.scan;

import modchecker.model.ModScanResult;

import java.net.URI;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Собирает ссылки, домены, IP-адреса и токены для ручной проверки.
 * Это не правила и не очки.
 */
final class EntityScanner {

    private static final Pattern URL = Pattern.compile(
            "https?://[^\\s\"'<>\\\\]+", Pattern.CASE_INSENSITIVE);
    private static final Pattern BARE_WEBHOOK = Pattern.compile(
            "(?i)(?:discord|discordapp)\\.com/api/webhooks/[^\\s\"'<>]+");
    private static final Pattern IPV4 = Pattern.compile(
            "\\b\\d{1,3}(?:\\.\\d{1,3}){3}(?::\\d{1,5})?\\b");
    private static final Pattern DISCORD_TOKEN = Pattern.compile(
            "(?:mfa\\.[\\w-]{20,}|[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27})");
    private static final Pattern TELEGRAM_TOKEN = Pattern.compile(
            "\\b\\d{8,10}:[A-Za-z0-9_-]{35}\\b");

    private final ModScanResult result;

    EntityScanner(ModScanResult result) {
        this.result = result;
    }

    void inspect(String value, String location) {
        if (value == null || value.isEmpty()) {
            return;
        }

        Matcher urls = URL.matcher(value);
        while (urls.find()) {
            String url = trimUrl(urls.group());
            addUrl(url, location);
        }

        Matcher webhooks = BARE_WEBHOOK.matcher(value);
        while (webhooks.find()) {
            if (isPartOfUrl(value, webhooks.start())) {
                continue;
            }
            String webhook = trimUrl(webhooks.group());
            addUrl("https://" + webhook, location);
        }

        Matcher ips = IPV4.matcher(value);
        while (ips.find()) {
            String ip = ips.group();
            int colon = ip.indexOf(':');
            if (colon >= 0) {
                ip = ip.substring(0, colon);
            }
            if (isIpv4(ip)) {
                result.addFoundEntity("IP", ip, location);
            }
        }

        Matcher discordTokens = DISCORD_TOKEN.matcher(value);
        while (discordTokens.find()) {
            result.addFoundEntity("токен Discord", discordTokens.group(), location);
        }

        Matcher telegramTokens = TELEGRAM_TOKEN.matcher(value);
        while (telegramTokens.find()) {
            result.addFoundEntity("токен Telegram", telegramTokens.group(), location);
        }
    }

    private void addUrl(String url, String location) {
        String lower = url.toLowerCase(Locale.ROOT);
        String kind = lower.contains("discord.com/api/webhooks")
                || lower.contains("discordapp.com/api/webhooks")
                ? "вебхук Discord" : "ссылка";
        result.addFoundEntity(kind, url, location);

        String host = hostOf(url);
        if (host == null) {
            return;
        }
        if (isIpv4(host)) {
            result.addFoundEntity("IP", host, location);
        } else {
            result.addFoundEntity("домен", host, location);
        }
    }

    private static String hostOf(String url) {
        try {
            String host = URI.create(url).getHost();
            return host == null ? null : host.toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }

    private static boolean isPartOfUrl(String value, int start) {
        return (start >= 8
                && value.regionMatches(true, start - 8, "https://", 0, 8))
                || (start >= 7
                && value.regionMatches(true, start - 7, "http://", 0, 7));
    }

    private static String trimUrl(String value) {
        int end = value.length();
        while (end > 0) {
            char last = value.charAt(end - 1);
            if (last == ')' || last == ']' || last == '}' || last == ','
                    || last == ';' || last == '.') {
                end--;
            } else {
                break;
            }
        }
        return value.substring(0, end);
    }

    private static boolean isIpv4(String value) {
        if (!value.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
            return false;
        }
        for (String part : value.split("\\.")) {
            if (Integer.parseInt(part) > 255) {
                return false;
            }
        }
        return true;
    }
}
