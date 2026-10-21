package modchecker.model;

/**
 * Ссылка, домен, IP-адрес или токен, найденный в моде. Это не находка
 * и не очки, а материал для ручной проверки.
 */
public record FoundEntity(String kind, String value, String location) {
}
