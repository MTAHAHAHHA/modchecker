package modchecker.model;

/**
 * Одна находка в моде. Правило считается один раз на мод, поэтому
 * ModScanResult хранит не больше одной находки с одинаковым номером правила.
 */
public record Finding(
        int rule,
        String title,
        int points,
        String location,
        String evidence
) {
}
