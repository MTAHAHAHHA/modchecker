package modchecker.model;

/**
 * Дополнительные очки за сочетание нескольких находок.
 *
 * Связка - это не отдельное правило, поэтому она хранится отдельно от
 * Finding и показывает, из каких правил и мест она сложилась.
 */
public record LinkFinding(
        String name,
        int points,
        String location,
        String evidence,
        String firstLocation,
        String secondLocation
) {
}
