package modchecker.model;

/**
 * Место, где найдено доказательство для правила связки.
 *
 * scope отделяет основной код мода от конкретного вложенного jar:
 * находки из разных архивов не должны складываться в одну связку.
 */
public record EvidenceLocation(
        int rule,
        String location,
        String scope
) {
}
