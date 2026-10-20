package modchecker.report;

import modchecker.model.ModScanResult;
import modchecker.online.OnlineCheckResult;

/**
 * Всё, что нужно для одной строки итогового отчёта.
 */
public record ModReport(
        ModScanResult scan,
        OnlineCheckResult online
) {
}
