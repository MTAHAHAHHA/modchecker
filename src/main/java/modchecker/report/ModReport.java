package modchecker.report;

import modchecker.model.ModScanResult;
import modchecker.online.OnlineCheckResult;
import modchecker.online.OnlineStatus;

/** Результат полной проверки или только сверки файла с сайтами. */
public record ModReport(ModScanResult scan, OnlineCheckResult online, boolean fullScan) {
    public ModReport(ModScanResult scan, OnlineCheckResult online) {
        this(scan, online, true);
    }

    public boolean needsFullScan() {
        return !fullScan && !scan.hasError() && !online.confirmed();
    }

    public String statusLabel() {
        if (fullScan || scan.hasError()) {
            return scan.verdict().label();
        }
        if (online.confirmed()) {
            return "ПОДТВЕРЖДЁН НА САЙТЕ";
        }
        if (online.modrinth() == OnlineStatus.NOT_FOUND
                && online.curseForge() == OnlineStatus.NOT_FOUND) {
            return "НЕ НАЙДЕН НА САЙТАХ";
        }
        if (online.modrinth() != OnlineStatus.NOT_FOUND
                && online.curseForge() != OnlineStatus.NOT_FOUND) {
            return "ПРОВЕРКА НЕДОСТУПНА";
        }
        return "НЕТ ПОДТВЕРЖДЕНИЯ";
    }
}