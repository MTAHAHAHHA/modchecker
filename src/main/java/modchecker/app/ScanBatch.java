package modchecker.app;

import modchecker.model.ModScanResult;
import modchecker.online.OnlineCheckResult;
import modchecker.online.OnlineChecker;
import modchecker.report.ModReport;
import modchecker.scan.ScanService;
import modchecker.trust.TrustedHashes;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Общий проход по списку модов: сканирование файла и онлайн-проверка.
 * Не содержит правил и не пересчитывает очки.
 */
public final class ScanBatch {

    @FunctionalInterface
    public interface Listener {
        void modScanned(int completed, int total, ModReport report);
    }

    private ScanBatch() {
    }

    public static List<ModReport> scan(List<Path> mods, OnlineChecker onlineChecker,
                                       Listener listener) {
        ScanService scanner = new ScanService();
        List<ModReport> reports = new ArrayList<>();

        for (int i = 0; i < mods.size(); i++) {
            Path mod = mods.get(i);
            ModScanResult scan = scanner.scan(mod);
            OnlineCheckResult online = onlineChecker.check(mod, scan);
            applyManualTrust(mod, scan, online);
            ModReport report = new ModReport(scan, online);
            reports.add(report);

            if (listener != null) {
                listener.modScanned(i + 1, mods.size(), report);
            }
        }

        return reports;
    }

    /**
     * Ручное доверие применяется после сканирования и онлайн-проверки:
     * SHA-1 уже известен, а все находки остаются в результате.
     */
    private static void applyManualTrust(Path mod, ModScanResult scan,
                                         OnlineCheckResult online) {
        if (scan.hasError() || online.sha1() == null) {
            return;
        }
        try {
            TrustedHashes.find(mod, online.sha1()).ifPresent(entry ->
                    scan.markManuallyTrusted(
                            entry.source().toString(), entry.comment()));
        } catch (IOException ignored) {
            // Нечитаемый trusted_hashes.txt не должен ломать проверку мода.
        }
    }
}
