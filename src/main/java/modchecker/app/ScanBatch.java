package modchecker.app;

import modchecker.model.ModScanResult;
import modchecker.online.OnlineCheckResult;
import modchecker.online.OnlineChecker;
import modchecker.report.ModReport;
import modchecker.scan.ScanService;
import modchecker.scan.ScanLimits;
import modchecker.trust.TrustedHashes;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.BooleanSupplier;

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
        return scan(mods, onlineChecker, listener, ScanLimits.DEFAULT);
    }

    public static List<ModReport> scan(List<Path> mods, OnlineChecker onlineChecker,
                                       Listener listener, ScanLimits limits) {
        return scan(mods, onlineChecker, listener, limits, () -> false);
    }

    /** Останавливается между файлами, сохраняя полностью готовые результаты. */
    public static List<ModReport> scan(List<Path> mods, OnlineChecker onlineChecker,
                                       Listener listener, ScanLimits limits, BooleanSupplier stopRequested) {
        ScanService scanner = new ScanService(limits);
        List<ModReport> reports = new ArrayList<>();

        for (int i = 0; i < mods.size(); i++) {
            if (stopRequested.getAsBoolean()) break;
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

    /** Сверка с сайтами без ScanService, JarWalker и ASM. */
    public static List<ModReport> checkSites(List<Path> mods, OnlineChecker checker,
                                             Listener listener,
                                             BiConsumer<Integer, Integer> hashingProgress) {
        return checkSites(mods, checker, listener, hashingProgress, () -> false);
    }

    public static List<ModReport> checkSites(List<Path> mods, OnlineChecker checker,
                                             Listener listener, BiConsumer<Integer, Integer> hashingProgress,
                                             BooleanSupplier stopRequested) {
        List<ModReport> reports = new ArrayList<>();
        for (int start = 0; start < mods.size() && !stopRequested.getAsBoolean(); start += 100) {
            final int offset = start;
            List<OnlineCheckResult> online = checker.checkFiles(
                    mods.subList(start, Math.min(start + 100, mods.size())),
                    (hashed, total) -> { if (hashingProgress != null) hashingProgress.accept(offset + hashed, mods.size()); },
                    stopRequested);
            for (int i = 0; i < online.size(); i++) {
                ModScanResult scan = new ModScanResult(mods.get(start + i));
                if (online.get(i).sha1() == null) {
                    scan.markError("не удалось прочитать файл и вычислить SHA-1");
                } else if (online.get(i).confirmed()) {
                    scan.markOnlineConfirmed();
                }
                ModReport report = new ModReport(scan, online.get(i), false);
                reports.add(report);
                if (listener != null) {
                    listener.modScanned(reports.size(), mods.size(), report);
                }
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
