package modchecker.scan;

/** Ограничения ресурсов, а не правила определения вредоносности. */
public record ScanLimits(int maxEntries, long maxEntryBytes, long maxTotalBytes,
                         int maxNestedDepth, long maxDurationMillis, long maxClassBytes) {
    public static final ScanLimits DEFAULT = new ScanLimits(
            75_000, 64L << 20, 512L << 20, 2, 120_000, 8L << 20);

    public ScanLimits {
        if (maxEntries < 1 || maxEntryBytes < 1 || maxTotalBytes < 1
                || maxNestedDepth < 0 || maxDurationMillis < 1 || maxClassBytes < 1) {
            throw new IllegalArgumentException("Лимиты должны быть положительными");
        }
    }

    public void checkTime(long started) throws ScanLimitException {
        if (Thread.currentThread().isInterrupted()) {
            throw new ScanLimitException("проверка прервана");
        }
        if ((System.nanoTime() - started) / 1_000_000 > maxDurationMillis) {
            throw new ScanLimitException("превышено время проверки: " + maxDurationMillis / 1000 + " с");
        }
    }
}