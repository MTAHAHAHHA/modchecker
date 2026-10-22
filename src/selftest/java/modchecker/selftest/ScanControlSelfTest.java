package modchecker.selftest;

import modchecker.app.ScanBatch;
import modchecker.model.Verdict;
import modchecker.report.ModReport;
import modchecker.scan.ScanLimits;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.*;

/** Паузы между файлами и пакетами, только на локальном HTTP-сервере. */
public final class ScanControlSelfTest {
    private ScanControlSelfTest() { }
    public static void full(Path mods, Path extra) throws Exception {
        var files = List.of(mods.resolve("clean.jar"), extra.resolve("fake_visual_rat.jar"), mods.resolve("stealer.jar"));
        try (var sites = new QuickCheckSelfTest.Sites()) {
            AtomicBoolean stop = new AtomicBoolean();
            var first = ScanBatch.scan(files, sites.checker(""), (done,total,report) -> stop.set(true), ScanLimits.DEFAULT, stop::get);
            require(first.size() == 1 && first.get(0).scan().file().equals(files.get(0)), "полная проверка не остановилась после файла");
            var combined = new ArrayList<>(first);
            combined.addAll(ScanBatch.scan(files.subList(first.size(), files.size()), sites.checker(""), null));
            require(combined.size() == 3 && sites.mrRequests.get() == 3, "продолжение повторило готовые файлы");
            require(combined.get(1).scan().verdict() == Verdict.DANGEROUS && combined.get(1).scan().points() == 21, "пауза изменила обнаружение RAT");
            int requests = sites.mrRequests.get();
            require(ScanBatch.scan(files, sites.checker(""), null, ScanLimits.DEFAULT, () -> true).isEmpty()
                    && sites.mrRequests.get() == requests, "стоп до начала не сработал");
        }
    }
    public static void duringHashing(Path temp) throws Exception {
        var files = files(temp, "stop-hash", 5);
        try (var sites = new QuickCheckSelfTest.Sites()) {
            AtomicBoolean stop = new AtomicBoolean();
            AtomicInteger hashes = new AtomicInteger();
            var first = ScanBatch.checkSites(files, sites.checker(""), null,
                    (done,total) -> { hashes.incrementAndGet(); if (done == 2) stop.set(true); }, stop::get);
            require(first.size() == 2 && hashes.get() == 2, "стоп во время хеширования потерял границу файлов");
            var all = new ArrayList<>(first);
            all.addAll(ScanBatch.checkSites(files.subList(2, files.size()), sites.checker(""), null,
                    (done,total) -> hashes.incrementAndGet()));
            require(all.size() == 5 && hashes.get() == 5 && sites.mrRequests.get() == 2, "повторно прочитан готовый префикс");
            assertPrefix(files, all);
            require(ScanBatch.checkSites(files, sites.checker(""), null, null, () -> true).isEmpty(), "стоп до быстрой проверки не сработал");
        }
    }
    public static void betweenBatches(Path temp) throws Exception {
        var files = files(temp, "stop-batches", 103);
        try (var sites = new QuickCheckSelfTest.Sites()) {
            AtomicBoolean stop = new AtomicBoolean();
            AtomicInteger hashes = new AtomicInteger();
            var first = ScanBatch.checkSites(files, sites.checker(""), (done,total,report) -> stop.set(true),
                    (done,total) -> hashes.incrementAndGet(), stop::get);
            require(first.size() == 100 && hashes.get() == 100 && sites.mrRequests.get() == 1, "не завершён только текущий пакет");
            var all = new ArrayList<>(first);
            all.addAll(ScanBatch.checkSites(files.subList(100, files.size()), sites.checker(""), null,
                    (done,total) -> hashes.incrementAndGet()));
            require(hashes.get() == 103 && sites.mrRequests.get() == 2, "продолжение дублирует пакет");
            assertPrefix(files, all);
        }
    }
    private static List<Path> files(Path temp, String name, int count) throws Exception {
        Path dir = Files.createDirectories(temp.resolve(name));
        List<Path> files = new ArrayList<>();
        for (int i=0;i<count;i++) files.add(Files.writeString(dir.resolve(i + ".jar"), "not a zip " + i));
        return files;
    }
    private static void assertPrefix(List<Path> files, List<ModReport> reports) {
        require(reports.size() == files.size(), "потеряны строки");
        for (int i=0;i<files.size();i++) require(reports.get(i).scan().file().equals(files.get(i))
                && !reports.get(i).fullScan() && reports.get(i).scan().findings().isEmpty(), "изменены порядок или режим");
    }
    private static void require(boolean value, String message) { if (!value) throw new IllegalStateException(message); }
}
