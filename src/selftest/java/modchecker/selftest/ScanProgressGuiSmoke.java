package modchecker.selftest;

import com.sun.net.httpserver.HttpServer;
import modchecker.gui.ModCheckerFrame;
import modchecker.model.Verdict;
import modchecker.online.OnlineChecker;
import javax.swing.*;
import java.awt.Point;
import java.net.*;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.BooleanSupplier;

/** HTTP-ответы выпускаются вручную: проверки не зависят от скорости диска или сканера. */
final class ScanProgressGuiSmoke {
    static void run(Path clean, Path rat, Path output) throws Exception {
        Files.createDirectories(output);
        full(clean, rat, output);
        quick(output);
    }

    private static void full(Path clean, Path rat, Path output) throws Exception {
        Path dir = Files.createDirectories(output.resolve("full"));
        Files.copy(rat, dir.resolve("01-rat.jar"), StandardCopyOption.REPLACE_EXISTING);
        Files.copy(clean, dir.resolve("02-clean.jar"), StandardCopyOption.REPLACE_EXISTING);
        Files.copy(rat, dir.resolve("03-rat.jar"), StandardCopyOption.REPLACE_EXISTING);
        Files.copy(clean, dir.resolve("04-clean.jar"), StandardCopyOption.REPLACE_EXISTING);
        try (var sites = new GatedSites()) {
            ModCheckerFrame frame = frame(sites, dir);
            try {
                edt(() -> frame.startScan());
                sites.next().countDown();
                CountDownLatch second = sites.next();
                await(() -> frame.getReports().size() == 1);
                edt(() -> {
                    field(frame, "searchField", JTextField.class).setText(".jar");
                    frame.getResultTable().getRowSorter().setSortKeys(List.of(new RowSorter.SortKey(0, SortOrder.DESCENDING)));
                    frame.getResultTable().setRowSelectionInterval(0,0);
                    JTextArea details = field(frame,"detailsArea",JTextArea.class);
                    details.select(40,75);
                });
                AtomicReference<String> text = new AtomicReference<>();
                AtomicReference<Point> position = new AtomicReference<>();
                edt(() -> {
                    var scroll = field(frame,"detailsScroll",JScrollPane.class);
                    scroll.getViewport().setViewPosition(new Point(0,50));
                    text.set(field(frame,"detailsArea",JTextArea.class).getText());
                    position.set(scroll.getViewport().getViewPosition());
                });
                second.countDown();
                CountDownLatch third = sites.next();
                await(() -> frame.getReports().size() == 2);
                edt(() -> assertView(frame, text.get(), position.get()));
                System.out.println("[OK] GUI: новые результаты сохраняют выбранный файл, текст, выделение и прокрутку");
                edt(() -> {
                    JButton button = field(frame,"stopResumeButton",JButton.class);
                    button.doClick();
                    require(!button.isEnabled() && button.getText().equals("Останавливаю…"), "нет состояния остановки");
                });
                third.countDown();
                await(() -> !frame.isScanning());
                edt(() -> {
                    require(frame.getReports().size() == 3, "не завершён текущий файл");
                    JButton button = field(frame,"stopResumeButton",JButton.class);
                    require(button.isEnabled() && button.getText().equals("Продолжить"), "нет продолжения");
                    require(field(frame,"saveButton",JButton.class).isEnabled(), "нельзя экспортировать готовую часть");
                    assertView(frame,text.get(),position.get());
                    JProgressBar progress = field(frame,"progressBar",JProgressBar.class);
                    require(progress.getValue() == 3 && progress.getMaximum() == 4, "сброшен прогресс");
                    button.doClick();
                });
                sites.next().countDown();
                await(() -> !frame.isScanning());
                edt(() -> {
                    require(frame.getReports().size() == 4 && sites.requests.get() == 4, "продолжение повторило готовые файлы");
                    require(frame.getReports().stream().map(r -> r.scan().file()).distinct().count() == 4, "дублированы строки");
                    require(frame.getReports().stream().filter(r -> r.scan().name().contains("rat")).allMatch(r -> r.scan().verdict() == Verdict.DANGEROUS && r.scan().points() == 21), "изменён вердикт RAT");
                    require(!field(frame,"stopResumeButton",JButton.class).isEnabled(), "кнопка осталась активной после завершения");
                    assertView(frame,text.get(),position.get());
                });
                System.out.println("[OK] GUI: стоп/продолжить сохраняет очередь, прогресс и результаты полной проверки");
            } finally { edt(() -> frame.dispose()); }
        }
    }

    private static void quick(Path output) throws Exception {
        Path dir = Files.createDirectories(output.resolve("quick"));
        for(int i=0;i<203;i++) Files.writeString(dir.resolve(String.format("mod-%03d.jar",i)), "not a zip: " + i);
        try(var sites = new GatedSites()) {
            ModCheckerFrame frame = frame(sites,dir);
            try {
                edt(() -> frame.startOnlineCheck());
                sites.next().countDown();
                CountDownLatch second = sites.next();
                await(() -> frame.getReports().size() == 100);
                edt(() -> field(frame,"stopResumeButton",JButton.class).doClick());
                second.countDown();
                await(() -> !frame.isScanning());
                edt(() -> {
                    require(frame.getReports().size() == 200, "быстрая остановка потеряла текущий пакет");
                    require(field(frame,"stopResumeButton",JButton.class).getText().equals("Продолжить"), "не сохранена очередь быстрой проверки");
                    field(frame,"stopResumeButton",JButton.class).doClick();
                });
                sites.next().countDown();
                await(() -> !frame.isScanning());
                edt(() -> {
                    require(frame.getReports().size() == 203 && sites.requests.get() == 3, "повторены пакеты или потеряны строки");
                    require(frame.getReports().stream().allMatch(r -> !r.fullScan() && !r.scan().hasError()), "быстрый режим начал разбирать архивы");
                    require(frame.getReports().stream().map(r -> r.scan().file()).distinct().count() == 203, "дублированы быстрые результаты");
                });
                System.out.println("[OK] GUI: быстрая проверка останавливается и продолжается по пакетам без повторов");
            } finally { edt(() -> frame.dispose()); }
        }
    }

    private static void assertView(ModCheckerFrame frame, String text, Point position) {
        JTable table = frame.getResultTable();
        require(table.getValueAt(table.getSelectedRow(),0).equals("01-rat.jar"), "сброшен выбранный файл");
        JTextArea details = field(frame,"detailsArea",JTextArea.class);
        require(details.getText().equals(text) && details.getSelectionStart() == 40 && details.getSelectionEnd() == 75, "перерисованы подробности");
        require(field(frame,"detailsScroll",JScrollPane.class).getViewport().getViewPosition().equals(position), "сброшена прокрутка");
        require(field(frame,"searchField",JTextField.class).getText().equals(".jar"), "сброшен фильтр");
    }
    private static ModCheckerFrame frame(GatedSites sites, Path dir) throws Exception {
        AtomicReference<ModCheckerFrame> ref = new AtomicReference<>();
        edt(() -> {
            ModCheckerFrame frame = new ModCheckerFrame(key -> sites.checker(), dir.resolve("settings.properties"));
            ref.set(frame);
            field(frame,"rememberKeyCheck",JCheckBox.class).setSelected(false);
            field(frame,"keyField",JPasswordField.class).setText("");
            frame.setPath(dir.toString()); frame.pack(); frame.setSize(1220,860); frame.validate();
        });
        return ref.get();
    }
    private static void await(BooleanSupplier condition) throws Exception {
        long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(12);
        while (true) {
            AtomicBoolean ready = new AtomicBoolean(); edt(() -> ready.set(condition.getAsBoolean()));
            if (ready.get()) return;
            if (System.nanoTime() > end) throw new IllegalStateException("GUI не достиг ожидаемого состояния");
            Thread.sleep(20);
        }
    }
    private static void edt(Runnable task) throws Exception { SwingUtilities.invokeAndWait(task); }
    private static <T> T field(Object target,String name,Class<T> type) {
        try { var f=target.getClass().getDeclaredField(name); f.setAccessible(true); return type.cast(f.get(target)); }
        catch(ReflectiveOperationException e) { throw new IllegalStateException(e); }
    }
    private static void require(boolean value,String message) { if(!value) throw new IllegalStateException(message); }

    private static final class GatedSites implements AutoCloseable {
        final AtomicInteger requests = new AtomicInteger();
        final BlockingQueue<CountDownLatch> waiting = new LinkedBlockingQueue<>();
        final Queue<CountDownLatch> all = new ConcurrentLinkedQueue<>();
        final HttpServer server;
        GatedSites() throws Exception {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
            server.createContext("/mr", exchange -> {
                CountDownLatch release = new CountDownLatch(1); all.add(release); requests.incrementAndGet(); waiting.add(release);
                try {
                    exchange.getRequestBody().readAllBytes();
                    if (!release.await(10,TimeUnit.SECONDS)) throw new java.io.IOException("Test response not released");
                    byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(200,body.length); exchange.getResponseBody().write(body);
                } catch(InterruptedException e) { Thread.currentThread().interrupt(); }
                finally { exchange.close(); }
            });
            server.start();
        }
        OnlineChecker checker() { return new OnlineChecker(HttpClient.newHttpClient(),"", URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/mr"), URI.create("http://127.0.0.1:1/cf")); }
        CountDownLatch next() throws Exception {
            CountDownLatch gate = waiting.poll(8,TimeUnit.SECONDS);
            if(gate == null) throw new IllegalStateException("Не получен ожидаемый запрос");
            return gate;
        }
        public void close() { all.forEach(CountDownLatch::countDown); server.stop(0); }
    }
}
