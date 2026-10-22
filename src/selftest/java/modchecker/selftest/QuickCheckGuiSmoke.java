package modchecker.selftest;

import modchecker.gui.ModCheckerFrame;
import modchecker.model.Verdict;
import modchecker.online.Hashes;
import javax.swing.*;
import java.awt.GraphicsEnvironment;
import java.awt.image.BufferedImage;
import java.nio.file.*;
import java.util.concurrent.atomic.AtomicReference;
import javax.imageio.ImageIO;

/** Проверяет переходы SwingWorker в скрытом окне, с локальными ответами сайтов. */
public final class QuickCheckGuiSmoke {
    public static void main(String[] args) throws Exception {
        if (GraphicsEnvironment.isHeadless()) {
            System.out.println("GUI недоступен; сетевые сценарии покрыты selfTest.");
            return;
        }
        Path dir = Files.createDirectories(Path.of(args[2]));
        Path clean = dir.resolve("clean.jar").toAbsolutePath();
        Path rat = dir.resolve("rat.jar").toAbsolutePath();
        Files.copy(Path.of(args[0], "clean.jar"), clean, StandardCopyOption.REPLACE_EXISTING);
        Files.copy(Path.of(args[1], "fake_visual_rat.jar"), rat, StandardCopyOption.REPLACE_EXISTING);
        AtomicReference<ModCheckerFrame> reference = new AtomicReference<>();
        try (var sites = new QuickCheckSelfTest.Sites()) {
            sites.modrinth.add(Hashes.sha1(clean));
            SwingUtilities.invokeAndWait(() -> {
                var frame = new ModCheckerFrame(key -> sites.checker(""));
                reference.set(frame);
                field(frame, "rememberKeyCheck", JCheckBox.class).setSelected(false);
                field(frame, "keyField", JPasswordField.class).setText("");
                frame.setPath(dir.toAbsolutePath().toString());
                frame.pack();
                frame.setSize(1100, 760);
                frame.validate();
                frame.startOnlineCheck();
            });
            await(reference.get());
            SwingUtilities.invokeAndWait(() -> {
                var frame = reference.get();
                require(frame.getReports().size() == 2, "ожидалось две строки");
                require(frame.getReports().stream().allMatch(report -> !report.fullScan()),
                        "быстрая проверка неожиданно разобрала код");
                require(field(frame, "fullSelectedButton", JButton.class).isEnabled()
                                && field(frame, "fullUnconfirmedButton", JButton.class).isEnabled(),
                        "нет кнопок продолжения для неподтверждённого файла");
                require(frame.getResultTable().getValueAt(0, 0).equals("rat.jar"),
                        "неподтверждённый файл должен быть выбран первым");
                var image = new BufferedImage(1100, 760, BufferedImage.TYPE_INT_RGB);
                var graphics = image.createGraphics();
                frame.getContentPane().printAll(graphics);
                graphics.dispose();
                try { ImageIO.write(image, "png", dir.resolve("quick-mode.png").toFile()); }
                catch (Exception e) { throw new IllegalStateException(e); }
                field(frame, "fullSelectedButton", JButton.class).doClick();
            });
            await(reference.get());
            assertUpgraded(reference.get());
            System.out.println("[OK] GUI: быстрая проверка -> полная выбранного; строки сохранены, RAT обнаружен");
            SwingUtilities.invokeAndWait(() -> reference.get().startOnlineCheck());
            await(reference.get());
            SwingUtilities.invokeAndWait(() ->
                    field(reference.get(), "fullUnconfirmedButton", JButton.class).doClick());
            await(reference.get());
            assertUpgraded(reference.get());
            System.out.println("[OK] GUI: полная проверка неподтверждённых; подтверждённый мод не анализировался");
        } finally {
            if (reference.get() != null) SwingUtilities.invokeAndWait(() -> reference.get().dispose());
        }
    }

    private static void assertUpgraded(ModCheckerFrame frame) throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            require(frame.getReports().size() == 2, "дублированы или удалены строки");
            var rat = frame.getReports().stream().filter(report -> report.scan().name().equals("rat.jar"))
                    .findFirst().orElseThrow();
            var clean = frame.getReports().stream().filter(report -> report.scan().name().equals("clean.jar"))
                    .findFirst().orElseThrow();
            require(rat.fullScan() && rat.scan().verdict() == Verdict.DANGEROUS && rat.scan().points() == 21,
                    "полная проверка должна обнаружить RAT");
            require(!clean.fullScan() && clean.online().confirmed(), "проверен лишний файл");
            require(!field(frame, "fullUnconfirmedButton", JButton.class).isEnabled(),
                    "неподтверждённых файлов для проверки больше нет");
            require(field(frame, "sitesButton", JButton.class).isEnabled()
                            && field(frame, "scanButton", JButton.class).isEnabled(),
                    "кнопки не восстановились после SwingWorker");
        });
    }

    private static void await(ModCheckerFrame frame) throws Exception {
        long deadline = System.nanoTime() + 20_000_000_000L;
        while (frame.isScanning()) {
            if (System.nanoTime() > deadline) throw new IllegalStateException("GUI завис");
            Thread.sleep(25);
        }
        SwingUtilities.invokeAndWait(() -> { });
    }

    private static <T> T field(Object owner, String name, Class<T> type) {
        try {
            var field = owner.getClass().getDeclaredField(name);
            field.setAccessible(true);
            return type.cast(field.get(owner));
        } catch (ReflectiveOperationException e) { throw new IllegalStateException(e); }
    }

    private static void require(boolean value, String message) {
        if (!value) throw new IllegalStateException(message);
    }
}