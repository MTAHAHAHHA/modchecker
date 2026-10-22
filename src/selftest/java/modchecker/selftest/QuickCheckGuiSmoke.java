package modchecker.selftest;

import modchecker.gui.ModCheckerFrame;
import modchecker.gui.ThemeManager;
import modchecker.app.ScanSettings;
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
                var frame = new ModCheckerFrame(key -> sites.checker(""), dir.resolve("scan-settings.properties"));
                reference.set(frame);
                field(frame, "rememberKeyCheck", JCheckBox.class).setSelected(false);
                field(frame, "keyField", JPasswordField.class).setText("");
                field(frame, "vtKeyField", JPasswordField.class).setText("");
                field(frame, "unlimitedArchivesCheck", JCheckBox.class).setSelected(false);
                frame.setPath(dir.toAbsolutePath().toString());
                frame.pack();
                frame.setSize(1100, 760);
                frame.validate();
                require(frame.getResultTable().getRowCount() == 0
                        && field(frame, "emptyTitle", JLabel.class).getText().equals("Результатов пока нет"), "нет начальной подсказки");
                require(!SwingUtilities.isDescendingFrom(field(frame, "keyField", JPasswordField.class), frame.getContentPane()), "ключ остался на главном экране");
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
            SwingUtilities.invokeAndWait(() -> modernUi(reference.get(), dir));
            checkArchiveLimits(reference.get(), dir);
            SwingUtilities.invokeAndWait(() -> {
                field(reference.get(), "modeCombo", JComboBox.class).setSelectedIndex(1);
                field(reference.get(), "scanButton", JButton.class).doClick();
            });
            await(reference.get());
            SwingUtilities.invokeAndWait(() -> require(reference.get().getReports().stream().allMatch(r -> r.fullScan()), "переключатель полной проверки не работает"));
            System.out.println("[OK] GUI: основной переключатель режима запускает полную проверку");
        } finally {
            if (reference.get() != null) SwingUtilities.invokeAndWait(() -> {
                reference.get().dispose();
                for (var window : java.awt.Window.getWindows()) window.dispose();
            });
        }
    }

    private static void checkArchiveLimits(ModCheckerFrame frame, Path dir) throws Exception {
        Path archive = Files.createDirectories(dir.resolveSibling(dir.getFileName() + "-limits")).resolve("large-class.jar");
        try (var out = new java.util.zip.ZipOutputStream(Files.newOutputStream(archive))) {
            out.putNextEntry(new java.util.zip.ZipEntry("Large.class"));
            out.write(new byte[(8 << 20) + 1]);
            out.closeEntry();
        }
        SwingUtilities.invokeAndWait(() -> { frame.setPath(archive.toString()); frame.startScan(); });
        await(frame);
        SwingUtilities.invokeAndWait(() -> {
            require(frame.getReports().get(0).scan().hasError(), "лимит класса по умолчанию не работает");
            field(frame, "unlimitedArchivesCheck", JCheckBox.class).doClick();
            require(ScanSettings.load(dir.resolve("scan-settings.properties")).unlimitedArchives(), "не сохранён выбор без лимитов");
            JButton retry = field(frame, "fullSelectedButton", JButton.class);
            require(retry.isEnabled(), "нельзя повторить проверку файла после снятия лимита");
            retry.doClick();
        });
        await(frame);
        SwingUtilities.invokeAndWait(() -> {
            require(!frame.getReports().get(0).scan().hasError(), "переключатель не передан в фоновую проверку");
            field(frame, "unlimitedArchivesCheck", JCheckBox.class).doClick();
            frame.setPath(dir.toString());
        });
        System.out.println("[OK] GUI: отключение лимитов сохраняется и применяется при проверке");
    }

    private static void modernUi(ModCheckerFrame frame, Path dir) {
        var search = field(frame, "searchField", JTextField.class);
        search.setText("rat.jar"); require(frame.getResultTable().getRowCount() == 1, "поиск не фильтрует таблицу");
        search.setText("no-such-file");
        require(frame.getResultTable().getRowCount() == 0 && frame.getReports().size() == 2
                && field(frame, "emptyTitle", JLabel.class).getText().equals("Ничего не найдено"), "фильтр удалил результаты или нет подсказки");
        search.setText("");
        var result = field(frame, "resultFilter", JComboBox.class);
        result.setSelectedItem("Вердикт: ОПАСНО"); require(frame.getResultTable().getRowCount() == 1, "фильтр вердикта не работает");
        result.setSelectedIndex(0);
        var rule = field(frame, "ruleFilter", JComboBox.class);
        rule.setSelectedIndex(24); require(frame.getResultTable().getRowCount() == 1, "фильтр правила не работает");
        rule.setSelectedIndex(0);
        System.out.println("[OK] GUI: поиск, фильтры и пустое состояние сохраняют результаты");
        var toggle = field(frame, "detailsToggle", JToggleButton.class);
        toggle.doClick(); require(!field(frame, "detailsScroll", JScrollPane.class).isVisible(), "подробности не сворачиваются");
        toggle.doClick(); require(field(frame, "detailsScroll", JScrollPane.class).isVisible(), "подробности не раскрываются");
        var split = field(frame, "resultsSplit", JSplitPane.class);
        split.setDividerLocation(260); require(split.getDividerLocation() == 260, "высота подробностей заблокирована");
        System.out.println("[OK] GUI: подробности сворачиваются и меняют высоту");
        try {
            var method = frame.getClass().getDeclaredMethod("ensureSettingsDialog"); method.setAccessible(true); method.invoke(frame);
            var dialog = field(frame, "settingsDialog", JDialog.class);
            require(SwingUtilities.isDescendingFrom(field(frame, "keyField", JPasswordField.class), dialog)
                    && SwingUtilities.isDescendingFrom(field(frame, "vtKeyField", JPasswordField.class), dialog), "ключи не в отдельном окне");
            var screen = GraphicsEnvironment.getLocalGraphicsEnvironment().getMaximumWindowBounds();
            require(dialog.getWidth() >= Math.min(840, screen.width) && dialog.getHeight() >= Math.min(760, screen.height),
                    "окно настроек по-прежнему открывается маленьким");
            require(SwingUtilities.isDescendingFrom(field(frame, "unlimitedArchivesCheck", JCheckBox.class), dialog), "нет переключателя лимитов в настройках");
            dialog.validate();
            snapshot(dialog, dir.resolve("settings-window.png"));
        } catch (ReflectiveOperationException e) { throw new IllegalStateException(e); }
        System.out.println("[OK] GUI: настройки ключей находятся в отдельном окне");
        boolean originalDark = ThemeManager.isDark();
        for (boolean dark : new boolean[]{true, false}) {
            ThemeManager.apply(dark, false);
            require(ThemeManager.isDark() == dark, "тема не переключилась");
            frame.setSize(1220, 860); frame.validate();
            snapshot(frame, dir.resolve(dark ? "modern-dark.png" : "modern-light.png"));
            frame.setSize(frame.getMinimumSize()); frame.validate();
            JButton button = field(frame, "scanButton", JButton.class);
            var bounds = SwingUtilities.convertRectangle(button.getParent(), button.getBounds(), frame.getContentPane());
            require(bounds.x >= 0 && bounds.x + bounds.width <= frame.getContentPane().getWidth(), "кнопка проверки не помещается при уменьшении окна");
            require(frame.getResultTable().getParent().getHeight() >= frame.getResultTable().getRowHeight() * 2,
                    "таблица исчезла при уменьшении окна");
            snapshot(frame, dir.resolve(dark ? "modern-dark-small.png" : "modern-light-small.png"));
        }
        ThemeManager.apply(originalDark, false);
        System.out.println("[OK] GUI: светлая/тёмная темы и минимальный размер окна");
    }
    private static void snapshot(RootPaneContainer frame, Path path) {
        var image = new BufferedImage(frame.getContentPane().getWidth(), frame.getContentPane().getHeight(), BufferedImage.TYPE_INT_RGB);
        var graphics = image.createGraphics(); frame.getContentPane().printAll(graphics); graphics.dispose();
        try { ImageIO.write(image, "png", path.toFile()); }
        catch (Exception e) { throw new IllegalStateException(e); }
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
