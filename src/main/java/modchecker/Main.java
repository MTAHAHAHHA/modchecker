package modchecker;

import modchecker.app.ScanBatch;
import modchecker.gui.ModCheckerFrame;
import modchecker.online.OnlineChecker;
import modchecker.report.ModReport;
import modchecker.report.ReportPrinter;
import modchecker.scan.ModFinder;

import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import java.awt.GraphicsEnvironment;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.List;

/**
 * Точка входа программы ModChecker.
 *
 * Без аргументов открывает окно. С одним аргументом работает старый
 * консольный режим: сканирует jar-файлы и образцы .jar.sample, считает
 * очки, проверяет SHA-1 на Modrinth и отпечаток CurseForge, затем печатает
 * отчёт.
 */
public final class Main {

    private Main() {
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            launchGui();
            return;
        }

        if (args.length != 1) {
            System.out.println("Использование: java -jar modchecker.jar "
                    + "[папка mods, один .jar или .jar.sample]");
            System.out.println("Без аргументов открывается графическое окно.");
            return;
        }

        Path target;
        try {
            target = Path.of(args[0]).toAbsolutePath().normalize();
        } catch (InvalidPathException e) {
            System.out.println("ОШИБКА: некорректный путь: " + args[0]);
            return;
        }

        if (!Files.exists(target)) {
            System.out.println("ОШИБКА: путь не существует: " + target);
            return;
        }

        List<Path> mods;
        try {
            mods = ModFinder.find(target);
        } catch (IOException e) {
            System.out.println("ОШИБКА: не удалось прочитать папку: " + e.getMessage());
            return;
        }

        System.out.println("ModChecker 0.1.0 - шаг 7");
        System.out.println("Цель: " + target);
        System.out.println("Найдено модов: " + mods.size());

        if (mods.isEmpty()) {
            System.out.println("Jar-файлы (.jar, .jar.sample) не найдены.");
            ReportPrinter.print(List.of(), System.out);
            return;
        }

        List<ModReport> reports = ScanBatch.scan(mods, new OnlineChecker(), null);
        ReportPrinter.print(reports, System.out);
    }

    private static void launchGui() {
        if (GraphicsEnvironment.isHeadless()) {
            System.out.println("ОШИБКА: графический режим недоступен (headless).");
            System.out.println("Запустите с путём: java -jar modchecker.jar "
                    + "<папка mods, один .jar или .jar.sample>");
            return;
        }

        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {
            // Остаёмся на стандартном виде Swing.
        }

        SwingUtilities.invokeLater(() -> new ModCheckerFrame().setVisible(true));
    }
}
