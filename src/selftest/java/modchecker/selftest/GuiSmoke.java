package modchecker.selftest;

import modchecker.app.ScanBatch;
import modchecker.gui.ModCheckerFrame;
import modchecker.gui.ModTableModel;
import modchecker.online.OnlineChecker;
import modchecker.report.ModReport;
import modchecker.scan.ModFinder;

import javax.swing.JTable;
import javax.swing.SwingUtilities;
import java.awt.GraphicsEnvironment;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Проверка настоящего GUI на папке build/testmods.
 * Окно открывается, сканирование идёт в SwingWorker, затем печатается таблица.
 */
public final class GuiSmoke {

    private GuiSmoke() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            throw new IllegalArgumentException("Нужен путь к папке с тестовыми модами");
        }

        Path mods = Path.of(args[0]).toAbsolutePath().normalize();
        if (!GraphicsEnvironment.isHeadless()) {
            runGui(mods);
            return;
        }

        System.out.println("GUI: headless, проверяю таблицу через модель");
        List<Path> jars = ModFinder.find(mods);
        List<ModReport> reports = ScanBatch.scan(jars, new OnlineChecker(""), null);
        ModTableModel model = new ModTableModel();
        model.setReports(reports);
        printModel(model);
    }

    private static void runGui(Path mods) throws Exception {
        System.out.println("GUI: открываю окно на " + mods);
        AtomicReference<ModCheckerFrame> frameRef = new AtomicReference<>();

        SwingUtilities.invokeAndWait(() -> {
            ModCheckerFrame frame = new ModCheckerFrame();
            frame.setPath(mods.toString());
            frame.setVisible(true);
            frameRef.set(frame);
            frame.startScan();
        });

        ModCheckerFrame frame = frameRef.get();
        long deadline = System.currentTimeMillis() + 180_000L;
        while (frame.isScanning() && System.currentTimeMillis() < deadline) {
            Thread.sleep(100L);
        }
        Thread.sleep(500L);

        AtomicReference<String> output = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            output.set(collectTable(frame.getResultTable()));
            frame.dispose();
        });

        System.out.print(output.get());
        if (frame.isScanning()) {
            System.out.println("GUI: TIMEOUT");
            System.exit(2);
        }
        System.exit(0);
    }

    private static String collectTable(JTable table) {
        StringBuilder out = new StringBuilder();
        out.append("=== GUI TABLE ===\n");
        out.append("Мод | Вердикт | Очки | Modrinth | CurseForge\n");
        for (int viewRow = 0; viewRow < table.getRowCount(); viewRow++) {
            out.append(table.getValueAt(viewRow, 0)).append(" | ")
                    .append(table.getValueAt(viewRow, 1)).append(" | ")
                    .append(table.getValueAt(viewRow, 2)).append(" | ")
                    .append(table.getValueAt(viewRow, 3)).append(" | ")
                    .append(table.getValueAt(viewRow, 4)).append('\n');
        }
        return out.toString();
    }

    private static void printModel(ModTableModel model) {
        var sorter = ModTableModel.createSorter(model);
        sorter.sort();

        System.out.println("=== GUI TABLE (model) ===");
        System.out.println("Мод | Вердикт | Очки | Modrinth | CurseForge");
        for (int viewRow = 0; viewRow < model.getRowCount(); viewRow++) {
            int modelRow = sorter.convertRowIndexToModel(viewRow);
            ModReport report = model.reportAt(modelRow);
            System.out.println(report.scan().name() + " | "
                    + report.scan().verdict().label() + " | "
                    + report.scan().points() + " | "
                    + report.online().modrinth().label() + " | "
                    + report.online().curseForge().label());
        }
    }
}
