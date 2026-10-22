package modchecker.gui;

import modchecker.app.ScanBatch;
import modchecker.model.Verdict;
import modchecker.online.CurseForgeKeyStore;
import modchecker.online.KeyCheckStatus;
import modchecker.online.OnlineChecker;
import modchecker.report.ModReport;
import modchecker.report.ReportPrinter;
import modchecker.scan.ModFinder;
import modchecker.trust.TrustedHashes;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JToggleButton;
import javax.swing.ListSelectionModel;
import javax.swing.SwingWorker;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.TableCellRenderer;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTarget;
import java.awt.dnd.DropTargetAdapter;
import java.awt.dnd.DropTargetDropEvent;
import java.awt.event.ItemEvent;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutionException;
import java.util.function.Function;

/**
 * Простое Swing-окно. Вся проверка выполняется существующими
 * ScanService / OnlineChecker / ReportPrinter.
 */
public final class ModCheckerFrame extends JFrame {

    private static final Color DANGEROUS_BACKGROUND = new Color(255, 165, 165);
    private static final Color SUSPICIOUS_BACKGROUND = new Color(255, 225, 225);
    private static final Color UNKNOWN_BACKGROUND = new Color(255, 248, 195);
    private static final Color TRUSTED_BACKGROUND = new Color(220, 235, 255);
    private static final Color OK_BACKGROUND = new Color(225, 245, 225);
    private static final Color ERROR_BACKGROUND = new Color(230, 230, 230);

    private final ModTableModel tableModel = new ModTableModel();
    private final JTextField pathField = new JTextField();
    private final JButton folderButton = new JButton("Папка...");
    private final JButton jarButton = new JButton("Файл .jar/.sample...");
    private final JButton scanButton = new JButton("Полная проверка");
    private final JButton sitesButton = new JButton("Проверить на сайтах");
    private final JButton fullSelectedButton = new JButton("Полная проверка выбранного");
    private final JButton fullUnconfirmedButton = new JButton("Полная проверка неподтверждённых");
    private final JButton saveButton = new JButton("Сохранить отчёт");
    private final JButton trustButton = new JButton("Доверять этому файлу");
    private final JButton untrustButton = new JButton("Убрать из доверенных");
    private final JProgressBar progressBar = new JProgressBar();
    private final JTable table = new JTable(tableModel) {
        @Override
        public Component prepareRenderer(TableCellRenderer renderer, int row, int column) {
            Component component = super.prepareRenderer(renderer, row, column);
            if (!isRowSelected(row)) {
                int modelRow = convertRowIndexToModel(row);
                ModReport report = tableModel.reportAt(modelRow);
                Verdict verdict = report.scan().verdict();
                component.setBackground(!report.fullScan() && !report.scan().hasError()
                        ? (report.online().confirmed() ? TRUSTED_BACKGROUND : UNKNOWN_BACKGROUND)
                        : backgroundFor(verdict));
                component.setForeground(Color.BLACK);
            }
            return component;
        }
    };
    private final JTextArea detailsArea = new JTextArea();
    private final JLabel totalsLabel = new JLabel();
    private final JLabel statusLabel = new JLabel("готов");
    private final JPasswordField keyField = new JPasswordField(24);
    private final JToggleButton showKeyButton = new JToggleButton("Показать");
    private final JButton checkKeyButton = new JButton("Проверить ключ");
    private final JCheckBox rememberKeyCheck = new JCheckBox("Запомнить ключ");
    private final JButton deleteKeyButton = new JButton("Удалить ключ");
    private final JLabel keyStatusLabel = new JLabel("ключ не задан - CurseForge пропускается");

    private final List<ModReport> reports = new ArrayList<>();
    private volatile boolean scanning;
    private final Function<String, OnlineChecker> checkerFactory;

    public ModCheckerFrame() {
        this(OnlineChecker::new);
    }

    public ModCheckerFrame(Function<String, OnlineChecker> checkerFactory) {
        super("ModChecker 1.2");
        this.checkerFactory = checkerFactory;
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setMinimumSize(new Dimension(900, 650));
        setSize(1100, 760);
        setLocationRelativeTo(null);

        buildUi();
        installDropTargets(getContentPane());
        loadDefaultPath();
        loadSavedKey();

        rememberKeyCheck.addItemListener(event -> {
            if (event.getStateChange() == ItemEvent.SELECTED) {
                String key = currentKey();
                if (!key.isEmpty()) {
                    saveKey(key, false);
                }
            }
        });
    }

    public void setPath(String path) {
        pathField.setText(path);
    }

    public JTable getResultTable() {
        return table;
    }

    public boolean isScanning() {
        return scanning;
    }

    public List<ModReport> getReports() {
        return List.copyOf(reports);
    }

    private void buildUi() {
        setLayout(new BorderLayout(8, 8));

        JPanel top = new JPanel();
        top.setLayout(new javax.swing.BoxLayout(top, javax.swing.BoxLayout.Y_AXIS));
        top.setBorder(BorderFactory.createEmptyBorder(8, 8, 0, 8));
        top.add(buildPathPanel());
        top.add(buildKeyPanel());
        top.add(buildActionPanel());
        add(top, BorderLayout.NORTH);
        add(buildResultsPanel(), BorderLayout.CENTER);
        add(buildFooterPanel(), BorderLayout.SOUTH);

        updateTotals();
    }

    private JPanel buildPathPanel() {
        JPanel panel = new JPanel(new BorderLayout(6, 0));
        panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 4, 0));
        panel.add(new JLabel("Путь:"), BorderLayout.WEST);

        pathField.setToolTipText("Папка с модами, один .jar или .jar.sample");
        panel.add(pathField, BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        folderButton.addActionListener(event -> chooseFolder());
        jarButton.addActionListener(event -> chooseJar());
        buttons.add(folderButton);
        buttons.add(jarButton);
        panel.add(buttons, BorderLayout.EAST);
        return panel;
    }

    private JPanel buildKeyPanel() {
        JPanel panel = new JPanel(new BorderLayout(6, 2));
        panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 4, 0));

        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        row.add(new JLabel("Ключ CurseForge:"));

        keyField.setEchoChar('*');
        keyField.setPreferredSize(new Dimension(260, keyField.getPreferredSize().height));
        row.add(keyField);

        showKeyButton.addActionListener(event -> toggleKeyVisibility());
        row.add(showKeyButton);

        checkKeyButton.addActionListener(event -> checkKey());
        row.add(checkKeyButton);
        row.add(rememberKeyCheck);

        deleteKeyButton.addActionListener(event -> deleteSavedKey());
        row.add(deleteKeyButton);

        panel.add(row, BorderLayout.CENTER);
        keyStatusLabel.setFont(keyStatusLabel.getFont().deriveFont(Font.PLAIN, 11f));
        keyStatusLabel.setForeground(new Color(90, 90, 90));
        panel.add(keyStatusLabel, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel buildActionPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 0));
        panel.setBorder(BorderFactory.createEmptyBorder(4, 0, 6, 0));

        scanButton.addActionListener(event -> startScan());
        scanButton.setToolTipText("Анализ кода и ресурсов всех модов по указанному пути");
        sitesButton.setToolTipText("Сверить хеши с Modrinth и CurseForge без анализа кода");
        sitesButton.addActionListener(event -> startOnlineCheck());
        JPanel scanActions = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        scanActions.add(sitesButton);
        scanActions.add(scanButton);
        panel.add(scanActions, BorderLayout.WEST);

        progressBar.setStringPainted(true);
        progressBar.setMinimum(0);
        progressBar.setMaximum(1);
        progressBar.setValue(0);
        progressBar.setString("готов к проверке");
        panel.add(progressBar, BorderLayout.CENTER);

        saveButton.setEnabled(false);
        saveButton.addActionListener(event -> saveReport());
        panel.add(saveButton, BorderLayout.EAST);
        return panel;
    }

    private Component buildResultsPanel() {
        table.setFillsViewportHeight(true);
        table.setRowHeight(22);
        table.setAutoCreateRowSorter(false);
        table.setRowSorter(ModTableModel.createSorter(tableModel));
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getColumnModel().getColumn(0).setPreferredWidth(220);
        table.getColumnModel().getColumn(1).setPreferredWidth(220);
        table.getColumnModel().getColumn(2).setPreferredWidth(60);
        table.getColumnModel().getColumn(3).setPreferredWidth(150);
        table.getColumnModel().getColumn(4).setPreferredWidth(150);
        table.getSelectionModel().addListSelectionListener(event -> {
            if (!event.getValueIsAdjusting()) {
                showDetails();
            }
        });

        JScrollPane tableScroll = new JScrollPane(table);
        JPanel tablePanel = new JPanel(new BorderLayout());
        tablePanel.add(tableScroll, BorderLayout.CENTER);

        JLabel hint = new JLabel("ПОДОЗРИТЕЛЬНО = проверь сам, это не приговор.");
        hint.setFont(hint.getFont().deriveFont(Font.PLAIN, 11f));
        hint.setForeground(new Color(90, 90, 90));
        hint.setBorder(BorderFactory.createEmptyBorder(3, 2, 3, 2));

        trustButton.setEnabled(false);
        trustButton.setToolTipText("Добавить SHA-1 в "
                + TrustedHashes.defaultFile());
        trustButton.addActionListener(event -> trustSelected());
        untrustButton.setEnabled(false);
        untrustButton.setToolTipText("Убрать SHA-1 из доверенных файлов");
        untrustButton.addActionListener(event -> untrustSelected());

        JPanel trustButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        trustButtons.add(trustButton);
        trustButtons.add(untrustButton);

        fullSelectedButton.setEnabled(false);
        fullSelectedButton.setToolTipText("Статический анализ выбранного файла после сверки с сайтами");
        fullSelectedButton.addActionListener(event -> {
            ModReport report = selectedReport();
            if (report != null && !scanning) {
                beginScan(List.of(report.scan().file()), false, true);
            }
        });
        fullUnconfirmedButton.setEnabled(false);
        fullUnconfirmedButton.setToolTipText("Полная проверка файлов без подтверждения, включая пропущенные онлайн-проверки");
        fullUnconfirmedButton.addActionListener(event -> {
            List<Path> pending = reports.stream().filter(ModReport::needsFullScan)
                    .map(report -> report.scan().file()).toList();
            if (!pending.isEmpty() && !scanning) {
                beginScan(pending, false, true);
            }
        });
        JPanel followupButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        followupButtons.add(fullSelectedButton);
        followupButtons.add(fullUnconfirmedButton);
        JPanel resultActions = new JPanel(new BorderLayout());
        resultActions.add(followupButtons, BorderLayout.WEST);
        resultActions.add(trustButtons, BorderLayout.EAST);
        JPanel tableBottom = new JPanel(new BorderLayout());
        tableBottom.add(hint, BorderLayout.NORTH);
        tableBottom.add(resultActions, BorderLayout.CENTER);
        tablePanel.add(tableBottom, BorderLayout.SOUTH);

        detailsArea.setEditable(false);
        detailsArea.setLineWrap(true);
        detailsArea.setWrapStyleWord(true);
        detailsArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        detailsArea.setRows(12);
        JScrollPane detailsScroll = new JScrollPane(detailsArea);
        detailsScroll.setBorder(BorderFactory.createTitledBorder("Подробности"));

        JSplitPane split = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT, tablePanel, detailsScroll);
        split.setResizeWeight(0.68);
        split.setContinuousLayout(true);
        split.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
        return split;
    }

    private JPanel buildFooterPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 0));
        panel.setBorder(BorderFactory.createEmptyBorder(4, 8, 8, 8));
        totalsLabel.setFont(totalsLabel.getFont().deriveFont(Font.BOLD));
        panel.add(totalsLabel, BorderLayout.NORTH);
        statusLabel.setForeground(new Color(90, 90, 90));
        panel.add(statusLabel, BorderLayout.SOUTH);
        return panel;
    }

    private void loadDefaultPath() {
        Path mods = defaultMinecraftModsPath();
        if (mods != null) {
            pathField.setText(mods.toString());
        }
    }

    private static Path defaultMinecraftModsPath() {
        String appData = System.getenv("APPDATA");
        Path path;
        if (appData != null && !appData.isBlank()) {
            path = Path.of(appData, ".minecraft", "mods");
        } else {
            path = Path.of(System.getProperty("user.home", "."), ".minecraft", "mods");
        }
        return Files.isDirectory(path) ? path : null;
    }

    private void loadSavedKey() {
        String saved = CurseForgeKeyStore.loadDefault();
        if (saved != null) {
            keyField.setText(saved);
            rememberKeyCheck.setSelected(true);
            keyStatusLabel.setText("ключ загружен из сохранённого файла");
            return;
        }

        String legacy = OnlineChecker.readDefaultKey();
        if (legacy != null) {
            keyField.setText(legacy);
            keyStatusLabel.setText("ключ загружен старым способом");
        } else {
            keyStatusLabel.setText("ключ не задан - CurseForge пропускается");
        }
    }

    private String currentKey() {
        return new String(keyField.getPassword()).trim();
    }

    private void toggleKeyVisibility() {
        boolean visible = showKeyButton.isSelected();
        keyField.setEchoChar(visible ? (char) 0 : '*');
        showKeyButton.setText(visible ? "Скрыть" : "Показать");
    }

    private void chooseFolder() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Выберите папку с модами");
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        File current = currentDirectory();
        if (current != null) {
            chooser.setCurrentDirectory(current);
        }
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            pathField.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void chooseJar() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Выберите .jar или .jar.sample");
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        chooser.setFileFilter(new FileFilter() {
            @Override
            public boolean accept(File file) {
                return file.isDirectory() || ModFinder.isModFileName(file.getName());
            }

            @Override
            public String getDescription() {
                return "Jar-файлы (*.jar, *.jar.sample)";
            }
        });
        File current = currentDirectory();
        if (current != null) {
            chooser.setCurrentDirectory(current);
        }
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            pathField.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private File currentDirectory() {
        String text = pathField.getText().trim();
        if (text.isEmpty()) {
            return null;
        }
        try {
            Path path = Path.of(text);
            if (Files.isDirectory(path)) {
                return path.toFile();
            }
            if (Files.isRegularFile(path) && path.getParent() != null) {
                return path.getParent().toFile();
            }
        } catch (InvalidPathException ignored) {
            // Просто откроем chooser в папке по умолчанию.
        }
        return null;
    }

    public void startScan() {
        startPathScan(false);
    }

    public void startOnlineCheck() {
        startPathScan(true);
    }

    private void startPathScan(boolean onlineOnly) {
        if (scanning) {
            return;
        }

        String rawPath = pathField.getText().trim();
        if (rawPath.isEmpty()) {
            showError("Укажите путь к папке с модами, .jar или .jar.sample.");
            return;
        }

        Path target;
        try {
            target = Path.of(rawPath).toAbsolutePath().normalize();
        } catch (InvalidPathException e) {
            showError("Некорректный путь.");
            return;
        }

        if (!Files.exists(target)) {
            showError("Путь не существует:\n" + target);
            return;
        }
        if (Files.isRegularFile(target)
                && !ModFinder.isModFileName(target.getFileName().toString())) {
            showError("Выберите .jar или .jar.sample файл.");
            return;
        }

        List<Path> mods;
        try {
            mods = ModFinder.find(target);
        } catch (IOException e) {
            showError("Не удалось прочитать путь: " + e.getMessage());
            return;
        }
        if (mods.isEmpty()) {
            showError("Jar-файлы (.jar, .jar.sample) не найдены.");
            return;
        }

        beginScan(mods, onlineOnly, false);
    }

    private void beginScan(List<Path> mods, boolean onlineOnly, boolean replaceExisting) {
        if (scanning || mods.isEmpty()) return;
        String key = currentKey();
        if (key.isEmpty()) keyStatusLabel.setText("Ключ не задан — CurseForge пропускается");
        if (!key.isEmpty() && rememberKeyCheck.isSelected()) {
            saveKey(key, false);
        }
        if (!replaceExisting) {
            reports.clear();
            tableModel.setReports(List.of());
            detailsArea.setText("");
        }
        scanning = true;
        scanButton.setEnabled(false);
        sitesButton.setEnabled(false);
        pathField.setEnabled(false);
        folderButton.setEnabled(false);
        jarButton.setEnabled(false);
        saveButton.setEnabled(false);
        updateTrustButtons();
        updateTotals();
        statusLabel.setText(onlineOnly ? "Сверяю файлы с сайтами..." : "Полная статическая проверка...");
        progressBar.setMaximum(mods.size());
        progressBar.setValue(0);
        progressBar.setString("мод 0 из " + mods.size());
        new ScanWorker(mods, checkerFactory.apply(key), onlineOnly, replaceExisting).execute();
    }

    private void mergeReport(ModReport report) {
        for (int i = 0; i < reports.size(); i++) {
            if (reports.get(i).scan().file().equals(report.scan().file())) {
                reports.set(i, report);
                return;
            }
        }
        reports.add(report);
    }

    private final class ScanWorker extends SwingWorker<List<ModReport>, ModReport> {
        private final List<Path> mods;
        private final OnlineChecker onlineChecker;
        private final boolean onlineOnly;
        private final boolean replaceExisting;
        private int completed;

        private ScanWorker(List<Path> mods, OnlineChecker onlineChecker,
                           boolean onlineOnly, boolean replaceExisting) {
            this.mods = mods;
            this.onlineChecker = onlineChecker;
            this.onlineOnly = onlineOnly;
            this.replaceExisting = replaceExisting;
        }

        @Override
        protected List<ModReport> doInBackground() {
            if (onlineOnly) {
                return ScanBatch.checkSites(mods, onlineChecker,
                        (done, total, report) -> publish(report),
                        (hashed, total) -> SwingUtilities.invokeLater(() -> {
                            progressBar.setValue(hashed);
                            progressBar.setString(hashed < total
                                    ? "Хеши: " + hashed + " из " + total
                                    : "Сверяю хеши с Modrinth и CurseForge...");
                        }));
            }
            return ScanBatch.scan(mods, onlineChecker,
                    (done, total, report) -> publish(report));
        }

        @Override
        protected void process(List<ModReport> chunks) {
            for (ModReport report : chunks) {
                if (replaceExisting) {
                    mergeReport(report);
                } else {
                    reports.add(report);
                }
                completed++;
            }
            tableModel.setReports(reports);
            progressBar.setMaximum(mods.size());
            progressBar.setValue(completed);
            progressBar.setString("мод " + completed + " из " + mods.size());
            updateTotals();
        }

        @Override
        protected void done() {
            try {
                List<ModReport> all = get();
                if (!replaceExisting) reports.clear();
                for (ModReport report : all) mergeReport(report);
                tableModel.setReports(reports);
                progressBar.setMaximum(Math.max(1, all.size()));
                progressBar.setValue(all.size());
                progressBar.setString("готово: " + all.size() + " мод(ов)");
                if (onlineChecker.hadNetworkError()) {
                    statusLabel.setText("Онлайн-проверка частично недоступна; подробности в таблице");
                } else if (onlineOnly) {
                    long pending = reports.stream().filter(ModReport::needsFullScan).count();
                    statusLabel.setText(pending > 0
                            ? "Без подтверждения: " + pending + ". Доступна полная проверка"
                            : "Сверка завершена. Анализ кода не выполнялся");
                } else {
                    statusLabel.setText("Полная проверка завершена");
                }
                if (replaceExisting && !all.isEmpty()) {
                    refreshSelection(all.get(0).scan().file());
                } else if (table.getRowCount() > 0) {
                    table.setRowSelectionInterval(0, 0);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                statusLabel.setText("проверка прервана");
            } catch (ExecutionException e) {
                statusLabel.setText("ошибка");
                progressBar.setString("ошибка");
                showError("Ошибка проверки: " + message(e.getCause()));
            } finally {
                scanning = false;
                scanButton.setEnabled(true);
                sitesButton.setEnabled(true);
                pathField.setEnabled(true);
                folderButton.setEnabled(true);
                jarButton.setEnabled(true);
                saveButton.setEnabled(!reports.isEmpty());
                updateTotals();
                updateTrustButtons();
            }
        }
    }

    private void updateFullButtons() {
        ModReport selected = selectedReport();
        fullSelectedButton.setEnabled(!scanning && selected != null && !selected.fullScan());
        fullUnconfirmedButton.setEnabled(!scanning
                && reports.stream().anyMatch(ModReport::needsFullScan));
    }
    private void showDetails() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            detailsArea.setText("");
            updateTrustButtons();
            return;
        }

        int modelRow = table.convertRowIndexToModel(viewRow);
        ModReport report = tableModel.reportAt(modelRow);
        detailsArea.setText(ReportPrinter.formatMod(report).stripLeading());
        detailsArea.setCaretPosition(0);
        updateTrustButtons();
    }

    private void trustSelected() {
        ModReport report = selectedReport();
        if (report == null) {
            showError("Сначала выберите строку с модом.");
            return;
        }

        String sha1 = report.online().sha1();
        if (sha1 == null || sha1.isBlank()) {
            showError("Не удалось вычислить SHA-1 этого файла.");
            return;
        }

        int answer = JOptionPane.showConfirmDialog(
                this,
                "Доверять файлу " + report.scan().name() + "?\n\n"
                        + "SHA-1: " + sha1 + "\n\n"
                        + "Все находки останутся в отчёте, очки не изменятся.",
                "Подтверждение доверия",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE
        );
        if (answer != JOptionPane.YES_OPTION) {
            return;
        }

        try {
            Path file = TrustedHashes.defaultFile();
            boolean added = TrustedHashes.add(
                    file, sha1, report.scan().name());
            report.scan().markManuallyTrusted(
                    file.toAbsolutePath().normalize().toString(),
                    report.scan().name());
            refreshSelection(report.scan().file());
            statusLabel.setText(added
                    ? "файл добавлен в доверенные"
                    : "файл уже был в доверенных");
        } catch (IOException e) {
            showError("Не удалось сохранить trusted_hashes.txt: " + e.getMessage());
        }
    }

    private void untrustSelected() {
        ModReport report = selectedReport();
        if (report == null) {
            showError("Сначала выберите строку с модом.");
            return;
        }

        String sha1 = report.online().sha1();
        if (sha1 == null || sha1.isBlank()) {
            showError("Не удалось вычислить SHA-1 этого файла.");
            return;
        }

        try {
            int removed = TrustedHashes.removeEverywhere(
                    report.scan().file(), sha1);
            report.scan().clearManualTrust();
            refreshSelection(report.scan().file());
            statusLabel.setText(removed > 0
                    ? "файл убран из доверенных"
                    : "хеш не найден в trusted_hashes.txt");
        } catch (IOException e) {
            showError("Не удалось изменить trusted_hashes.txt: " + e.getMessage());
        }
    }

    private void refreshSelection(Path selectedFile) {
        tableModel.setReports(reports);
        for (int viewRow = 0; viewRow < table.getRowCount(); viewRow++) {
            int modelRow = table.convertRowIndexToModel(viewRow);
            if (tableModel.reportAt(modelRow).scan().file().equals(selectedFile)) {
                table.setRowSelectionInterval(viewRow, viewRow);
                break;
            }
        }
        updateTotals();
        updateTrustButtons();
        showDetails();
    }

    private ModReport selectedReport() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            return null;
        }
        int modelRow = table.convertRowIndexToModel(viewRow);
        return tableModel.reportAt(modelRow);
    }

    private void updateTrustButtons() {
        updateFullButtons();
        ModReport report = selectedReport();
        if (scanning || report == null || !report.fullScan()) {
            trustButton.setEnabled(false);
            untrustButton.setEnabled(false);
            return;
        }

        String sha1 = report.online().sha1();
        boolean hasSha1 = sha1 != null && !sha1.isBlank();
        boolean trusted = report.scan().isManuallyTrusted();
        trustButton.setEnabled(hasSha1 && !trusted && !report.scan().hasError());
        untrustButton.setEnabled(hasSha1 && trusted);
    }

    private void updateTotals() {
        int dangerous = 0;
        int suspicious = 0;
        int unknown = 0;
        int trusted = 0;
        int ok = 0;
        int errors = 0;
        int siteOnly = 0;
        int confirmed = 0;
        int siteErrors = 0;

        for (ModReport report : reports) {
            if (!report.fullScan()) {
                siteOnly++;
                if (report.online().confirmed()) confirmed++;
                if (report.scan().hasError()) siteErrors++;
                continue;
            }
            Verdict verdict = report.scan().verdict();
            if (verdict == Verdict.DANGEROUS) {
                dangerous++;
            } else if (verdict == Verdict.SUSPICIOUS) {
                suspicious++;
            } else if (verdict == Verdict.UNKNOWN) {
                unknown++;
            } else if (verdict == Verdict.TRUSTED) {
                trusted++;
            } else if (verdict == Verdict.OK) {
                ok++;
            } else {
                errors++;
            }
        }

        String fullTotals = "ОК: " + ok
                + "   ДОВЕРЕН: " + trusted
                + "   НЕИЗВЕСТНО: " + unknown
                + "   ПОДОЗРИТЕЛЬНО: " + suspicious
                + "   ОПАСНО: " + dangerous
                + "   ОШИБКА: " + errors;
        totalsLabel.setText(siteOnly > 0
                ? "<html>На сайтах: " + confirmed + " подтверждено / "
                    + (siteOnly - confirmed - siteErrors) + " без подтверждения / "
                    + siteErrors + " ошибок"
                    + (siteOnly < reports.size() ? "<br>Полная: " + fullTotals : "") + "</html>"
                : fullTotals);
    }

    private void saveReport() {
        if (reports.isEmpty()) {
            showError("Сначала выполните проверку.");
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Сохранить отчёт");
        chooser.setSelectedFile(new File("modchecker-report.txt"));
        chooser.setFileFilter(new FileNameExtensionFilter("Текстовые файлы (*.txt)", "txt"));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }

        Path file = chooser.getSelectedFile().toPath();
        if (!file.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".txt")) {
            file = file.resolveSibling(file.getFileName() + ".txt");
        }

        try {
            Files.writeString(file, ReportPrinter.format(reports), StandardCharsets.UTF_8);
            statusLabel.setText("отчёт сохранён: " + file.getFileName());
            JOptionPane.showMessageDialog(this,
                    "Отчёт сохранён:\n" + file,
                    "Готово", JOptionPane.INFORMATION_MESSAGE);
        } catch (IOException e) {
            showError("Не удалось сохранить отчёт: " + e.getMessage());
        }
    }

    private void checkKey() {
        String key = currentKey();
        if (key.isEmpty()) {
            keyStatusLabel.setText(KeyCheckStatus.EMPTY.label());
            return;
        }

        checkKeyButton.setEnabled(false);
        keyStatusLabel.setText("проверяю ключ...");

        new SwingWorker<KeyCheckStatus, Void>() {
            @Override
            protected KeyCheckStatus doInBackground() {
                return checkerFactory.apply(key).checkKey();
            }

            @Override
            protected void done() {
                checkKeyButton.setEnabled(true);
                try {
                    KeyCheckStatus status = get();
                    keyStatusLabel.setText(status.label());
                    if (status == KeyCheckStatus.WORKING
                            && rememberKeyCheck.isSelected()) {
                        saveKey(key, false);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    keyStatusLabel.setText(KeyCheckStatus.NO_NETWORK.label());
                } catch (ExecutionException e) {
                    keyStatusLabel.setText(KeyCheckStatus.ERROR.label());
                }
            }
        }.execute();
    }

    private boolean saveKey(String key, boolean updateStatus) {
        try {
            CurseForgeKeyStore.saveDefault(key);
            if (updateStatus) {
                keyStatusLabel.setText("ключ сохранён");
            }
            return true;
        } catch (IOException e) {
            showError("Не удалось сохранить ключ.");
            return false;
        }
    }

    private void deleteSavedKey() {
        try {
            boolean deleted = CurseForgeKeyStore.deleteDefault();
            keyField.setText("");
            rememberKeyCheck.setSelected(false);
            keyStatusLabel.setText(deleted
                    ? "сохранённый ключ удалён"
                    : "сохранённого ключа нет");
        } catch (IOException e) {
            showError("Не удалось удалить сохранённый ключ.");
        }
    }

    private void installDropTargets(Component component) {
        DropTargetAdapter adapter = new DropTargetAdapter() {
            @Override
            public void drop(DropTargetDropEvent event) {
                handleDrop(event);
            }
        };

        try {
            new DropTarget(component, DnDConstants.ACTION_COPY, adapter, true);
        } catch (RuntimeException ignored) {
            // DnD может быть недоступен в среде без графической поддержки.
        }

        if (component instanceof Container container) {
            for (Component child : container.getComponents()) {
                installDropTargets(child);
            }
        }
    }

    private void handleDrop(DropTargetDropEvent event) {
        try {
            if (!event.getTransferable().isDataFlavorSupported(DataFlavor.javaFileListFlavor)) {
                event.rejectDrop();
                return;
            }

            event.acceptDrop(DnDConstants.ACTION_COPY);
            @SuppressWarnings("unchecked")
            List<File> files = (List<File>) event.getTransferable()
                    .getTransferData(DataFlavor.javaFileListFlavor);

            if (files.size() != 1) {
                event.dropComplete(false);
                showError("Перетащите одну папку, .jar или .jar.sample.");
                return;
            }

            File file = files.get(0);
            if (!file.isDirectory() && !ModFinder.isModFileName(file.getName())) {
                event.dropComplete(false);
                showError("Нужна папка с модами, .jar или .jar.sample.");
                return;
            }

            pathField.setText(file.getAbsolutePath());
            event.dropComplete(true);
        } catch (Exception e) {
            event.dropComplete(false);
            showError("Не удалось прочитать перетащенный путь.");
        }
    }

    private void showError(String message) {
        JOptionPane.showMessageDialog(this, message, "Ошибка",
                JOptionPane.ERROR_MESSAGE);
    }

    private static String message(Throwable throwable) {
        if (throwable == null) {
            return "неизвестная ошибка";
        }
        String message = throwable.getMessage();
        return message == null || message.isBlank()
                ? throwable.getClass().getSimpleName()
                : message;
    }

    private static Color backgroundFor(Verdict verdict) {
        return switch (verdict) {
            case DANGEROUS -> DANGEROUS_BACKGROUND;
            case SUSPICIOUS -> SUSPICIOUS_BACKGROUND;
            case UNKNOWN -> UNKNOWN_BACKGROUND;
            case TRUSTED -> TRUSTED_BACKGROUND;
            case OK -> OK_BACKGROUND;
            case ERROR -> ERROR_BACKGROUND;
        };
    }
}
