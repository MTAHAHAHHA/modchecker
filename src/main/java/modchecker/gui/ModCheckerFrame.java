package modchecker.gui;

import modchecker.app.ScanBatch;
import modchecker.model.Verdict;
import modchecker.online.*;
import modchecker.report.*;
import modchecker.scan.ModFinder;
import modchecker.scan.NativeFileScanner;
import modchecker.trust.TrustedHashes;
import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.dnd.*;
import java.awt.event.ItemEvent;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutionException;
import java.util.function.Function;

/** Представление готовых результатов. Правила и баллы находятся в ScanService. */
public final class ModCheckerFrame extends JFrame {
    private final ModTableModel tableModel = new ModTableModel();
    private final JTextField pathField = new JTextField();
    private final JButton folderButton = new JButton("Папка…");
    private final JButton jarButton = new JButton("JAR…");
    private final JButton scanButton = new JButton("Проверить");
    private final JButton sitesButton = new JButton("Быстрая проверка");
    private final JButton fullSelectedButton = new JButton("Полная проверка выбранного");
    private final JButton fullUnconfirmedButton = new JButton("Полная проверка неподтверждённых");
    private final JButton saveButton = new JButton("Экспорт ▾");
    private final JButton trustButton = new JButton("Доверять этому файлу…");
    private final JButton untrustButton = new JButton("Убрать из доверенных");
    private final JButton nativeButton = new JButton("Нативные файлы → VirusTotal");
    private final JButton settingsButton = new JButton("Настройки");
    private final JButton actionsButton = new JButton("Действия ▾");
    private final JComboBox<String> modeCombo = new JComboBox<>(new String[]{"Быстрая проверка", "Полная проверка"});
    private final JLabel modeHint = new JLabel();
    private final JTextField searchField = new JTextField(16);
    private final JComboBox<String> resultFilter = new JComboBox<>(new String[]{
            "Все результаты", "Требуют внимания", "Только полная проверка", "Только быстрая проверка",
            "Подтверждены на сайтах", "Без подтверждения", "Вердикт: ОПАСНО", "Вердикт: ПОДОЗРИТЕЛЬНО",
            "Вердикт: НЕИЗВЕСТНО", "Вердикт: ОК", "Вердикт: ДОВЕРЕН (вручную)", "Вердикт: ОШИБКА"});
    private final JComboBox<String> ruleFilter = new JComboBox<>();
    private final JComboBox<String> sourceFilter = new JComboBox<>(new String[]{"Любой источник", "Основной JAR", "Вложенные JAR"});
    private final JLabel visibleLabel = new JLabel();
    private final JProgressBar progressBar = new JProgressBar();
    private final JTable table = new JTable(tableModel);
    private final JTextArea detailsArea = new JTextArea();
    private final JLabel totalsLabel = new JLabel();
    private final JLabel statusLabel = new JLabel("Готов к проверке");
    private final JPasswordField keyField = new JPasswordField(24);
    private final JToggleButton showKeyButton = new JToggleButton("Показать");
    private final JButton checkKeyButton = new JButton("Проверить ключ");
    private final JCheckBox rememberKeyCheck = new JCheckBox("Сохранять ключ на этом компьютере");
    private final JButton deleteKeyButton = new JButton("Удалить");
    private final JLabel keyStatusLabel = new JLabel("Ключ не задан — CurseForge пропускается");
    private final JPasswordField vtKeyField = new JPasswordField(24);
    private final JLabel vtStatusLabel = new JLabel("Проверка доступна в меню «Действия» выбранного мода");
    private final JToggleButton detailsToggle = new JToggleButton("Подробности  ▾", true);
    private final CardLayout resultCards = new CardLayout();
    private final JPanel resultContent = new JPanel(resultCards);
    private final JLabel emptyTitle = new JLabel("Результатов пока нет", SwingConstants.CENTER);
    private final JLabel emptyHint = new JLabel("Выберите папку или JAR-файл и нажмите «Проверить»", SwingConstants.CENTER);
    private JSplitPane resultsSplit;
    private JScrollPane detailsScroll;
    private int detailsHeight = 160;
    private final List<ModReport> reports = new ArrayList<>();
    private volatile boolean scanning;
    private final Function<String, OnlineChecker> checkerFactory;

    public ModCheckerFrame() { this(OnlineChecker::new); }
    public ModCheckerFrame(Function<String, OnlineChecker> checkerFactory) {
        super("ModChecker 1.2");
        this.checkerFactory = checkerFactory;
        ThemeManager.ensureInstalled();
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        Rectangle screen = GraphicsEnvironment.getLocalGraphicsEnvironment().getMaximumWindowBounds();
        setMinimumSize(new Dimension(Math.min(920, screen.width), Math.min(720, screen.height)));
        setSize(Math.min(1220, screen.width), Math.min(860, screen.height));
        setLocationRelativeTo(null);
        buildUi();
        SwingUtilities.updateComponentTreeUI(this);
        installDropTargets(getContentPane());
        loadDefaultPath();
        loadSavedKey();
        String vtKey = VirusTotalKeyStore.loadDefault();
        if (vtKey != null) vtKeyField.setText(vtKey);
        rememberKeyCheck.addItemListener(event -> {
            if (event.getStateChange() == ItemEvent.SELECTED && !currentKey().isEmpty()) saveKey(currentKey(), false);
        });
    }
    public void setPath(String path) { pathField.setText(path); }
    public JTable getResultTable() { return table; }
    public boolean isScanning() { return scanning; }
    public List<ModReport> getReports() { return List.copyOf(reports); }

    private void buildUi() {
        JPanel root = new JPanel(new BorderLayout(0, 16));
        root.setBorder(BorderFactory.createEmptyBorder(20, 24, 16, 24));
        setContentPane(root);
        JPanel top = new JPanel(new BorderLayout(0, 18));
        JPanel heading = new JPanel(new BorderLayout(16, 0));
        JPanel brand = verticalPanel();
        JLabel title = new JLabel("ModChecker");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 25f));
        brand.add(title);
        brand.add(Box.createVerticalStrut(4));
        brand.add(new JLabel("Статический анализ Minecraft-модов · без запуска кода"));
        heading.add(brand);
        JPanel utilities = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        saveButton.setEnabled(false);
        saveButton.addActionListener(event -> {
            JPopupMenu menu = new JPopupMenu();
            JMenuItem txt = new JMenuItem("Текстовый отчёт (.txt)…");
            txt.addActionListener(e -> saveReport());
            JMenuItem json = new JMenuItem("Структурированный отчёт (.json)…");
            json.addActionListener(e -> saveJsonReport());
            menu.add(txt); menu.add(json);
            menu.show(saveButton, 0, saveButton.getHeight());
        });
        settingsButton.addActionListener(event -> showSettings());
        utilities.add(saveButton); utilities.add(settingsButton);
        heading.add(utilities, BorderLayout.EAST);
        top.add(heading, BorderLayout.NORTH);
        top.add(buildPathPanel());
        root.add(top, BorderLayout.NORTH);
        root.add(buildResultsPanel());
        root.add(buildFooterPanel(), BorderLayout.SOUTH);
        updateTotals();
    }

    private JPanel buildPathPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 8));
        panel.add(new JLabel("Папка с модами или JAR-файл"), BorderLayout.NORTH);
        JPanel row = new JPanel(new BorderLayout(8, 0));
        pathField.putClientProperty("JTextField.placeholderText", "Укажите путь или перетащите файл / папку сюда");
        pathField.setToolTipText("Поддерживаются .jar и .jar.sample. Код файлов никогда не запускается.");
        pathField.addActionListener(e -> scanButton.doClick());
        row.add(pathField);
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        folderButton.addActionListener(e -> chooseFolder());
        jarButton.addActionListener(e -> chooseJar());
        scanButton.putClientProperty("JButton.buttonType", "roundRect");
        scanButton.setFont(scanButton.getFont().deriveFont(Font.BOLD));
        scanButton.setBackground(new Color(0x3765ca));
        scanButton.setForeground(Color.WHITE);
        scanButton.addActionListener(e -> { if (modeCombo.getSelectedIndex() == 0) startOnlineCheck(); else startScan(); });
        sitesButton.addActionListener(e -> startOnlineCheck());
        buttons.add(folderButton); buttons.add(jarButton); buttons.add(modeCombo); buttons.add(scanButton);
        row.add(buttons, BorderLayout.EAST);
        panel.add(row);
        modeCombo.addActionListener(e -> updateModeHint());
        updateModeHint();
        panel.add(modeHint, BorderLayout.SOUTH);
        return panel;
    }

    private void updateModeHint() {
        modeHint.setText(modeCombo.getSelectedIndex() == 0
                ? "Сверка хешей с Modrinth и CurseForge. Для неподтверждённых файлов доступна полная проверка."
                : "Анализ байткода и ресурсов по 29 правилам, затем сверка хешей с сайтами.");
    }

    private Component buildResultsPanel() {
        JPanel tablePanel = new JPanel(new BorderLayout(0, 10));
        JPanel filters = new JPanel(new BorderLayout(8, 8));
        searchField.putClientProperty("JTextField.placeholderText", "Поиск по имени, находке или пути…");
        searchField.setToolTipText("Поиск по имени файла, названию правила, месту и тексту находок");
        filters.add(searchField);
        JPanel choices = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        choices.add(resultFilter);
        actionsButton.addActionListener(e -> actionMenu().show(actionsButton, 0, actionsButton.getHeight()));
        choices.add(actionsButton);
        filters.add(choices, BorderLayout.EAST);
        JPanel second = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        ruleFilter.addItem("Все правила");
        for (int i = 1; i <= 29; i++) ruleFilter.addItem("Правило " + i);
        second.add(ruleFilter); second.add(sourceFilter);
        JButton reset = new JButton("Сбросить фильтры");
        reset.addActionListener(e -> resetFilters());
        second.add(reset); second.add(visibleLabel);
        filters.add(second, BorderLayout.SOUTH);
        tablePanel.add(filters, BorderLayout.NORTH);
        table.setFillsViewportHeight(true);
        table.setRowHeight(38);
        table.setShowGrid(false);
        table.setIntercellSpacing(new Dimension(0, 0));
        DefaultTableCellRenderer plainText = new DefaultTableCellRenderer();
        plainText.putClientProperty("html.disable", true);
        table.setDefaultRenderer(String.class, plainText);
        table.setAutoCreateRowSorter(false);
        table.setRowSorter(ModTableModel.createSorter(tableModel));
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getTableHeader().setReorderingAllowed(false);
        int[] widths = {330, 260, 65, 170, 170};
        for (int i = 0; i < widths.length; i++) table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        table.getColumnModel().getColumn(2).setMaxWidth(90);
        table.getColumnModel().getColumn(1).setCellRenderer(new VerdictRenderer());
        table.getSelectionModel().addListSelectionListener(e -> { if (!e.getValueIsAdjusting()) showDetails(); });
        table.addMouseListener(new java.awt.event.MouseAdapter() {
            private void popup(java.awt.event.MouseEvent e) {
                if (!e.isPopupTrigger()) return;
                int row = table.rowAtPoint(e.getPoint());
                if (row >= 0) table.setRowSelectionInterval(row, row);
                actionMenu().show(table, e.getX(), e.getY());
            }
            @Override public void mousePressed(java.awt.event.MouseEvent e) { popup(e); }
            @Override public void mouseReleased(java.awt.event.MouseEvent e) { popup(e); }
        });
        resultContent.add(new JScrollPane(table), "table");
        JPanel empty = new JPanel(new GridBagLayout());
        JPanel words = new JPanel(new GridLayout(2, 1, 0, 12));
        emptyTitle.setFont(emptyTitle.getFont().deriveFont(Font.BOLD, 19f));
        words.add(emptyTitle); words.add(emptyHint); empty.add(words);
        resultContent.add(empty, "empty");
        tablePanel.add(resultContent);
        detailsToggle.setHorizontalAlignment(SwingConstants.LEFT);
        detailsToggle.addActionListener(e -> toggleDetails());
        tablePanel.add(detailsToggle, BorderLayout.SOUTH);
        detailsArea.setEditable(false);
        detailsArea.setLineWrap(true);
        detailsArea.setWrapStyleWord(true);
        detailsArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        detailsArea.setMargin(new Insets(12, 14, 12, 14));
        detailsScroll = new JScrollPane(detailsArea);
        detailsScroll.setMinimumSize(new Dimension(0, 80));
        tablePanel.setMinimumSize(new Dimension(0, 230));
        resultsSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tablePanel, detailsScroll) {
            private boolean initialized;
            private int lastHeight;
            @Override public void doLayout() {
                if (getHeight() > 0 && detailsScroll.isVisible()) {
                    int maximum = Math.max(230, getHeight() - 64 - getDividerSize());
                    int requested = initialized ? getDividerLocation() + getHeight() - lastHeight
                            : getHeight() - detailsHeight - getDividerSize();
                    int location = Math.max(230, Math.min(maximum, requested));
                    if (location != getDividerLocation()) setDividerLocation(location);
                    initialized = true;
                }
                super.doLayout();
                lastHeight = getHeight();
            }
        };
        resultsSplit.setResizeWeight(1.0);
        resultsSplit.setContinuousLayout(true);
        resultsSplit.setBorder(BorderFactory.createEmptyBorder());
        resultsSplit.setDividerLocation(300);
        trustButton.addActionListener(e -> trustSelected());
        untrustButton.addActionListener(e -> untrustSelected());
        fullSelectedButton.addActionListener(e -> {
            ModReport report = selectedReport();
            if (report != null && !scanning) beginScan(List.of(report.scan().file()), false, true);
        });
        fullUnconfirmedButton.addActionListener(e -> {
            List<Path> pending = reports.stream().filter(ModReport::needsFullScan).map(r -> r.scan().file()).toList();
            if (!pending.isEmpty() && !scanning) beginScan(pending, false, true);
        });
        nativeButton.addActionListener(e -> checkNativeFiles());
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { applyFilters(); }
            public void removeUpdate(DocumentEvent e) { applyFilters(); }
            public void changedUpdate(DocumentEvent e) { applyFilters(); }
        });
        resultFilter.addActionListener(e -> applyFilters());
        ruleFilter.addActionListener(e -> applyFilters());
        sourceFilter.addActionListener(e -> applyFilters());
        tableModel.addTableModelListener(e -> updateEmptyState());
        table.getRowSorter().addRowSorterListener(e -> updateEmptyState());
        updateTrustButtons();
        return resultsSplit;
    }

    private void resetFilters() {
        searchField.setText(""); resultFilter.setSelectedIndex(0); ruleFilter.setSelectedIndex(0); sourceFilter.setSelectedIndex(0);
    }
    @SuppressWarnings("unchecked")
    private void applyFilters() {
        var sorter = (TableRowSorter<ModTableModel>) table.getRowSorter();
        sorter.setRowFilter(new RowFilter<>() {
            @Override public boolean include(Entry<? extends ModTableModel, ? extends Integer> entry) {
                return ResultFilters.matches(tableModel.reportAt(entry.getIdentifier()), searchField.getText(),
                        (String) resultFilter.getSelectedItem(), ruleFilter.getSelectedIndex(), (String) sourceFilter.getSelectedItem());
            }
        });
        updateEmptyState();
        showDetails();
    }
    private void updateEmptyState() {
        int visible = table.getRowCount();
        visibleLabel.setText("Показано " + visible + " из " + tableModel.getRowCount());
        boolean noData = tableModel.getRowCount() == 0;
        emptyTitle.setText(noData ? (scanning ? "Проверка выполняется…" : "Результатов пока нет") : "Ничего не найдено");
        emptyHint.setText(noData ? "Выберите папку или JAR-файл и нажмите «Проверить»" : "Измените запрос или сбросьте фильтры");
        resultCards.show(resultContent, visible == 0 ? "empty" : "table");
    }
    private void toggleDetails() {
        boolean expanded = detailsToggle.isSelected();
        if (!expanded) detailsHeight = Math.max(100, detailsScroll.getHeight());
        detailsScroll.setVisible(expanded);
        resultsSplit.setDividerSize(expanded ? 8 : 0);
        resultsSplit.setDividerLocation(expanded ? Math.max(200, resultsSplit.getHeight() - detailsHeight - 8) : resultsSplit.getHeight());
        detailsToggle.setText(expanded ? "Подробности  ▾" : "Подробности  ▸");
        resultsSplit.revalidate();
    }
    private JPopupMenu actionMenu() {
        updateTrustButtons();
        JPopupMenu menu = new JPopupMenu();
        for (JButton action : List.of(fullSelectedButton, fullUnconfirmedButton, nativeButton)) addAction(menu, action);
        menu.addSeparator();
        addAction(menu, trustButton); addAction(menu, untrustButton);
        JMenuItem copy = new JMenuItem("Копировать подробности");
        copy.setEnabled(selectedReport() != null);
        copy.addActionListener(e -> Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                new StringSelection(ReportPrinter.formatMod(selectedReport())), null));
        menu.addSeparator(); menu.add(copy);
        return menu;
    }
    private static void addAction(JPopupMenu menu, JButton action) {
        JMenuItem item = new JMenuItem(action.getText());
        item.setEnabled(action.isEnabled()); item.addActionListener(e -> action.doClick()); menu.add(item);
    }
    private JPanel buildFooterPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 10));
        panel.add(totalsLabel, BorderLayout.NORTH);
        progressBar.setStringPainted(true); progressBar.setMaximum(1); progressBar.setString("Готов к проверке");
        panel.add(progressBar);
        panel.add(statusLabel, BorderLayout.SOUTH);
        return panel;
    }
    private static JPanel verticalPanel() {
        JPanel panel = new JPanel(); panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS)); return panel;
    }
    private JPanel buildKeyPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 10));
        panel.setBorder(BorderFactory.createTitledBorder("CurseForge"));
        JPanel input = new JPanel(new BorderLayout(8, 0));
        input.add(keyField); input.add(showKeyButton, BorderLayout.EAST);
        showKeyButton.addActionListener(e -> toggleKeyVisibility());
        panel.add(input, BorderLayout.NORTH);
        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        controls.add(checkKeyButton); controls.add(rememberKeyCheck); controls.add(deleteKeyButton);
        checkKeyButton.addActionListener(e -> checkKey());
        deleteKeyButton.addActionListener(e -> deleteSavedKey());
        panel.add(controls);
        panel.add(keyStatusLabel, BorderLayout.SOUTH);
        return panel;
    }
    private JDialog settingsDialog;
    private void showSettings() {
        ensureSettingsDialog();
        settingsDialog.setLocationRelativeTo(this); settingsDialog.setVisible(true);
    }
    private void ensureSettingsDialog() {
        if (settingsDialog == null) {
            settingsDialog = new JDialog(this, "Настройки ModChecker", false);
            settingsDialog.setDefaultCloseOperation(JDialog.HIDE_ON_CLOSE);
            JPanel content = verticalPanel();
            content.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));
            JPanel theme = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
            theme.add(new JLabel("Оформление:"));
            JComboBox<String> themes = new JComboBox<>(new String[]{"Тёмная тема", "Светлая тема"});
            themes.setSelectedIndex(ThemeManager.isDark() ? 0 : 1);
            themes.addActionListener(e -> ThemeManager.apply(themes.getSelectedIndex() == 0, true));
            theme.add(themes); content.add(theme); content.add(Box.createVerticalStrut(12));
            content.add(buildKeyPanel()); content.add(Box.createVerticalStrut(16));
            JPanel vt = new JPanel(new BorderLayout(8, 10));
            vt.setBorder(BorderFactory.createTitledBorder("VirusTotal · нативные файлы"));
            JPanel input = new JPanel(new BorderLayout(8, 0));
            input.add(vtKeyField);
            JToggleButton show = new JToggleButton("Показать");
            show.addActionListener(e -> { vtKeyField.setEchoChar(show.isSelected() ? (char) 0 : '*'); show.setText(show.isSelected() ? "Скрыть" : "Показать"); });
            input.add(show, BorderLayout.EAST); vt.add(input, BorderLayout.NORTH);
            JButton save = new JButton("Сохранить ключ");
            save.addActionListener(e -> {
                try { VirusTotalKeyStore.saveDefault(new String(vtKeyField.getPassword()).trim()); vtStatusLabel.setText("Ключ сохранён локально"); }
                catch (IOException ex) { showError("Не удалось сохранить ключ VirusTotal"); }
            });
            JButton delete = new JButton("Удалить");
            delete.addActionListener(e -> {
                try { VirusTotalKeyStore.deleteDefault(); vtKeyField.setText(""); vtStatusLabel.setText("Ключ удалён"); }
                catch (IOException ex) { showError("Не удалось удалить ключ VirusTotal"); }
            });
            JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
            controls.add(save); controls.add(delete); vt.add(controls); vt.add(vtStatusLabel, BorderLayout.SOUTH);
            content.add(vt); content.add(Box.createVerticalStrut(12));
            content.add(new JLabel("<html>VirusTotal получает только SHA-256. Файлы не отправляются.<br>До 4 запросов в минуту и 500 за 24 часа. Повторные результаты берутся из кэша.<br><br>Ключи хранятся в папке пользователя modchecker, в обычных текстовых файлах.<br>Modrinth работает без ключа.</html>"));
            JPanel bottom = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            JButton close = new JButton("Готово"); close.addActionListener(e -> settingsDialog.setVisible(false)); bottom.add(close);
            settingsDialog.add(new JScrollPane(content)); settingsDialog.add(bottom, BorderLayout.SOUTH);
            settingsDialog.setMinimumSize(new Dimension(680, 520)); settingsDialog.setSize(740, 570);
        }
    }

    private void saveJsonReport() { saveReportAs(true); }
    private void saveReportAs(boolean json) {
        if (reports.isEmpty()) return;
        String extension = json ? "json" : "txt";
        JFileChooser chooser = new JFileChooser(); chooser.setDialogTitle("Сохранить все результаты");
        chooser.setSelectedFile(new File("modchecker-report." + extension));
        chooser.setFileFilter(new FileNameExtensionFilter("Отчёт (*." + extension + ")", extension));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        Path file = chooser.getSelectedFile().toPath();
        if (!file.getFileName().toString().toLowerCase(Locale.ROOT).endsWith("." + extension)) file = file.resolveSibling(file.getFileName() + "." + extension);
        if (Files.exists(file) && JOptionPane.showConfirmDialog(this, "Заменить существующий файл?\n" + file,
                "Экспорт отчёта", JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION) return;
        try { Files.writeString(file, json ? ReportJson.format(reports) : ReportPrinter.format(reports), StandardCharsets.UTF_8); statusLabel.setText("Отчёт сохранён: " + file.getFileName()); }
        catch (IOException e) { showError("Не удалось сохранить отчёт: " + e.getMessage()); }
    }
    private void setBusy(boolean busy) {
        scanning = busy;
        for (JComponent control : List.of(scanButton, sitesButton, pathField, folderButton, jarButton, modeCombo, settingsButton)) control.setEnabled(!busy);
        saveButton.setEnabled(!busy && !reports.isEmpty());
        if (settingsDialog != null) settingsDialog.setVisible(false);
        updateTrustButtons(); updateEmptyState();
    }
    private void checkNativeFiles() {
        ModReport report = selectedReport();
        if (report == null || scanning) return;
        String key = new String(vtKeyField.getPassword()).trim();
        setBusy(true); progressBar.setIndeterminate(true); statusLabel.setText("Читаю нативные файлы и сверяю SHA-256 с VirusTotal…");
        new SwingWorker<ModReport, Void>() {
            @Override protected ModReport doInBackground() throws Exception {
                String before = Hashes.sha1(report.scan().file());
                if (!before.equals(report.online().sha1())) throw new IOException("Файл изменён после проверки; проверьте его заново");
                var files = NativeFileScanner.collect(report.scan().file());
                var client = new VirusTotalClient(key);
                List<NativeFileReport> results = new ArrayList<>();
                for (var file : files) results.add(new NativeFileReport(file, client.check(file.sha256())));
                if (!before.equals(Hashes.sha1(report.scan().file()))) throw new IOException("Файл изменён во время проверки");
                return report.withNativeReports(results);
            }
            @Override protected void done() {
                try {
                    ModReport updated = get(); mergeReport(updated); refreshSelection(updated.scan().file());
                    statusLabel.setText(updated.nativeReports().isEmpty() ? "Нативных .exe/.dll/.so/.dylib не найдено"
                            : "VirusTotal: результаты в подробностях. Ограниченные запросы можно повторить позже");
                } catch (InterruptedException e) { Thread.currentThread().interrupt(); statusLabel.setText("Проверка прервана"); }
                catch (ExecutionException e) { statusLabel.setText("Ошибка проверки VirusTotal"); showError(message(e.getCause())); }
                finally { progressBar.setIndeterminate(false); setBusy(false); }
            }
        }.execute();
    }
    private static final class VerdictRenderer extends DefaultTableCellRenderer {
        @Override public Component getTableCellRendererComponent(JTable table, Object value, boolean selected, boolean focus, int row, int column) {
            super.getTableCellRendererComponent(table, value, selected, focus, row, column);
            String label = String.valueOf(value);
            setText("●  " + label); setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 6));
            setFont(table.getFont().deriveFont(Font.BOLD));
            int order = ModTableModel.verdictOrder(label);
            int rgb = switch (order) { case 0 -> ThemeManager.isDark() ? 0xff8585 : 0xb42332; case 1 -> ThemeManager.isDark() ? 0xffbd70 : 0x965800;
                case 2 -> ThemeManager.isDark() ? 0xe5ce81 : 0x746000; case 3 -> ThemeManager.isDark() ? 0x9bb8ff : 0x315cd4;
                case 4 -> ThemeManager.isDark() ? 0x83d7af : 0x18794e; default -> ThemeManager.isDark() ? 0xc6a5e8 : 0x73508c; };
            if (!selected) setForeground(new Color(rgb));
            setToolTipText(label.equals("ПОДОЗРИТЕЛЬНО") ? "Есть признаки, требующие проверки. Это не доказательство заражения." : label);
            return this;
        }
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
        setBusy(true);
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
                setBusy(false);
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
        nativeButton.setEnabled(!scanning && report != null && !report.scan().hasError());
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
                + " · Доверен: " + trusted
                + " · Неизвестно: " + unknown
                + " · Подозрительно: " + suspicious
                + " · Опасно: " + dangerous
                + " · Ошибки: " + errors;
        totalsLabel.setText(siteOnly > 0
                ? "<html>На сайтах: " + confirmed + " подтверждено / "
                    + (siteOnly - confirmed - siteErrors) + " без подтверждения / "
                    + siteErrors + " ошибок"
                    + (siteOnly < reports.size() ? "<br>Полная: " + fullTotals : "") + "</html>"
                : "<html>Всего: " + reports.size() + " · " + fullTotals + "</html>");
        updateEmptyState();
    }

    private void saveReport() { saveReportAs(false); }

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
            if (scanning) { event.rejectDrop(); return; }
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

}
