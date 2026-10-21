package modchecker.gui;

import modchecker.report.ModReport;

import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Модель таблицы. Только показывает уже готовые ModReport,
 * ничего не пересчитывает.
 */
public final class ModTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {
            "Мод", "Вердикт", "Очки", "Modrinth", "CurseForge"
    };

    private final List<ModReport> reports = new ArrayList<>();

    public void setReports(List<ModReport> newReports) {
        reports.clear();
        reports.addAll(newReports);
        fireTableDataChanged();
    }

    public void addReport(ModReport report) {
        int row = reports.size();
        reports.add(report);
        fireTableRowsInserted(row, row);
    }

    public ModReport reportAt(int modelRow) {
        return reports.get(modelRow);
    }

    public List<ModReport> reports() {
        return List.copyOf(reports);
    }

    @Override
    public int getRowCount() {
        return reports.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    @Override
    public Class<?> getColumnClass(int column) {
        return column == 2 ? Integer.class : String.class;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        ModReport report = reports.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> report.scan().name();
            case 1 -> report.scan().verdict().label();
            case 2 -> report.scan().points();
            case 3 -> report.online().modrinth().label();
            case 4 -> report.online().curseForge().label();
            default -> "";
        };
    }

    public static TableRowSorter<ModTableModel> createSorter(ModTableModel model) {
        TableRowSorter<ModTableModel> sorter = new TableRowSorter<>(model);
        sorter.setComparator(1, Comparator.comparingInt(ModTableModel::verdictOrder));
        sorter.setSortKeys(List.of(
                new RowSorter.SortKey(1, SortOrder.ASCENDING),
                new RowSorter.SortKey(2, SortOrder.DESCENDING)
        ));
        return sorter;
    }

    public static int verdictOrder(String label) {
        if (label == null) {
            return 99;
        }
        return switch (label) {
            case "ОПАСНО" -> 0;
            case "ПОДОЗРИТЕЛЬНО" -> 1;
            case "НЕИЗВЕСТНО" -> 2;
            case "ДОВЕРЕН (вручную)" -> 3;
            case "ОК" -> 4;
            case "ОШИБКА" -> 5;
            default -> 99;
        };
    }
}
