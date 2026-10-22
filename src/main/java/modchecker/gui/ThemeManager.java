package modchecker.gui;

import com.formdev.flatlaf.*;
import modchecker.online.LocalFiles;
import javax.swing.*;
import java.awt.Color;
import java.io.IOException;
import java.nio.file.*;

public final class ThemeManager {
    private ThemeManager() { }
    public static boolean isDark() { return UIManager.getLookAndFeel() instanceof FlatDarkLaf; }
    public static void ensureInstalled() {
        if (UIManager.getLookAndFeel() instanceof FlatLaf) return;
        boolean dark = true;
        try { dark = !Files.readString(LocalFiles.directory().resolve("theme.txt")).trim().equals("light"); }
        catch (IOException ignored) { }
        apply(dark, false);
    }
    public static void apply(boolean dark, boolean persist) {
        if (dark) FlatDarkLaf.setup(); else FlatLightLaf.setup();
        UIManager.put("Component.arc", 10);
        UIManager.put("Component.minimumHeight", 34);
        java.awt.Font font = UIManager.getFont("Label.font");
        UIManager.put("defaultFont", new javax.swing.plaf.FontUIResource(font.deriveFont(14f)));
        UIManager.put("Button.arc", 10);
        UIManager.put("TextComponent.arc", 10);
        UIManager.put("ScrollBar.showButtons", false);
        UIManager.put("Table.showVerticalLines", false);
        UIManager.put("Table.showHorizontalLines", false);
        UIManager.put("Table.intercellSpacing", new java.awt.Dimension(0, 0));
        FlatLaf.updateUI();
        if (persist) {
            try {
                Files.createDirectories(LocalFiles.directory());
                Files.writeString(LocalFiles.directory().resolve("theme.txt"), dark ? "dark" : "light");
            } catch (IOException ignored) { /* Выбранная тема работает и без сохранения. */ }
        }
    }
    public static Color muted() {
        Color color = UIManager.getColor("Label.disabledForeground");
        return color != null ? color : (isDark() ? new Color(155,160,175) : new Color(95,100,115));
    }
    public static Color accent() { return new Color(isDark() ? 0x86a9ff : 0x315cd4); }
}
