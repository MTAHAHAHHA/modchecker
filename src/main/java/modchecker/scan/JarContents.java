package modchecker.scan;

import java.util.List;

/**
 * Результат обхода архива: обычные файлы и найденные вложенные jar,
 * которые лежат в подозрительном месте (assets, data, resources или корень).
 */
record JarContents(List<ArchiveFile> files, List<String> suspiciousJars) {
}
