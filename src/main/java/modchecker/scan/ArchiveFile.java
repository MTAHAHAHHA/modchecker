package modchecker.scan;

/**
 * Один обычный файл из jar. location хранит полный путь, включая вложенные
 * jar, например: inner.jar!/assets/config.json
 */
record ArchiveFile(String entryName, String location, byte[] data) {
}
