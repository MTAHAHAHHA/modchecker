package modchecker.scan;

/** Только метаданные и хеш. Исполняемые данные никуда не извлекаются. */
public record NativeFileInfo(String location, String sha256, long size) { }