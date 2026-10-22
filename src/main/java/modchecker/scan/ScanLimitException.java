package modchecker.scan;

import java.io.IOException;

public final class ScanLimitException extends IOException {
    public ScanLimitException(String message) { super(message); }
}