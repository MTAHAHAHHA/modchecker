package modchecker.report;

import modchecker.scan.NativeFileInfo;
import modchecker.online.VtResult;

public record NativeFileReport(NativeFileInfo file, VtResult result) { }