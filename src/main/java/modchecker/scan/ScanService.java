package modchecker.scan;

import modchecker.model.Finding;
import modchecker.model.ModScanResult;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;

/**
 * Проверка одного мода: читаем содержимое, ищем строки по правилам 1-8,
 * маскировку и энтропию (9, 18, 19; правило 18 - только в .class),
 * байткод (10-16, 22-23, 27, 29), имена классов (20, 21), RAT-признаки
 * (24-26, 28) и исполняемые файлы (17).
 */
public final class ScanService {

    private static final List<String> TEXT_EXTENSIONS = List.of(
            ".json", ".txt", ".properties", ".cfg"
    );

    private static final List<String> EXECUTABLE_EXTENSIONS = List.of(
            ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".scr"
    );

    public ModScanResult scan(Path modFile) {
        ModScanResult result = new ModScanResult(modFile);

        JarContents contents;
        try {
            contents = JarWalker.read(modFile);
        } catch (IOException e) {
            result.markError("файл битый или не мод");
            return result;
        }
        List<ArchiveFile> files = contents.files();

        reportHiddenJars(contents.suspiciousJars(), result);

        TextRuleScanner textRules = new TextRuleScanner(result);
        RatScanner rat = new RatScanner(result);
        EntityScanner entities = new EntityScanner(result);
        StringObfuscationScanner obfuscation = new StringObfuscationScanner(result);
        ExternalPathScanner externalPaths = new ExternalPathScanner(result);
        LargeFileScanner largeFiles = new LargeFileScanner(result);
        HardwareIdScanner hardwareIds = new HardwareIdScanner(result);
        String executableLocation = null;
        String executableName = null;
        BytecodeScanState bytecodeState = new BytecodeScanState();

        for (ArchiveFile file : files) {
            String lowerName = file.entryName().toLowerCase(Locale.ROOT);

            if (lowerName.endsWith(".class")) {
                scanClass(file, result, textRules, rat, entities, obfuscation,
                        externalPaths, hardwareIds, bytecodeState);
            } else if (isTextFile(lowerName)) {
                String content = new String(file.data(), StandardCharsets.UTF_8);
                String location = "файл " + file.location();
                textRules.inspectText(content, location);
                rat.inspectString(content, location);
                entities.inspect(content, location);
                obfuscation.inspectText(content, location);
                externalPaths.inspect(content, location);
            }

            largeFiles.inspect(file);

            if (isExecutable(lowerName) && executableLocation == null) {
                executableLocation = file.location();
                executableName = file.entryName();
            }
        }

        if (executableLocation != null) {
            result.addFinding(new Finding(
                    17,
                    "Исполняемый файл внутри jar",
                    4,
                    "файл " + executableLocation,
                    "расширение: " + extensionOf(executableName)
            ));
        }

        if (bytecodeState.xorLoopLocation != null && !bytecodeState.dangerousXorFound) {
            result.addFinding(new Finding(
                    11,
                    "XOR-цикл без опасного результата",
                    2,
                    bytecodeState.xorLoopLocation,
                    "XOR-цикл найден, но опасная строка не восстановлена"
            ));
        }

        rat.finish();

        List<String> classNames = ClassNameScanner.simpleNames(files);
        hardwareIds.finish(classNames);
        ClassNameScanner.inspectNames(classNames, result);
        LinkService.apply(result);

        return result;
    }

    private void scanClass(ArchiveFile file, ModScanResult result,
                           TextRuleScanner textRules,
                           RatScanner rat,
                           EntityScanner entities,
                           StringObfuscationScanner obfuscation,
                           ExternalPathScanner externalPaths,
                           HardwareIdScanner hardwareIds,
                           BytecodeScanState bytecodeState) {
        try {
            for (StringConstant constant : ClassStringExtractor.extract(file.data())) {
                String location = "класс " + constant.className()
                        + ", метод " + constant.methodName()
                        + " - " + file.location();
                textRules.inspectClassConstant(constant.value(), location);
                rat.inspectString(constant.value(), location);
                entities.inspect(constant.value(), location);
                obfuscation.inspectClassConstant(constant.value(), location);
                externalPaths.inspect(constant.value(), location);
                hardwareIds.inspectClassConstant(
                        constant.value(), constant.className(), location);
            }
        } catch (RuntimeException ignored) {
            // Повреждённый .class пропускаем, но остальные файлы мода проверяем.
        }

        BytecodeAnalysis analysis;
        try {
            analysis = BytecodeAnalyzer.analyze(file.data());
        } catch (RuntimeException ignored) {
            return;
        }

        if (analysis.xorLoop() != null && bytecodeState.xorLoopLocation == null) {
            bytecodeState.xorLoopLocation = "класс " + analysis.xorLoop().className()
                    + ", метод " + analysis.xorLoop().methodName()
                    + " - " + file.location();
        }
        if (!analysis.xorStrings().isEmpty()) {
            bytecodeState.dangerousXorFound = true;
        }

        rat.inspectNames(analysis.className(), analysis.methodNames(), file.location());

        for (HardwareCall call : analysis.hardwareCalls()) {
            hardwareIds.inspectCall(call, file.location());
        }

        addDangerousCalls(analysis, file, result);
        addSurveillanceCalls(analysis, file, result);
        addC2Calls(analysis, file, result);
        addDecodedStrings(analysis.xorStrings(), analysis, file, result);
        addDecodedStrings(analysis.assembledStrings(), analysis, file, result);
    }

    private void reportHiddenJars(List<String> suspiciousJars, ModScanResult result) {
        if (suspiciousJars.isEmpty()) {
            return;
        }

        String first = suspiciousJars.get(0);
        result.addFindingWithScope(new Finding(
                24,
                "Jar спрятан в ресурсах",
                6,
                "файл " + first,
                "вложенный jar вне META-INF/jars и META-INF/jarjar"
        ), first);

        for (int i = 1; i < suspiciousJars.size(); i++) {
            String hidden = suspiciousJars.get(i);
            result.markEvidenceRule(24, "файл " + hidden, hidden);
        }
    }

    private void addSurveillanceCalls(BytecodeAnalysis analysis, ArchiveFile file,
                                      ModScanResult result) {
        if (analysis.surveillanceCalls().isEmpty()) {
            return;
        }

        boolean screenOrWebcam = analysis.surveillanceCalls().stream()
                .anyMatch(call -> !"микрофон".equals(call.kind()));
        boolean microphone = analysis.surveillanceCalls().stream()
                .anyMatch(call -> "микрофон".equals(call.kind()));
        int points = (screenOrWebcam ? 4 : 0) + (microphone ? 1 : 0);

        SurveillanceCall first = analysis.surveillanceCalls().stream()
                .filter(call -> screenOrWebcam && !"микрофон".equals(call.kind()))
                .findFirst()
                .orElse(analysis.surveillanceCalls().get(0));
        String firstLocation = "класс " + first.className()
                + ", метод " + first.methodName()
                + " - " + file.location();
        StringBuilder evidence = new StringBuilder("вызовы: ");
        for (int i = 0; i < analysis.surveillanceCalls().size(); i++) {
            SurveillanceCall call = analysis.surveillanceCalls().get(i);
            if (i > 0) {
                evidence.append("; ");
            }
            evidence.append(call.owner().replace('/', '.'))
                    .append('.').append(call.calledName())
                    .append(" (").append(call.kind()).append(')');
            if (!"микрофон".equals(call.kind())) {
                String location = "класс " + call.className()
                        + ", метод " + call.methodName()
                        + " - " + file.location();
                result.markCriticalHarm(location);
            }
        }

        result.addFinding(new Finding(
                27,
                "Слежка",
                points,
                firstLocation,
                evidence.toString()
        ));
    }

    private void addC2Calls(BytecodeAnalysis analysis, ArchiveFile file,
                            ModScanResult result) {
        for (C2Call call : analysis.c2Calls()) {
            String location = "класс " + call.className()
                    + ", метод " + call.methodName()
                    + " - " + file.location();
            if (call.host().matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
                result.addFoundEntity("IP", call.host(), location);
            } else {
                result.addFoundEntity("домен", call.host(), location);
            }
            if (result.hasRule(29)) {
                continue;
            }
            result.addFinding(new Finding(
                    29,
                    "C2-подключение",
                    3,
                    location,
                    call.kind() + ": " + call.host()
            ));
        }
    }

    private void addDangerousCalls(BytecodeAnalysis analysis, ArchiveFile file,
                                   ModScanResult result) {
        for (DangerousCall call : analysis.dangerousCalls()) {
            boolean opensFolderOrLink = call.rule() == 13
                    && call.openCommandContext();
            int points = opensFolderOrLink ? 1 : callPoints(call.rule());
            String evidence = "вызов: " + call.owner().replace('/', '.')
                    + "." + call.calledName();
            if (opensFolderOrLink) {
                evidence += " (рядом: открытие папки/ссылки)";
            }

            result.addOrUpgradeFinding(new Finding(
                    call.rule(),
                    callTitle(call.rule()),
                    points,
                    "класс " + call.className()
                            + ", метод " + call.methodName()
                            + " - " + file.location(),
                    evidence
            ));
        }

        if (!analysis.dangerousInClinit()) {
            return;
        }

        DangerousCall first = analysis.dangerousCalls().stream()
                .filter(call -> "<clinit>".equals(call.methodName()))
                .findFirst()
                .orElse(null);
        if (first == null) {
            return;
        }

        result.addFinding(new Finding(
                16,
                "Опасный вызов в статическом блоке",
                2,
                "класс " + first.className()
                        + ", метод <clinit> - " + file.location(),
                "в <clinit>: " + first.owner().replace('/', '.')
                        + "." + first.calledName()
        ));
    }

    private void addDecodedStrings(List<DecodedCandidate> candidates,
                                   BytecodeAnalysis analysis, ArchiveFile file,
                                   ModScanResult result) {
        for (DecodedCandidate candidate : candidates) {
            for (SignatureRule baseRule : SignatureRules.matching(candidate.value())) {
                result.markEvidenceRule(baseRule.id(), "класс " + analysis.className()
                        + ", метод " + candidate.methodName()
                        + " - " + file.location());
                result.addOrUpgradeFinding(new Finding(
                        10,
                        "Строка восстановлена из байткода",
                        baseRule.points() + 3,
                        "класс " + analysis.className()
                                + ", метод " + candidate.methodName()
                                + " - " + file.location(),
                        candidate.technique() + " -> " + baseRule.title()
                ));
            }
        }
    }

    private static String callTitle(int rule) {
        return switch (rule) {
            case 12 -> "Загрузка кода";
            case 13 -> "Запуск процесса";
            case 14 -> "Сетевое подключение";
            default -> "Опасный вызов";
        };
    }

    private static int callPoints(int rule) {
        return switch (rule) {
            case 12 -> 4;
            case 13 -> 3;
            case 14 -> 2;
            default -> 0;
        };
    }

    private static boolean isTextFile(String lowerName) {
        return TEXT_EXTENSIONS.stream().anyMatch(lowerName::endsWith);
    }

    private static boolean isExecutable(String lowerName) {
        return EXECUTABLE_EXTENSIONS.stream().anyMatch(lowerName::endsWith);
    }

    private static String extensionOf(String fileName) {
        int dot = fileName.lastIndexOf('.');
        return dot < 0 ? "?" : fileName.substring(dot).toLowerCase(Locale.ROOT);
    }

    /**
     * Общее состояние по всем классам мода: где впервые встретился XOR-цикл
     * и была ли хотя бы одна опасная XOR-строка. Правило 11 добавляется
     * только если опасной XOR-строки не нашлось.
     */
    private static final class BytecodeScanState {
        private String xorLoopLocation;
        private boolean dangerousXorFound;
    }
}
