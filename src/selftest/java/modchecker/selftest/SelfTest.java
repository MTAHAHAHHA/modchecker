package modchecker.selftest;

import modchecker.gui.ModTableModel;
import modchecker.model.Finding;
import modchecker.model.LinkFinding;
import modchecker.model.ModScanResult;
import modchecker.model.Verdict;
import modchecker.online.CurseForgeKeyStore;
import modchecker.online.Hashes;
import modchecker.online.KeyCheckStatus;
import modchecker.online.OnlineCheckResult;
import modchecker.online.OnlineChecker;
import modchecker.online.OnlineStatus;
import modchecker.report.ModReport;
import modchecker.report.ReportPrinter;
import modchecker.scan.ModFinder;
import modchecker.scan.ScanService;
import modchecker.trust.TrustedHashes;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;
import java.util.stream.Stream;

/**
 * Первый набор автотестов. На этом шаге он проверяет, что тестовые jar'ы
 * действительно содержат нужные строки и байткод, но ничего не запускает.
 */
public final class SelfTest {

    private static final List<String> EXPECTED_JARS = List.of(
            "broken.jar",
            "clean.jar",
            "discord_integration.jar",
            "fractureiser.jar",
            "hidden_stealer.jar",
            "loader.jar",
            "obfuscated.jar",
            "stealer.jar",
            "xor_stealer.jar"
    );

    private static final List<String> EXPECTED_EXTRA_JARS = List.of(
            "asm_calls.jar",
            "clinit_exec.jar",
            "fake_visual_rat.jar",
            "hidden_max_10.jar",
            "hidden_max_9.jar",
            "paths.jar",
            "safe_xor.jar",
            "symbol_assembly.jar",
            "symbol_chars.jar"
    );

    private static final String DISCORD_WEBHOOK =
            "https://discord.com/api/webhooks/123456789012345678/test-token";
    private static final String HIDDEN_WEBHOOK =
            "https://discord.com/api/webhooks/1/test";

    private static final List<String> CLEAN_FORBIDDEN = List.of(
            "discord.com/api/webhooks",
            "discordapp.com/api/webhooks",
            "api.telegram.org",
            "launcher_accounts",
            "launcher_profiles",
            "Local Storage",
            "leveldb",
            "Login Data",
            "Cookies",
            "wallet.dat",
            "dev/neko",
            "skyrage",
            "pastebin.com",
            "URLClassLoader",
            "defineClass",
            "Runtime",
            "ProcessBuilder",
            "openConnection",
            "HttpClient",
            "APPDATA",
            "AppData",
            "user.home"
    );

    private static int passed;
    private static int failed;

    private SelfTest() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            throw new IllegalArgumentException(
                    "Нужны пути к папке тестовых модов и папке дополнительных модов");
        }

        Path modsDir = Path.of(args[0]).toAbsolutePath().normalize();
        Path extraDir = Path.of(args[1]).toAbsolutePath().normalize();
        System.out.println("Проверяю тестовые моды в " + modsDir);
        System.out.println("Дополнительные моды: " + extraDir);
        System.out.println();

        check("Созданы все 9 тестовых файлов", () -> {
            List<String> actual = listJarNames(modsDir);
            if (!actual.equals(EXPECTED_JARS)) {
                throw new IllegalStateException("ожидалось " + EXPECTED_JARS + ", получено " + actual);
            }
        });

        check("Созданы все 9 дополнительных тестовых файлов", () -> {
            List<String> actual = listJarNames(extraDir);
            if (!actual.equals(EXPECTED_EXTRA_JARS)) {
                throw new IllegalStateException(
                        "ожидалось " + EXPECTED_EXTRA_JARS + ", получено " + actual);
            }
        });

        check("clean: обычные строки без опасных признаков", () -> verifyClean(modsDir));
        check("discord_integration: вебхук и HttpClient", () -> verifyDiscord(modsDir));
        check("stealer: вебхук и Local Storage", () -> verifyStealer(modsDir));
        check("hidden_stealer: вебхук только в Base64", () -> verifyHidden(modsDir));
        check("xor_stealer: Telegram XOR и launcher_accounts", () -> verifyXor(modsDir));
        check("loader: pastebin XOR, URLClassLoader в <clinit>", () -> verifyLoader(modsDir));
        check("fractureiser: строка dev/neko", () -> verifyFractureiser(modsDir));
        check("obfuscated: 12 классов и длинная случайная строка", () -> verifyObfuscated(modsDir));
        check("broken: файл не открывается как zip", () -> verifyBroken(modsDir));

        runScannerChecks(modsDir, extraDir, modsDir.resolveSibling("selftest-tmp"));

        System.out.println();
        if (failed > 0) {
            throw new IllegalStateException("Провалено проверок: " + failed + ", пройдено: " + passed);
        }
        System.out.println("Итог: " + passed + " проверок пройдено, 0 провалено.");
    }

    private static void verifyClean(Path modsDir) throws IOException {
        Map<String, byte[]> entries = readEntries(modsDir.resolve("clean.jar"));

        require(entries.containsKey("testmods/clean/CleanMod.class"),
                "в clean.jar нет CleanMod.class");
        require(containsInAnyEntry(entries, "Hello, Minecraft!"),
                "в clean.jar нет ожидаемой безопасной строки");

        for (String forbidden : CLEAN_FORBIDDEN) {
            require(!containsInAnyEntry(entries, forbidden),
                    "clean.jar случайно содержит опасный признак: " + forbidden);
        }
    }

    private static void verifyDiscord(Path modsDir) throws IOException {
        Map<String, byte[]> entries = readEntries(modsDir.resolve("discord_integration.jar"));

        require(containsInAnyEntry(entries, DISCORD_WEBHOOK),
                "не найден Discord-вебхук");
        require(containsInAnyEntry(entries, "java/net/http/HttpClient"),
                "не найден вызов HttpClient");
    }

    private static void verifyStealer(Path modsDir) throws IOException {
        Map<String, byte[]> entries = readEntries(modsDir.resolve("stealer.jar"));

        require(containsInAnyEntry(entries, DISCORD_WEBHOOK), "не найден Discord-вебхук");
        require(containsInAnyEntry(entries, "Local Storage"), "не найдена строка Local Storage");
    }

    private static void verifyHidden(Path modsDir) throws IOException {
        Map<String, byte[]> entries = readEntries(modsDir.resolve("hidden_stealer.jar"));

        require(!containsInAnyEntry(entries, HIDDEN_WEBHOOK),
                "вебхук присутствует открытым текстом, а должен быть только в Base64");
        require(containsInAnyEntry(entries, "Local Storage"), "не найдена строка Local Storage");

        boolean decoded = false;
        for (byte[] classBytes : classEntries(entries).values()) {
            for (String constant : stringConstants(classBytes)) {
                try {
                    String plain = new String(Base64.getDecoder().decode(constant),
                            StandardCharsets.UTF_8);
                    if (plain.contains(HIDDEN_WEBHOOK)) {
                        decoded = true;
                        break;
                    }
                } catch (IllegalArgumentException ignored) {
                    // Это просто не Base64-строка.
                }
            }
            if (decoded) {
                break;
            }
        }
        require(decoded, "Base64-строка не раскодируется в ожидаемый вебхук");
    }

    private static void verifyXor(Path modsDir) throws IOException {
        Map<String, byte[]> entries = readEntries(modsDir.resolve("xor_stealer.jar"));

        require(!containsInAnyEntry(entries, "api.telegram.org"),
                "api.telegram.org присутствует открытым текстом, а должен быть XOR");
        require(containsInAnyEntry(entries, "launcher_accounts"),
                "не найдена строка launcher_accounts");
        require(hasOpcode(entries, Opcodes.IXOR),
                "в байткоде xor_stealer нет операции XOR");
    }

    private static void verifyLoader(Path modsDir) throws IOException {
        Map<String, byte[]> entries = readEntries(modsDir.resolve("loader.jar"));

        require(!containsInAnyEntry(entries, "pastebin.com"),
                "pastebin.com присутствует открытым текстом, а должен быть XOR");

        boolean found = classEntries(entries).values().stream()
                .anyMatch(SelfTest::hasUrlClassLoaderInStaticInitializer);
        require(found, "не найден URLClassLoader внутри <clinit>");
    }

    private static void verifyFractureiser(Path modsDir) throws IOException {
        Map<String, byte[]> entries = readEntries(modsDir.resolve("fractureiser.jar"));
        require(containsInAnyEntry(entries, "dev/neko"), "не найдена строка dev/neko");
    }

    private static void verifyObfuscated(Path modsDir) throws IOException {
        Map<String, byte[]> entries = readEntries(modsDir.resolve("obfuscated.jar"));

        Set<String> names = new LinkedHashSet<>();
        for (String name : entries.keySet()) {
            if (name.startsWith("testmods/obfuscated/") && name.endsWith(".class")) {
                String simpleName = name.substring("testmods/obfuscated/".length(),
                        name.length() - ".class".length());
                names.add(simpleName);
            }
        }

        Set<String> expected = new LinkedHashSet<>(Arrays.asList(
                "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"));
        require(names.equals(expected), "ожидались классы a..l, найдено: " + names);

        List<String> constants = new ArrayList<>();
        for (byte[] classBytes : classEntries(entries).values()) {
            constants.addAll(stringConstants(classBytes));
        }

        boolean hasLongRandom = constants.stream().anyMatch(value ->
                value.length() >= 64
                        && value.chars().noneMatch(Character::isWhitespace)
                        && !value.contains("/")
                        && !value.contains(";")
                        && entropy(value) >= 4.8);

        require(hasLongRandom, "не найдена длинная случайная строка с энтропией >= 4.8");
    }

    private static void verifyBroken(Path modsDir) {
        boolean openedAsZip = false;
        try {
            readEntries(modsDir.resolve("broken.jar"));
            openedAsZip = true;
        } catch (IOException expected) {
            // Так и должно быть: это не zip.
        }
        require(!openedAsZip, "broken.jar неожиданно открылся как zip");
    }

    private static void runScannerChecks(Path modsDir, Path extraDir,
                                         Path tempDir) throws IOException {
        Files.createDirectories(tempDir);
        ScanService scanner = new ScanService();

        check("Хеши: MurmurHash2 и фильтрация CurseForge", () -> {
            require(Hashes.murmurHash2(utf8(""), 1) == 1540447798L,
                    "MurmurHash2 для пустой строки");
            require(Hashes.murmurHash2(utf8("a"), 1) == 626045324L,
                    "MurmurHash2 для \"a\"");
            require(Hashes.murmurHash2(utf8("hello"), 1) == 2788266382L,
                    "MurmurHash2 для \"hello\"");
            require(Hashes.murmurHash2(utf8("Minecraft mod"), 1) == 2127713455L,
                    "MurmurHash2 для \"Minecraft mod\"");
            require(Hashes.curseForgeFingerprint(utf8("Minecraft mod")) == 101310214L,
                    "фильтрованный отпечаток CurseForge");
            require(Arrays.equals(
                            Hashes.filterForCurseForge(utf8("a\tb\nc\rd e")),
                            utf8("abcde")),
                    "фильтр CurseForge должен убирать 9, 10, 13 и 32");
        });

        check("Хеши: SHA-1 файла", () -> {
            Path file = tempDir.resolve("sha1_hello.txt");
            Files.writeString(file, "hello", StandardCharsets.UTF_8);
            require(Hashes.sha1(file).equals(
                            "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"),
                    "неверный SHA-1 для строки hello");
        });

        check("Сканер: clean - 0 очков", () -> {
            ModScanResult result = scanner.scan(modsDir.resolve("clean.jar"));
            assertPointsAndRules(result, 0, Set.of());
        });

        check("Сканер: .jar.sample читается как обычный jar", () -> {
            Path sample = writeJar(tempDir, "webhook_sample.jar.sample", Map.of(
                    "testmods/sample/SampleMod.class",
                    classWithString("testmods/sample/SampleMod", HIDDEN_WEBHOOK)
            ));

            ModScanResult result = scanner.scan(sample);
            assertPointsAndRules(result, 4, Set.of(1));
            require(finding(result, 1).location().contains("SampleMod"),
                    "в находке из .jar.sample нет класса SampleMod");
        });

        check("Доверенные хеши: вердикт ДОВЕРЕН (вручную) не скрывает находки", () -> {
            Path jar = writeJar(tempDir, "trusted_suspicious.jar", Map.of(
                    "testmods/trusted/Stealer.class",
                    classWithString("testmods/trusted/Stealer",
                            "discord.com/api/webhooks/1/test Local Storage")
            ));

            ModScanResult scan = scanner.scan(jar);
            require(scan.points() >= ModScanResult.SUSPICIOUS_THRESHOLD,
                    "для проверки доверия нужен файл с 10+ очками");
            String sha1 = Hashes.sha1(jar);
            Path trustedFile = TrustedHashes.fileNear(jar);
            require(TrustedHashes.add(trustedFile, sha1, "ручной тест"),
                    "хеш не добавился в trusted_hashes.txt");

            var found = TrustedHashes.find(jar, sha1);
            require(found.isPresent(), "хеш не найден в trusted_hashes.txt");
            require(found.get().comment().equals("ручной тест"),
                    "комментарий доверенного хеша не сохранился");

            scan.markManuallyTrusted(
                    found.get().source().toString(), found.get().comment());
            require(scan.verdict() == Verdict.TRUSTED,
                    "доверенный файл должен получать ДОВЕРЕН (вручную)");
            require(!scan.findings().isEmpty(),
                    "у доверенного файла должны остаться все находки");
            require(scan.points() >= ModScanResult.SUSPICIOUS_THRESHOLD,
                    "доверие не должно менять очки");

            require(TrustedHashes.remove(trustedFile, sha1),
                    "хеш не удалился из trusted_hashes.txt");
            require(TrustedHashes.findInFile(trustedFile, sha1).isEmpty(),
                    "удалённый хеш всё ещё находится");
        });

        check("Сканер: discord_integration - вебхук и HttpClient", () -> {
            ModScanResult result = scanner.scan(modsDir.resolve("discord_integration.jar"));
            assertPointsAndRules(result, 6, Set.of(1, 14));
            require(finding(result, 1).location().contains("DiscordIntegration"),
                    "в месте находки нет класса DiscordIntegration");
            require(finding(result, 1).location().contains("webhook"),
                    "в месте находки нет метода webhook");
            require(finding(result, 14).location().contains("client"),
                    "у HttpClient не показан метод client");
            require(finding(result, 14).evidence().contains("HttpClient"),
                    "в доказательстве нет HttpClient");
        });

        check("Сканер: stealer - вебхук, Local Storage и КРАЖА", () -> {
            ModScanResult result = scanner.scan(modsDir.resolve("stealer.jar"));
            assertPointsRulesAndLinks(result, 12, Set.of(1, 4), Set.of("КРАЖА"));
            LinkFinding theft = link(result, "КРАЖА");
            require(theft.points() == 4, "связка КРАЖА должна давать +4");
            require(theft.evidence().contains("1") && theft.evidence().contains("4"),
                    "в связке КРАЖА не указаны правила 1 и 4");
        });

        check("Сканер: hidden_stealer - Base64-вебхук, Local Storage и КРАЖА", () -> {
            ModScanResult result = scanner.scan(modsDir.resolve("hidden_stealer.jar"));
            assertPointsRulesAndLinks(result, 15, Set.of(4, 9), Set.of("КРАЖА"));
            require(result.hasEvidenceRule(1),
                    "скрытый вебхук должен участвовать в связке КРАЖА");
            require(finding(result, 9).points() == 7,
                    "за скрытый вебхук ожидалось 4 + 3 = 7 очков");
            require(finding(result, 9).location().contains("packed"),
                    "в месте находки нет метода packed");
            require(link(result, "КРАЖА").evidence().contains("1 + 4"),
                    "связка должна сложиться из скрытого правила 1 и правила 4");
            require(result.decodedNotes().isEmpty(),
                    "опасная Base64-строка не должна попадать в заметки");
        });

        check("Сканер: xor_stealer - Telegram XOR, аккаунты и КРАЖА", () -> {
            ModScanResult result = scanner.scan(modsDir.resolve("xor_stealer.jar"));
            assertPointsRulesAndLinks(result, 13, Set.of(3, 10), Set.of("КРАЖА"));
            require(finding(result, 3).location().contains("accounts"),
                    "в месте находки нет метода accounts");
            require(finding(result, 10).points() == 6,
                    "за XOR-строку Telegram ожидалось 3 + 3 = 6 очков");
            require(finding(result, 10).location().contains("endpoint"),
                    "у XOR-строки не показан метод endpoint");
            require(finding(result, 10).evidence().contains("XOR"),
                    "не указано, что строка восстановлена XOR");
            require(result.hasEvidenceRule(2),
                    "XOR-строка api.telegram.org должна считаться Telegram");
            require(!result.hasRule(11),
                    "правило 11 не должно добавляться, если XOR дал опасную строку");
            require(link(result, "КРАЖА").evidence().contains("2 + 3"),
                    "связка должна сложиться из XOR-правила 2 и правила 3");
        });

        check("Сканер: loader - pastebin XOR, URLClassLoader и ЗАГРУЗЧИК", () -> {
            ModScanResult result = scanner.scan(modsDir.resolve("loader.jar"));
            assertPointsRulesAndLinks(result, 13, Set.of(10, 12, 16), Set.of("ЗАГРУЗЧИК"));
            require(finding(result, 10).points() == 4,
                    "за XOR-строку pastebin ожидалось 1 + 3 = 4 очка");
            require(finding(result, 10).location().contains("<clinit>"),
                    "у XOR-строки не показан метод <clinit>");
            require(result.hasEvidenceRule(8),
                    "XOR-строка pastebin должна считаться Pastebin");
            require(finding(result, 12).location().contains("<clinit>"),
                    "URLClassLoader должен быть найден в <clinit>");
            require(finding(result, 16).location().contains("<clinit>"),
                    "правило 16 должно указать <clinit>");
            require(!result.hasRule(11),
                    "правило 11 не должно добавляться, если XOR дал опасную строку");
            LinkFinding loaderLink = link(result, "ЗАГРУЗЧИК");
            require(loaderLink.points() == 3, "связка ЗАГРУЗЧИК должна давать +3");
            require(loaderLink.evidence().contains("10 + 12"),
                    "связка должна сложиться из правил 10 и 12");
        });

        check("Сканер: случайная строка + defineClass не даёт ЗАГРУЗЧИК", () -> {
            String token = randomToken(80, 777L);
            Path jar = writeJar(tempDir, "random_string_define_class.jar", Map.of(
                    "testmods/define/DefineRandom.class",
                    classWithStringAndDefineClass(
                            "testmods/define/DefineRandom", token)
            ));

            ModScanResult result = scanner.scan(jar);
            assertPointsRulesAndLinks(result, 5, Set.of(12, 18), Set.of());
            require(result.hasRule(12), "defineClass должен дать правило 12");
            require(result.hasRule(18), "случайная строка должна дать правило 18");
            require(result.links().isEmpty(),
                    "правило 18 не должно участвовать в связке ЗАГРУЗЧИК");
        });

        check("Сканер: hwid_collector - правила 22+23 = 5 очков", () -> {
            Map<String, byte[]> entries = new LinkedHashMap<>();
            entries.put("testmods/hwid/a.class",
                    classWithHardwareCollector("testmods/hwid/a"));
            for (int i = 0; i < 10; i++) {
                String name = "Feature" + (char) ('A' + i);
                entries.put("testmods/hwid/" + name + ".class",
                        emptyClass("testmods/hwid/" + name));
            }

            Path jar = writeJar(tempDir, "hwid_collector.jar", entries);
            ModScanResult result = scanner.scan(jar);
            assertPointsRulesAndLinks(result, 5, Set.of(22, 23), Set.of());
            require(result.verdict() == Verdict.UNKNOWN,
                    "5 очков без сайта должны давать НЕИЗВЕСТНО");

            require(finding(result, 22).location().contains("класс testmods.hwid.a"),
                    "правило 22 не показало короткий класс a");
            require(finding(result, 22).location().contains("метод collect"),
                    "правило 22 не показало метод collect");
            require(finding(result, 22).evidence().contains("getHardwareUUID"),
                    "правило 22 не показало вызов getHardwareUUID");
            require(finding(result, 23).location().contains("testmods.hwid.a"),
                    "правило 23 не показало класс со спрятанным сбором");
            require(finding(result, 23).evidence().contains("10 из 11"),
                    "правило 23 не посчитало нормальные классы");
        });

        check("Сканер: правило 23 - O004 и Il1", () -> {
            for (String shortName : List.of("O004", "Il1")) {
                Map<String, byte[]> entries = new LinkedHashMap<>();
                String className = "testmods/hwid/" + shortName;
                entries.put(className + ".class",
                        classWithHardwareCall(className,
                                "oshi/hardware/ComputerSystem", "getHardwareUUID",
                                "()Ljava/lang/String;", true));
                for (int i = 0; i < 10; i++) {
                    String normalName = "Feature" + (char) ('A' + i);
                    entries.put("testmods/hwid/" + normalName + ".class",
                            emptyClass("testmods/hwid/" + normalName));
                }

                Path jar = writeJar(tempDir, "hwid_" + shortName + ".jar", entries);
                ModScanResult result = scanner.scan(jar);
                assertPointsRulesAndLinks(result, 5, Set.of(22, 23), Set.of());
            }
        });

        check("Сканер: правило 22 - OSHI, MAC и строки Windows", () -> {
            record Call(String owner, String name, String descriptor,
                        boolean isInterface) {
            }

            List<Call> calls = List.of(
                    new Call("oshi/hardware/ComputerSystem", "getHardwareUUID",
                            "()Ljava/lang/String;", true),
                    new Call("oshi/hardware/Baseboard", "getSerialNumber",
                            "()Ljava/lang/String;", true),
                    new Call("oshi/hardware/HWDiskStore", "getSerial",
                            "()Ljava/lang/String;", true),
                    new Call("java/net/NetworkInterface", "getHardwareAddress",
                            "()[B", false)
            );

            int index = 0;
            for (Call call : calls) {
                String className = "testmods/hwid/Call" + index;
                Path jar = writeJar(tempDir, "hwid_call_" + index + ".jar", Map.of(
                        className + ".class",
                        classWithHardwareCall(className, call.owner(), call.name(),
                                call.descriptor(), call.isInterface())
                ));

                ModScanResult result = scanner.scan(jar);
                assertPointsAndRules(result, 3, Set.of(22));
                require(!result.hasRule(23),
                        "без короткого класса правило 23 не должно добавляться");
                require(finding(result, 22).evidence().contains(call.name()),
                        "в доказательстве нет " + call.name());
                index++;
            }

            List<String> markers = List.of(
                    "wmic csproduct get uuid",
                    "csproduct",
                    "wmic baseboard get serialnumber",
                    "wmic diskdrive get serialnumber",
                    "MachineGuid"
            );
            for (String marker : markers) {
                String className = "testmods/hwid/String" + index;
                Path jar = writeJar(tempDir, "hwid_string_" + index + ".jar", Map.of(
                        className + ".class", classWithString(className, marker)
                ));

                ModScanResult result = scanner.scan(jar);
                assertPointsAndRules(result, 3, Set.of(22));
                require(!result.hasRule(23),
                        "без короткого класса правило 23 не должно добавляться");
                index++;
            }

            Path configJar = writeJar(tempDir, "hwid_config_words.jar", Map.of(
                    "testmods/config/ServerConfig$DiskDrive.class",
                    classWithString("testmods/config/ServerConfig$DiskDrive", "diskdrive"),
                    "testmods/config/BaseboardConfig.class",
                    classWithString("testmods/config/BaseboardConfig", "baseboard")
            ));
            ModScanResult configResult = scanner.scan(configJar);
            assertPointsAndRules(configResult, 0, Set.of());
        });

        check("Сканер: правило 9 берёт максимум из pastebin и вебхука", () -> {
            ModScanResult result = scanner.scan(extraDir.resolve("hidden_max_9.jar"));
            assertPointsAndRules(result, 7, Set.of(9));
            require(finding(result, 9).points() == 7,
                    "из 4 и 7 очков должно остаться максимальное значение 7");
            require(finding(result, 9).evidence().contains("Discord"),
                    "победить должен скрытый Discord-вебхук");
            require(result.hasEvidenceRule(1) && result.hasEvidenceRule(8),
                    "обе скрытые строки должны остаться в доказательствах");
        });

        check("Сканер: правило 10 берёт максимум из двух XOR-строк", () -> {
            ModScanResult result = scanner.scan(extraDir.resolve("hidden_max_10.jar"));
            assertPointsAndRules(result, 7, Set.of(10));
            require(finding(result, 10).points() == 7,
                    "из 4 и 7 очков должно остаться максимальное значение 7");
            require(finding(result, 10).location().contains("webhook"),
                    "победить должна XOR-строка из метода webhook");
            require(finding(result, 10).evidence().contains("Discord"),
                    "победить должен скрытый Discord-вебхук");
            require(result.hasEvidenceRule(1) && result.hasEvidenceRule(8),
                    "обе XOR-строки должны остаться в доказательствах");
        });

        check("Сканер: Runtime.exec/ProcessBuilder и сетевые вызовы", () -> {
            ModScanResult result = scanner.scan(extraDir.resolve("asm_calls.jar"));
            assertPointsAndRules(result, 5, Set.of(13, 14));
            require(finding(result, 13).location().contains("exec"),
                    "у правила 13 не показан метод exec");
            require(finding(result, 14).location().contains("connect"),
                    "у правила 14 не показан метод connect");
            require(!result.hasRule(16),
                    "вне <clinit> правило 16 добавляться не должно");
        });

        check("Сканер: Runtime.exec рядом с explorer - 1 очко", () -> {
            int index = 0;
            for (String marker : List.of(
                    "explorer", "xdg-open", "open", "rundll32 url.dll")) {
                String className = "testmods/open/Open" + index;
                Path jar = writeJar(tempDir, "open_command_" + index + ".jar", Map.of(
                        className + ".class",
                        classWithCallAndString(className,
                                "java/lang/Runtime", "exec",
                                "(Ljava/lang/String;)Ljava/lang/Process;",
                                false, marker)
                ));

                ModScanResult result = scanner.scan(jar);
                assertPointsAndRules(result, 1, Set.of(13));
                require(finding(result, 13).evidence().contains("открытие"),
                        "в доказательстве нет пометки об открытии папки/ссылки");
                index++;
            }
        });

        check("Сканер: Runtime.exec в open() и команда в соседнем методе - 1 очко", () -> {
            String className = "testmods/open/OpenHelper";
            Path jar = writeJar(tempDir, "open_helper.jar", Map.of(
                    className + ".class",
                    classWithOpenHelper(className, "xdg-open")
            ));

            ModScanResult result = scanner.scan(jar);
            assertPointsAndRules(result, 1, Set.of(13));
            require(finding(result, 13).location().contains("метод open"),
                    "правило 13 должно относиться к методу open");
        });

        check("Сканер: два опасных вызова в <clinit> дают 16 один раз", () -> {
            ModScanResult result = scanner.scan(extraDir.resolve("clinit_exec.jar"));
            assertPointsAndRules(result, 5, Set.of(13, 16));
            require(finding(result, 16).location().contains("<clinit>"),
                    "правило 16 должно указать <clinit>");
            require(result.findings().stream()
                            .filter(finding -> finding.rule() == 16).count() == 1,
                    "правило 16 должно добавляться только один раз");
        });

        check("Сканер: APPDATA и user.home - правило 15", () -> {
            ModScanResult result = scanner.scan(extraDir.resolve("paths.jar"));
            assertPointsAndRules(result, 2, Set.of(15));
            require(finding(result, 15).location().contains("PathsMod"),
                    "у пути не показан класс PathsMod");
            require(finding(result, 15).evidence().contains("APPDATA"),
                    "не указан найденный путь APPDATA");
        });

        check("Сканер: безопасный XOR-цикл - правило 11", () -> {
            ModScanResult result = scanner.scan(extraDir.resolve("safe_xor.jar"));
            assertPointsAndRules(result, 2, Set.of(11));
            require(finding(result, 11).location().contains("text"),
                    "у XOR-цикла не показан метод text");
            require(!result.hasRule(10),
                    "безопасная XOR-строка не должна давать правило 10");
        });

        check("Сканер: числовой XOR с буфером не даёт правило 11 и ЗАГРУЗЧИК", () -> {
            Path jar = writeJar(tempDir, "numeric_xor_library.jar", Map.of(
                    "testmods/hash/BufferHash.class", classWithBufferXor(false),
                    "testmods/hash/ClassFactory.class",
                    classWithCallAndString("testmods/hash/ClassFactory",
                            "java/lang/ClassLoader", "defineClass",
                            "([BII)Ljava/lang/Class;", false, "safe")));
            ModScanResult result = scanner.scan(jar);
            assertPointsAndRules(result, 4, Set.of(12));
            require(!result.hasEvidenceRule(11),
                    "числовой хеш не должен давать улику загрузчика");
        });

        check("Сканер: XOR записывается в байты без создания String", () -> {
            Path jar = writeJar(tempDir, "xor_bytes_only.jar", Map.of(
                    "testmods/hash/BufferHash.class", classWithBufferXor(true)));
            assertPointsAndRules(scanner.scan(jar), 2, Set.of(11));
        });

        check("Сканер: сборка строки через StringBuilder", () -> {
            ModScanResult result = scanner.scan(extraDir.resolve("symbol_assembly.jar"));
            assertPointsAndRules(result, 6, Set.of(10));
            require(finding(result, 10).location().contains("endpoint"),
                    "у собранной строки не показан метод endpoint");
            require(finding(result, 10).evidence().contains("сборка по символам"),
                    "не указан способ сборки по символам");
            require(result.hasEvidenceRule(2),
                    "собранный api.telegram.org должен считаться Telegram");
        });

        check("Сканер: сборка строки из char[]", () -> {
            ModScanResult result = scanner.scan(extraDir.resolve("symbol_chars.jar"));
            assertPointsAndRules(result, 7, Set.of(10));
            require(finding(result, 10).location().contains("webhook"),
                    "у собранной строки не показан метод webhook");
            require(finding(result, 10).evidence().contains("сборка по символам"),
                    "не указан способ сборки по символам");
            require(result.hasEvidenceRule(1),
                    "собранный вебхук должен считаться Discord-вебхуком");
        });

        check("Сканер: fractureiser - 10 очков", () -> {
            ModScanResult result = scanner.scan(modsDir.resolve("fractureiser.jar"));
            assertPointsAndRules(result, 10, Set.of(7));
            require(finding(result, 7).location().contains("FractureiserTest"),
                    "в месте находки нет класса FractureiserTest");
            require(finding(result, 7).location().contains("marker"),
                    "в месте находки нет метода marker");
        });

        check("Сканер: obfuscated - длинная строка и короткие имена", () -> {
            ModScanResult result = scanner.scan(modsDir.resolve("obfuscated.jar"));
            assertPointsAndRules(result, 2, Set.of(18, 20));
        });

        check("Сканер: Base64 в текстовом файле", () -> {
            String encoded = Base64.getEncoder().encodeToString(
                    HIDDEN_WEBHOOK.getBytes(StandardCharsets.UTF_8));
            Path jar = writeJar(tempDir, "hidden_base64.jar", Map.of(
                    "assets/data.txt", utf8(encoded)
            ));

            ModScanResult result = scanner.scan(jar);
            assertPointsAndRules(result, 7, Set.of(9));
            require(result.hasEvidenceRule(1), "Base64-вебхук не отмечен как вебхук");
            require(finding(result, 9).evidence().contains("Base64"),
                    "не указано, что строка была в Base64");
        });

        check("Сканер: Base64 обычного текста даёт заметку", () -> {
            String plain = "ordinary text for manual review";
            String encoded = Base64.getEncoder().encodeToString(
                    plain.getBytes(StandardCharsets.UTF_8));
            Path jar = writeJar(tempDir, "base64_note.jar", Map.of(
                    "assets/note.txt", utf8(encoded)
            ));

            ModScanResult result = scanner.scan(jar);
            assertPointsAndRules(result, 0, Set.of());
            require(result.decodedNotes().size() == 1,
                    "ожидалась одна заметка, получено: " + result.decodedNotes());
            require(result.decodedNotes().get(0).value().equals(plain),
                    "раскрытый текст заметки не совпал");
            require(result.decodedNotes().get(0).location().contains("assets/note.txt"),
                    "в заметке нет места находки");

            String report = ReportPrinter.format(List.of(new ModReport(result,
                    new OnlineCheckResult("0".repeat(40),
                            OnlineStatus.SKIPPED, OnlineStatus.SKIPPED))));
            require(report.contains("Заметка: раскрытые строки"),
                    "в отчёте нет заголовка заметки");
            require(report.contains(plain),
                    "в отчёте нет раскрытой строки");
        });

        check("Сканер: Base64 заметки ограничены 10", () -> {
            StringBuilder content = new StringBuilder();
            for (int i = 0; i < 11; i++) {
                String plain = "ordinary note text number " + i;
                content.append(Base64.getEncoder().encodeToString(
                        plain.getBytes(StandardCharsets.UTF_8))).append('\n');
            }
            Path jar = writeJar(tempDir, "base64_notes_limit.jar", Map.of(
                    "assets/notes.txt", utf8(content.toString())
            ));

            ModScanResult result = scanner.scan(jar);
            assertPointsAndRules(result, 0, Set.of());
            require(result.decodedNotes().size() == 10,
                    "заметок должно быть не больше 10, получено: "
                            + result.decodedNotes().size());
        });

        check("Сканер: hex в текстовом файле", () -> {
            Path jar = writeJar(tempDir, "hidden_hex.jar", Map.of(
                    "assets/data.txt", utf8(hex("api.telegram.org"))
            ));

            ModScanResult result = scanner.scan(jar);
            assertPointsAndRules(result, 6, Set.of(9));
            require(result.hasEvidenceRule(2), "hex-Telegram не отмечен как Telegram");
            require(finding(result, 9).evidence().contains("hex"),
                    "не указано, что строка была в hex");
        });

        check("Сканер: перевёрнутая строка", () -> {
            Path jar = writeJar(tempDir, "hidden_reverse.jar", Map.of(
                    "assets/data.txt", utf8(reverse("wallet.dat"))
            ));

            ModScanResult result = scanner.scan(jar);
            assertPointsAndRules(result, 6, Set.of(9));
            require(result.hasEvidenceRule(6), "перевёрнутый wallet.dat не отмечен");
            require(finding(result, 9).evidence().contains("перевёрнутая"),
                    "не указано, что строка была перевёрнута");
        });

        check("Сканер: длинная случайная строка в .txt не даёт правило 18", () -> {
            String token = randomToken(80, 42L);
            require(entropy(token) >= 4.8,
                    "тестовая строка должна была бы дать правило 18 без фильтра");
            Path jar = writeJar(tempDir, "long_string_txt.jar", Map.of(
                    "assets/notes.txt", utf8(token)
            ));

            ModScanResult result = scanner.scan(jar);
            require(!result.hasRule(18),
                    "в .txt правило 18 не должно срабатывать");
            assertPointsAndRules(result, 0, Set.of());
        });

        check("Сканер: длинная случайная строка в .json не даёт правило 18", () -> {
            String token = randomToken(120, 4242L);
            require(entropy(token) >= 4.8,
                    "тестовая строка должна была бы дать правило 18 без фильтра");
            Path jar = writeJar(tempDir, "long_string_json.jar", Map.of(
                    "assets/data.json", utf8("{\"token\":\"" + token + "\"}")
            ));

            ModScanResult result = scanner.scan(jar);
            require(!result.hasRule(18),
                    "в .json правило 18 не должно срабатывать");
            assertPointsAndRules(result, 0, Set.of());
        });

        check("Сканер: 64 разных символа - алфавит, а не случайная строка", () -> {
            String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+_";
            require(alphabet.length() == 64, "в алфавите должно быть 64 символа");
            require(entropy(alphabet) >= 6.0,
                    "у 64 разных символов должна быть энтропия 6.00");

            Path jar = writeJar(tempDir, "alphabet64.jar", Map.of(
                    "testmods/alphabet/Alphabet.class",
                    classWithString("testmods/alphabet/Alphabet", alphabet)
            ));

            ModScanResult result = scanner.scan(jar);
            require(!result.hasRule(18),
                    "таблица из 64 разных символов не должна давать правило 18");
            assertPointsAndRules(result, 0, Set.of());
        });

        check("Сканер: правило 18 игнорирует не-ASCII строку в .class", () -> {
            String token = randomUnicodeToken(80, 42L);
            require(entropy(token) >= 4.8,
                    "тестовая не-ASCII строка должна была бы дать правило 18 без фильтра");

            Path jar = writeJar(tempDir, "long_string_unicode_class.jar", Map.of(
                    "testmods/font/FontTable.class",
                    classWithString("testmods/font/FontTable", token)
            ));

            ModScanResult result = scanner.scan(jar);
            assertPointsAndRules(result, 0, Set.of());
        });

        byte[] randomBytes = new byte[4096];
        new Random(20261020L).nextBytes(randomBytes);

        check("Сканер: большой файл с высокой энтропией", () -> {
            Path jar = writeJar(tempDir, "high_entropy.jar", Map.of(
                    "assets/payload.bin", randomBytes
            ));

            ModScanResult result = scanner.scan(jar);
            assertPointsAndRules(result, 2, Set.of(19));
        });

        check("Сканер: .png с высокой энтропией исключён", () -> {
            Path jar = writeJar(tempDir, "high_entropy_png.jar", Map.of(
                    "assets/picture.png", randomBytes
            ));

            ModScanResult result = scanner.scan(jar);
            assertPointsAndRules(result, 0, Set.of());
        });

        check("Сканер: медиа и шрифты исключены из правила 19", () -> {
            Map<String, byte[]> entries = new LinkedHashMap<>();
            entries.put("assets/track.mp3", randomBytes);
            entries.put("assets/picture.webp", randomBytes);
            entries.put("assets/animation.gif", randomBytes);
            entries.put("assets/photo.jpeg", randomBytes);
            entries.put("assets/font.woff", randomBytes);
            entries.put("assets/font.woff2", randomBytes);

            Path jar = writeJar(tempDir, "high_entropy_media.jar", entries);
            ModScanResult result = scanner.scan(jar);
            assertPointsAndRules(result, 0, Set.of());
        });

        check("Сканер: подписи META-INF исключены из правила 19", () -> {
            Map<String, byte[]> entries = new LinkedHashMap<>();
            entries.put("META-INF/TEST.RSA", randomBytes);
            entries.put("META-INF/TEST.DSA", randomBytes);
            entries.put("META-INF/TEST.EC", randomBytes);

            Path jar = writeJar(tempDir, "high_entropy_signatures.jar", entries);
            ModScanResult result = scanner.scan(jar);
            assertPointsAndRules(result, 0, Set.of());
        });

        check("Сканер: не-ASCII имена классов", () -> {
            byte[] cleanClass = readEntries(modsDir.resolve("clean.jar"))
                    .get("testmods/clean/CleanMod.class");
            require(cleanClass != null, "не найден класс для теста имён");

            Map<String, byte[]> entries = new LinkedHashMap<>();
            entries.put("testmods/unicode/Класс.class", cleanClass);
            entries.put("testmods/unicode/a.class", cleanClass);
            entries.put("testmods/unicode/b.class", cleanClass);
            entries.put("testmods/unicode/c.class", cleanClass);
            entries.put("testmods/unicode/d.class", cleanClass);
            Path jar = writeJar(tempDir, "unicode_names.jar", entries);

            ModScanResult result = scanner.scan(jar);
            assertPointsAndRules(result, 1, Set.of(21));
        });

        check("Сканер: broken - ошибка без падения", () -> {
            ModScanResult result = scanner.scan(modsDir.resolve("broken.jar"));
            require(result.hasError(), "ожидалась ошибка чтения broken.jar");
            require(result.error().contains("битый"), "неожиданный текст ошибки: " + result.error());
            require(result.points() == 0, "у битого файла не должно быть очков");
        });

        check("Сканер: финальные очки всех 9 тестовых модов", () -> {
            assertFinalPoints(scanner, modsDir.resolve("clean.jar"), 0);
            assertFinalPoints(scanner, modsDir.resolve("discord_integration.jar"), 6);
            assertFinalPoints(scanner, modsDir.resolve("stealer.jar"), 12);
            assertFinalPoints(scanner, modsDir.resolve("hidden_stealer.jar"), 15);
            assertFinalPoints(scanner, modsDir.resolve("xor_stealer.jar"), 13);
            assertFinalPoints(scanner, modsDir.resolve("loader.jar"), 13);
            assertFinalPoints(scanner, modsDir.resolve("fractureiser.jar"), 10);
            assertFinalPoints(scanner, modsDir.resolve("obfuscated.jar"), 2);

            ModScanResult broken = scanner.scan(modsDir.resolve("broken.jar"));
            require(broken.hasError(), "ожидалась ошибка чтения broken.jar");
            require(broken.error().equals("файл битый или не мод"),
                    "неожиданный текст ошибки: " + broken.error());
            require(broken.verdict() == Verdict.ERROR,
                    "у битого файла ожидался вердикт ОШИБКА");
        });

        check("Сканер: discord_integration не получает КРАЖУ", () -> {
            ModScanResult result = scanner.scan(modsDir.resolve("discord_integration.jar"));
            require(result.links().stream()
                            .noneMatch(link -> link.name().equals("КРАЖА")),
                    "discord_integration не должен получать связку КРАЖА: " + result.links());
            require(result.linkPoints() == 0,
                    "у discord_integration не должно быть очков за связки");
        });

        check("Вердикт: порог 10 для всех 9 тестовых модов", () -> {
            assertVerdict(scanner, modsDir.resolve("clean.jar"), Verdict.UNKNOWN);
            assertVerdict(scanner, modsDir.resolve("discord_integration.jar"), Verdict.UNKNOWN);
            assertVerdict(scanner, modsDir.resolve("stealer.jar"), Verdict.SUSPICIOUS);
            assertVerdict(scanner, modsDir.resolve("hidden_stealer.jar"), Verdict.SUSPICIOUS);
            assertVerdict(scanner, modsDir.resolve("xor_stealer.jar"), Verdict.SUSPICIOUS);
            assertVerdict(scanner, modsDir.resolve("loader.jar"), Verdict.SUSPICIOUS);
            assertVerdict(scanner, modsDir.resolve("fractureiser.jar"), Verdict.SUSPICIOUS);
            assertVerdict(scanner, modsDir.resolve("obfuscated.jar"), Verdict.UNKNOWN);
            assertVerdict(scanner, modsDir.resolve("broken.jar"), Verdict.ERROR);
        });

        check("Вердикт: подтверждение сайта переводит НЕИЗВЕСТНО в ОК", () -> {
            ModScanResult result = new ModScanResult(Path.of("clean.jar"));
            require(result.points() == 0, "у пустого результата не должно быть очков");
            require(result.verdict() == Verdict.UNKNOWN,
                    "без подтверждения сайта ожидался вердикт НЕИЗВЕСТНО");
            result.markOnlineConfirmed();
            require(result.verdict() == Verdict.OK,
                    "после подтверждения сайта ожидался вердикт ОК");
        });

        check("Вердикт: 7 очков и подтверждение сайта дают ОК", () -> {
            ModScanResult result = new ModScanResult(Path.of("confirmed7.jar"));
            result.addFinding(new Finding(15, "Путь", 2, "test", "test"));
            result.addFinding(new Finding(18, "Длинная строка", 1, "test", "test"));
            result.addFinding(new Finding(12, "Загрузка кода", 4, "test", "test"));

            require(result.points() == 7, "ожидалось 7 очков");
            require(result.verdict() == Verdict.UNKNOWN,
                    "до подтверждения сайта 7 очков должны давать НЕИЗВЕСТНО");
            result.markOnlineConfirmed();
            require(result.verdict() == Verdict.OK,
                    "подтверждение сайта должно переводить 7 очков в ОК");
        });

        check("Быстрая проверка: пакеты, порядок и точное совпадение SHA-1", () ->
                QuickCheckSelfTest.batches(tempDir));
        check("Быстрая проверка: нет ключа, сбой сайта и нечитаемый файл", () ->
                QuickCheckSelfTest.failures(tempDir));
        check("Быстрая проверка: полная проверка по-прежнему обнаруживает RAT", () ->
                QuickCheckSelfTest.fullScan(extraDir));
        check("Быстрая проверка: таблица и отчёт не обещают анализ кода", () ->
                QuickCheckSelfTest.presentation());
        for (String kind : List.of("entry", "total", "count", "class", "nested")) {
            check("Ограничения архива: " + kind, () -> ModernizationSelfTest.limits(tempDir, kind));
        }
        check("Ограничения: время и прерывание дают ошибку", () -> ModernizationSelfTest.timeLimit(tempDir));
        check("Настройки: сохранение и восстановление лимитов", () -> ModernizationSelfTest.scanPreferences(tempDir));
        check("Без лимитов: большие записи, время и сохранение RAT", () -> ModernizationSelfTest.unlimitedArchives(tempDir, extraDir));
        check("Лимиты: передача в полную проверку и хеширование нативных файлов", () -> ModernizationSelfTest.propagatedLimits(tempDir));
        check("Нативные файлы: только чтение, SHA-256 и вложенные пути", () -> ModernizationSelfTest.nativeFiles(tempDir));
        check("VirusTotal: GET и постоянный кэш", () -> ModernizationSelfTest.vtFound(tempDir));
        check("VirusTotal: нет данных, нет ключа, истечение кэша", () -> ModernizationSelfTest.vtMissing(tempDir));
        check("VirusTotal: ошибки ключа, квоты и ответа", () -> ModernizationSelfTest.vtErrors(tempDir));
        check("VirusTotal: общий лимит 4/мин и 500/сутки", () -> ModernizationSelfTest.vtQuota(tempDir));
        check("VirusTotal: вердикт и правило 17 не меняются", () -> ModernizationSelfTest.vtNoVerdict(tempDir));
        check("Представление: фильтры и JSON не меняют находки", ModernizationSelfTest::filtersAndExport);
        check("Murmur2: потоковый отпечаток совпадает с исходным", () -> ModernizationSelfTest.streamingHash(tempDir));
        check("Modrinth: разбор ответа и User-Agent", () -> {
            require(OnlineChecker.USER_AGENT.equals("modchecker/1.2"),
                    "неверный User-Agent для Modrinth");
            require(OnlineChecker.parseModrinthResponse(
                            "abc", "{\"abc\":{\"id\":\"version\"}}")
                            == OnlineStatus.CONFIRMED,
                    "ответ с найденным хешем не распознан");
            require(OnlineChecker.parseModrinthResponse(
                            "abc", "{\"ABC\":{\"id\":\"version\"}}")
                            == OnlineStatus.CONFIRMED,
                    "хеш должен сравниваться без учёта регистра");
            require(OnlineChecker.parseModrinthResponse("abc", "{}")
                            == OnlineStatus.NOT_FOUND,
                    "пустой ответ должен означать «не найдено»");
            require(OnlineChecker.parseModrinthResponse("abc", "not-json")
                            == OnlineStatus.SKIPPED,
                    "битый ответ должен означать «проверка пропущена»");
            require(new OnlineCheckResult("x",
                            OnlineStatus.CONFIRMED, OnlineStatus.SKIPPED).confirmed(),
                    "подтверждение Modrinth должно считаться подтверждением");
        });

        check("CurseForge: разбор ответа и 403", () -> {
            require(OnlineChecker.parseCurseForgeResponse(403, "")
                            == OnlineStatus.INVALID_KEY,
                    "403 должен давать статус недействительного ключа");
            require(OnlineStatus.INVALID_KEY.label().contains("недействителен")
                            && OnlineStatus.INVALID_KEY.label().contains("не одобрен"),
                    "статус 403 должен упоминать недействительный/неодобренный ключ");
            require(OnlineChecker.parseCurseForgeResponse(200,
                            "{\"data\":{\"exactMatches\":[{\"id\":1}]}}")
                            == OnlineStatus.CONFIRMED,
                    "exactMatches не распознан как подтверждение");
            require(OnlineChecker.parseCurseForgeResponse(200,
                            "{\"data\":{\"exactMatches\":[]}}")
                            == OnlineStatus.NOT_FOUND,
                    "пустой exactMatches должен означать «не найдено»");
            require(OnlineChecker.parseCurseForgeResponse(200, "{}")
                            == OnlineStatus.SKIPPED,
                    "битый ответ CurseForge должен пропускать проверку");
        });

        check("CurseForge: без ключа проверка пропущена", () -> {
            Path missingKey = tempDir.resolve("missing_curseforge_key.txt");
            Files.deleteIfExists(missingKey);
            OnlineChecker checker = new OnlineChecker(missingKey);
            require(checker.checkCurseForge(123L) == OnlineStatus.SKIPPED,
                    "без ключа проверка CurseForge должна быть пропущена");
            require(OnlineStatus.SKIPPED.label().equals("проверка пропущена"),
                    "неверный текст статуса пропущенной проверки");

            Path keyFile = tempDir.resolve("curseforge_key_test.txt");
            Files.writeString(keyFile, "  test-key\n", StandardCharsets.UTF_8);
            require("test-key".equals(OnlineChecker.readKey(keyFile)),
                    "ключ CurseForge не обрезан от пробелов");
            require(OnlineChecker.readKey(missingKey) == null,
                    "отсутствующий ключ должен читаться как null");
        });

        check("CurseForge: ключ в папке запуска важнее ~/.modchecker", () -> {
            Path workDir = Files.createDirectories(tempDir.resolve("key-work"));
            Path homeDir = Files.createDirectories(tempDir.resolve("key-home"));
            Path localKey = workDir.resolve("curseforge_key.txt");
            Path globalKey = homeDir.resolve(".modchecker").resolve("curseforge_key.txt");

            Files.deleteIfExists(localKey);
            Files.deleteIfExists(globalKey);
            require(OnlineChecker.readKeyFrom(workDir, homeDir) == null,
                    "без файлов ключ должен отсутствовать");

            Files.createDirectories(globalKey.getParent());
            Files.writeString(globalKey, "global-key\n", StandardCharsets.UTF_8);
            require("global-key".equals(OnlineChecker.readKeyFrom(workDir, homeDir)),
                    "не сработал запасной ключ из ~/.modchecker");

            Files.writeString(localKey, "local-key\n", StandardCharsets.UTF_8);
            require("local-key".equals(OnlineChecker.readKeyFrom(workDir, homeDir)),
                    "ключ из папки запуска должен быть важнее запасного");
        });

        check("Отчёт: в выводе нет длинного тире и стрелки", () -> {
            ModScanResult result = scanner.scan(modsDir.resolve("hidden_stealer.jar"));
            OnlineCheckResult online = new OnlineCheckResult(
                    "0000000000000000000000000000000000000000",
                    OnlineStatus.SKIPPED,
                    OnlineStatus.SKIPPED);

            String text = renderReport(result, online);
            require(!text.contains("\u2014") && !text.contains("\u2013")
                            && !text.contains("\u2192"),
                    "в выводе остались неконсольные символы: " + text);
            require(text.contains(" - "),
                    "в выводе нет обычного дефиса между частями строки");
            require(text.contains("Base64 -> Discord"),
                    "стрелка в доказательстве не заменена на ->");
        });

        check("Отчёт: последние две строки и итоги", () -> {
            ModScanResult clean = new ModScanResult(Path.of("clean.jar"));
            OnlineCheckResult online = new OnlineCheckResult(
                    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                    OnlineStatus.SKIPPED,
                    OnlineStatus.INVALID_KEY);

            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (PrintStream out = new PrintStream(
                    bytes, true, StandardCharsets.UTF_8)) {
                ReportPrinter.print(List.of(new ModReport(clean, online)), out);
            }

            String text = bytes.toString(StandardCharsets.UTF_8);
            String expectedEnd = "Подтверждение с сайта = файл тот же, "
                    + "что на официальной странице."
                    + System.lineSeparator()
                    + "ПОДОЗРИТЕЛЬНО = проверь сам, это не приговор."
                    + System.lineSeparator();

            require(text.endsWith(expectedEnd),
                    "последние две строки отчёта напечатаны неверно");
            require(text.contains("SHA-1: da39a3ee5e6b4b0d3255bfef95601890afd80709"),
                    "в отчёте нет SHA-1");
            require(text.contains("Modrinth: проверка пропущена"),
                    "в отчёте нет статуса Modrinth");
            require(text.contains("CurseForge: ключ недействителен или не одобрен (403)"),
                    "в отчёте нет статуса CurseForge для 403");
            require(text.contains("=== ИТОГО ==="),
                    "в отчёте нет блока итогов");
            require(text.contains("Проверено модов: 1"),
                    "в отчёте нет количества модов");
        });

        check("Отчёт: format совпадает с консольным выводом", () -> {
            ModScanResult hidden = scanner.scan(modsDir.resolve("hidden_stealer.jar"));
            OnlineCheckResult online = new OnlineCheckResult(
                    "0000000000000000000000000000000000000000",
                    OnlineStatus.SKIPPED,
                    OnlineStatus.SKIPPED);
            ModReport report = new ModReport(hidden, online);

            String printed = renderReport(hidden, online);
            String formatted = ReportPrinter.format(List.of(report));
            require(formatted.equals(printed),
                    "ReportPrinter.format не совпадает с консольным выводом");

            String details = ReportPrinter.formatMod(report);
            require(details.contains("=== hidden_stealer.jar ==="),
                    "в подробностях мода нет заголовка");
            require(details.contains("SHA-1:"),
                    "в подробностях мода нет SHA-1");
            require(details.contains("Base64 -> Discord"),
                    "в подробностях мода нет стрелки ->");
            require(details.contains("КРАЖА"),
                    "в подробностях мода нет связки КРАЖА");

            String secret = "cf-secret-should-not-be-printed";
            require(!formatted.contains(secret) && !details.contains(secret),
                    "ключ не должен попадать в отчёт");
        });

        check("Ключ: сохранение, загрузка и удаление", () -> {
            Path keyFile = tempDir.resolve("gui-key").resolve("curseforge_key.txt");
            Files.deleteIfExists(keyFile);

            CurseForgeKeyStore.save(keyFile, "  test-key\n");
            require("test-key".equals(CurseForgeKeyStore.load(keyFile)),
                    "сохранённый ключ не загрузился");
            require(CurseForgeKeyStore.delete(keyFile),
                    "сохранённый ключ не удалился");
            require(!Files.exists(keyFile),
                    "файл ключа остался после удаления");
            require(CurseForgeKeyStore.load(keyFile) == null,
                    "удалённый ключ всё ещё читается");

            CurseForgeKeyStore.save(keyFile, "   ");
            require(!Files.exists(keyFile),
                    "пустой ключ должен удалять файл, а не создавать его");
        });

        check("Ключ: статусы проверки 200/403/нет сети", () -> {
            require(OnlineChecker.parseKeyCheckResponse(200) == KeyCheckStatus.WORKING,
                    "200 должен означать рабочий ключ");
            require(OnlineChecker.parseKeyCheckResponse(403) == KeyCheckStatus.INVALID,
                    "403 должен означать неверный ключ");
            require(OnlineChecker.parseKeyCheckResponse(500) == KeyCheckStatus.ERROR,
                    "500 не должен выдаваться за неверный ключ");
            require(KeyCheckStatus.INVALID.label()
                            .equals("ключ неверный или не одобрен (403)"),
                    "неверный текст статуса 403");
            require(KeyCheckStatus.NO_NETWORK.label().equals("нет сети"),
                    "неверный текст статуса без сети");
            require(KeyCheckStatus.EMPTY.label().equals("ключ не введён"),
                    "неверный текст пустого ключа");
        });

        check("Поиск модов: .jar и .jar.sample без подпапок", () -> {
            Path finderDir = Files.createDirectories(tempDir.resolve("finder"));
            Path one = Files.writeString(finderDir.resolve("one.jar"), "x");
            Path sample = Files.writeString(finderDir.resolve("two.jar.sample"), "x");
            Files.writeString(finderDir.resolve("note.txt"), "x");
            Files.writeString(finderDir.resolve("skip.jar.sample.txt"), "x");
            Path sub = Files.createDirectories(finderDir.resolve("sub"));
            Files.writeString(sub.resolve("two.jar"), "x");

            require(ModFinder.find(finderDir).equals(List.of(one, sample)),
                    "папка должна давать one.jar и two.jar.sample: "
                            + ModFinder.find(finderDir));
            require(ModFinder.find(one).equals(List.of(one)),
                    "одиночный jar должен возвращаться как есть");
            require(ModFinder.find(sample).equals(List.of(sample)),
                    "одиночный .jar.sample должен возвращаться как есть");
            require(ModFinder.isModFileName("MOD.JAR.SAMPLE"),
                    "расширение .jar.sample должно быть регистронезависимым");
            require(!ModFinder.isModFileName("mod.jar.sample.txt"),
                    "файл с хвостом .txt не должен считаться образцом");
            require(ModFinder.find(Files.createDirectories(
                            tempDir.resolve("finder-empty"))).isEmpty(),
                    "пустая папка должна давать пустой список");

            boolean thrown = false;
            try {
                ModFinder.find(tempDir.resolve("finder-missing"));
            } catch (IOException e) {
                thrown = true;
            }
            require(thrown, "несуществующий путь должен давать ошибку");
        });

        check("Таблица: колонки и порядок по умолчанию", () -> {
            ModTableModel model = new ModTableModel();
            model.setReports(List.of(
                    tableReport("clean.jar", 0, false, true),
                    tableReport("unknown.jar", 0, false, false),
                    tableReport("stealer.jar", 12, false, false),
                    tableReport("loader.jar", 15, false, false),
                    tableReport("broken.jar", 0, true, false)
            ));

            require(model.getColumnName(0).equals("Мод")
                            && model.getColumnName(1).equals("Результат")
                            && model.getColumnName(2).equals("Очки")
                            && model.getColumnName(3).equals("Modrinth")
                            && model.getColumnName(4).equals("CurseForge"),
                    "неверные названия колонок таблицы");

            var sorter = ModTableModel.createSorter(model);
            sorter.sort();

            ModReport first = model.reportAt(sorter.convertRowIndexToModel(0));
            ModReport second = model.reportAt(sorter.convertRowIndexToModel(1));
            ModReport third = model.reportAt(sorter.convertRowIndexToModel(2));
            ModReport fourth = model.reportAt(sorter.convertRowIndexToModel(3));
            ModReport fifth = model.reportAt(sorter.convertRowIndexToModel(4));

            require(first.scan().verdict() == Verdict.SUSPICIOUS
                            && first.scan().points() == 15,
                    "первым должен идти ПОДОЗРИТЕЛЬНО с 15 очками");
            require(second.scan().verdict() == Verdict.SUSPICIOUS
                            && second.scan().points() == 12,
                    "среди подозрительных очки должны идти по убыванию");
            require(third.scan().verdict() == Verdict.UNKNOWN,
                    "после подозрительных должно идти НЕИЗВЕСТНО");
            require(fourth.scan().verdict() == Verdict.OK,
                    "после неизвестных должно идти ОК");
            require(fifth.scan().verdict() == Verdict.ERROR,
                    "последней должна идти ОШИБКА");
        });

        Map<String, byte[]> allRuleEntries = new LinkedHashMap<>();
        allRuleEntries.put("assets/config.json",
                utf8("discord.com/api/webhooks\napi.telegram.org"));
        allRuleEntries.put("data/app.properties",
                utf8("launcher_accounts"));
        allRuleEntries.put("data/settings.cfg",
                utf8("wallet.dat\ndev/neko\npastebin.com"));
        allRuleEntries.put("testmods/rules/BrowserClass.class",
                classWithStrings("testmods/rules/BrowserClass",
                        "Cookies", "Local Storage"));
        allRuleEntries.put("notes.txt",
                utf8("discord.com/api/webhooks"));
        Path allRulesJar = writeJar(tempDir, "all_rules.jar", allRuleEntries);

        check("Сканер: правила 1-8 и связка КРАЖА", () -> {
            ModScanResult result = scanner.scan(allRulesJar);
            assertPointsRulesAndLinks(result, 33,
                    Set.of(1, 2, 3, 4, 5, 6, 7, 8), Set.of("КРАЖА"));
            require(link(result, "КРАЖА").evidence().contains("1 + 3"),
                    "связка должна использовать первые подходящие правила 1 и 3");
        });

        check("Сканер: Cookies в .json не даёт правило 5", () -> {
            Path jar = writeJar(tempDir, "cookies_json.jar", Map.of(
                    "assets/refmap.json",
                    utf8("{\"cookies\":\"minecraft:method\"}")
            ));

            ModScanResult result = scanner.scan(jar);
            assertPointsAndRules(result, 0, Set.of());
        });

        check("Сканер: правило 4 - Local Storage только в .class", () -> {
            Path textJar = writeJar(tempDir, "browser_text.jar", Map.of(
                    "assets/fancymenu/lang/en_us.json",
                    utf8("{\"menu.local_storage\":\"Local Storage\"}"),
                    "data/browser.properties", utf8("browser=leveldb"),
                    "data/encoded.txt", utf8(Base64.getEncoder().encodeToString(
                            "Local Storage".getBytes(StandardCharsets.UTF_8))),
                    "notes.txt", utf8("Login Data")
            ));

            ModScanResult textResult = scanner.scan(textJar);
            assertPointsAndRules(textResult, 0, Set.of());
            require(!textResult.hasRule(4),
                    "правило 4 не должно срабатывать на .json/.properties/.txt");

            Path classJar = writeJar(tempDir, "browser_class.jar", Map.of(
                    "testmods/browser/BrowserData.class",
                    classWithString("testmods/browser/BrowserData", "Local Storage")
            ));
            assertPointsAndRules(scanner.scan(classJar), 4, Set.of(4));
        });

        check("Сканер: все сигнатуры браузера и кодировки только в .class", () -> {
            for (String signature : List.of("local storage", "leveldb", "login data")) {
                String base64 = Base64.getEncoder().encodeToString(utf8(signature));
                String hex = java.util.HexFormat.of().formatHex(utf8(signature));
                String reversed = new StringBuilder(signature).reverse().toString();
                Path textJar = writeJar(tempDir, "browser_encodings_text.jar", Map.of(
                        "assets/fancymenu/lang/en_us.json", utf8(signature),
                        "data/browser.cfg", utf8(base64 + "\n" + hex + "\n" + reversed)
                ));
                ModScanResult textResult = scanner.scan(textJar);
                assertPointsAndRules(textResult, 0, Set.of());
                require(!textResult.hasEvidenceRule(4),
                        "ресурсы не должны давать улику правила 4: " + signature);

                Path plainJar = writeJar(tempDir, "browser_signature_class.jar", Map.of(
                        "testmods/browser/BrowserData.class",
                        classWithString("testmods/browser/BrowserData", signature)
                ));
                assertPointsAndRules(scanner.scan(plainJar), 4, Set.of(4));
                Path encodedJar = writeJar(tempDir, "browser_encodings_class.jar", Map.of(
                        "testmods/browser/BrowserData.class",
                        classWithStrings("testmods/browser/BrowserData", hex, reversed)
                ));
                ModScanResult encodedResult = scanner.scan(encodedJar);
                assertPointsAndRules(encodedResult, 7, Set.of(9));
                require(encodedResult.hasEvidenceRule(4),
                        "скрытая сигнатура в .class должна сохранять улику: " + signature);
            }
        });

        Path unknownExtension = writeJar(tempDir, "unknown_extension.jar", Map.of(
                "assets/data.bin", utf8("api.telegram.org")
        ));

        check("Сканер: файл неизвестного типа не сканируется как текст", () -> {
            ModScanResult result = scanner.scan(unknownExtension);
            assertPointsAndRules(result, 0, Set.of());
        });

        Map<String, byte[]> executables = new LinkedHashMap<>();
        executables.put("bin/tool.exe", utf8("not a real executable"));
        executables.put("bin/run.bat", utf8("echo hello"));
        Path executableJar = writeJar(tempDir, "executables.jar", executables);

        check("Сканер: правило 17 считается один раз", () -> {
            ModScanResult result = scanner.scan(executableJar);
            assertPointsAndRules(result, 4, Set.of(17));
            require(result.findings().size() == 1,
                    "два исполняемых файла должны дать только одну находку");
        });

        byte[] level3 = zipBytes(Map.of("too_deep.txt", utf8("wallet.dat")));

        Map<String, byte[]> level2Entries = new LinkedHashMap<>();
        level2Entries.put("deep.txt",
                utf8("https://discord.com/api/webhooks/42/nested"));
        level2Entries.put("payload.exe", utf8("not a real executable"));
        level2Entries.put("level3.jar", level3);
        byte[] level2 = zipBytes(level2Entries);

        byte[] level1 = zipBytes(Map.of("level2.jar", level2));
        Path nestedJar = writeJar(tempDir, "nested.jar", Map.of("level1.jar", level1));

        check("Сканер: вложенные jar до двух уровней", () -> {
            ModScanResult result = scanner.scan(nestedJar);
            assertPointsAndRules(result, 14, Set.of(1, 17, 24));

            require(finding(result, 1).location()
                            .contains("level1.jar!/level2.jar!/deep.txt"),
                    "не показан полный путь вложенного файла: "
                            + finding(result, 1).location());
            require(finding(result, 17).location()
                            .contains("level1.jar!/level2.jar!/payload.exe"),
                    "для вложенного exe не показан путь: "
                            + finding(result, 17).location());
            require(!result.hasRule(6),
                    "файл третьего уровня не должен проверяться");
        });

        check("Сканер: вложенный .jar.sample", () -> {
            byte[] inner = zipBytes(Map.of(
                    "inside.txt", utf8(HIDDEN_WEBHOOK)
            ));
            Path outer = writeJar(tempDir, "nested_sample_holder.jar",
                    Map.of("inner.jar.sample", inner));

            ModScanResult result = scanner.scan(outer);
            assertPointsAndRules(result, 10, Set.of(1, 24));
            require(finding(result, 1).location()
                            .contains("inner.jar.sample!/inside.txt"),
                    "не показан полный путь вложенного .jar.sample: "
                            + finding(result, 1).location());
        });

        check("Связка: Telegram в основном коде и Local Storage во вложенном jar", () -> {
            byte[] inner = zipBytes(Map.of(
                    "testmods/link/InnerStorage.class",
                    classWithString("testmods/link/InnerStorage", "Local Storage")
            ));
            Path jar = writeJar(tempDir, "nested_link_isolation.jar", Map.of(
                    "testmods/link/Main.class",
                    classWithString("testmods/link/Main", "api.telegram.org"),
                    "libs/kotlin-compiler.jar", inner
            ));

            ModScanResult result = scanner.scan(jar);
            assertPointsAndRules(result, 7, Set.of(2, 4));
            require(result.links().isEmpty(),
                    "нельзя складывать Telegram из основного кода с данными "
                            + "из вложенного jar: " + result.links());
        });

        check("Связка: обе части в одном вложенном jar и места в отчёте", () -> {
            byte[] inner = zipBytes(Map.of(
                    "testmods/link/InnerData.class",
                    classWithStrings("testmods/link/InnerData",
                            "api.telegram.org", "Local Storage")
            ));
            Path jar = writeJar(tempDir, "nested_link_same.jar", Map.of(
                    "libs/kotlin-compiler.jar", inner
            ));

            ModScanResult result = scanner.scan(jar);
            assertPointsRulesAndLinks(result, 11, Set.of(2, 4), Set.of("КРАЖА"));
            LinkFinding theft = link(result, "КРАЖА");
            require(theft.firstLocation().contains(
                            "kotlin-compiler.jar!/testmods/link/InnerData.class"),
                    "в связке не показано место первой части: "
                            + theft.firstLocation());
            require(theft.secondLocation().contains(
                            "kotlin-compiler.jar!/testmods/link/InnerData.class"),
                    "в связке не показано место второй части: "
                            + theft.secondLocation());

            String report = ReportPrinter.format(List.of(new ModReport(result,
                    new OnlineCheckResult("0".repeat(40),
                            OnlineStatus.SKIPPED, OnlineStatus.SKIPPED))));
            require(report.contains("часть 1:")
                            && report.contains("часть 2:")
                            && report.contains("kotlin-compiler.jar"),
                    "в отчёте не показаны места обеих частей связки");
        });

        check("Сканер: правило 24 - jar в assets/data/resources и корне", () -> {
            byte[] safeInner = zipBytes(Map.of("safe.txt", utf8("hello")));
            List<String> locations = List.of(
                    "assets/hidden.jar", "data/hidden.jar",
                    "resources/hidden.jar", "hidden.jar");
            int index = 0;
            for (String location : locations) {
                Path jar = writeJar(tempDir, "hidden_place_" + index + ".jar",
                        Map.of(location, safeInner));
                ModScanResult result = scanner.scan(jar);
                assertPointsAndRules(result, 6, Set.of(24));
                require(finding(result, 24).location().contains(location),
                        "правило 24 не показало путь " + location);
                index++;
            }
        });

        check("Сканер: имя-улика у скрытого jar не даёт ОПАСНО", () -> {
            byte[] inner = zipBytes(Map.of(
                    "testmods/names/StealOnly.class",
                    classWithNamedMethods("testmods/names/StealOnly", "stealData")));
            Path jar = writeJar(tempDir, "hidden_named_rat.jar",
                    Map.of("assets/hidden.jar", inner));
            ModScanResult result = scanner.scan(jar);
            assertPointsRulesAndLinks(result, 6, Set.of(24, 25), Set.of());
            require(result.verdict() == Verdict.UNKNOWN,
                    "имя-улика не должна давать ОПАСНО");
        });

        check("Сканер: правило 24 не трогает META-INF/jars и jarjar", () -> {
            byte[] safeInner = zipBytes(Map.of("safe.txt", utf8("hello")));
            Path jar = writeJar(tempDir, "legal_nested.jar", Map.of(
                    "META-INF/jars/legal.jar", safeInner,
                    "META-INF/jarjar/legal2.jar", safeInner));
            ModScanResult result = scanner.scan(jar);
            assertPointsAndRules(result, 0, Set.of());
        });

        check("Отчёт: пояснение о вложенных библиотеках не скрывает находки", () -> {
            byte[] library = zipBytes(Map.of(
                    "library/http/HttpClient.class",
                    classWithString("library/http/HttpClient", "cookies")));
            Path jar = writeJar(tempDir, "http_library.jar", Map.of(
                    "META-INF/jars/http.jar", library));
            ModScanResult result = scanner.scan(jar);
            assertPointsAndRules(result, 1, Set.of(5));
            String report = renderReport(result, new OnlineCheckResult(
                    "0".repeat(40), OnlineStatus.SKIPPED, OnlineStatus.SKIPPED));
            require(report.contains("Находок во вложенных JAR: 1."),
                    "нет числа находок из вложенного JAR");
            require(report.contains("встроенные библиотеки тоже проверяются")
                            && report.contains("[5] Cookies: +1")
                            && report.contains("META-INF/jars/http.jar!/"),
                    "пояснение не должно скрывать правило или место находки");
        });

        check("Сканер: правило 25 - только заметка 0 очков", () -> {
            Path jar = writeJar(tempDir, "name_evidence.jar", Map.of(
                    "testmods/names/NameEvidence.class",
                    classWithNamedMethods("testmods/names/NameEvidence",
                            "value", "stealTelegramData")));
            ModScanResult result = scanner.scan(jar);
            assertPointsAndRules(result, 0, Set.of(25));
            require(finding(result, 25).points() == 0,
                    "правило 25 должно давать 0 очков");
            require(finding(result, 25).title().contains("заметка"),
                    "правило 25 должно быть помечено как заметка");
            require(finding(result, 25).location().contains("stealTelegramData"),
                    "правило 25 не показало метод stealTelegramData");

            Path safe = writeJar(tempDir, "name_generator.jar", Map.of(
                    "testmods/names/Generator.class",
                    classWithNamedMethods("testmods/names/Generator", "operate")));
            assertPointsAndRules(scanner.scan(safe), 0, Set.of());

            Path c2s = writeJar(tempDir, "name_c2s.jar", Map.of(
                    "testmods/names/C2SNetwork.class",
                    classWithNamedMethods("testmods/names/C2SNetwork", "write")));
            assertPointsAndRules(scanner.scan(c2s), 0, Set.of());
        });

        check("Сканер: правило 26 - только 3+ разных команды", () -> {
            Path single = writeJar(tempDir, "rat_command_one.jar", Map.of(
                    "testmods/commands/Commands.class",
                    classWithStrings("testmods/commands/Commands", "PASSWORD_STEAL")));
            assertPointsAndRules(scanner.scan(single), 0, Set.of());

            Path two = writeJar(tempDir, "rat_command_two.jar", Map.of(
                    "testmods/commands/Commands.class",
                    classWithStrings("testmods/commands/Commands",
                            "PASSWORD_STEAL", "DISCORD_STEAL")));
            assertPointsAndRules(scanner.scan(two), 0, Set.of());

            Path keys = writeJar(tempDir, "rat_command_keys.jar", Map.of(
                    "testmods/commands/Commands.class",
                    classWithStrings("testmods/commands/Commands",
                            "KEY_TYPE", "MOUSE_CLICK", "PASSWORD_STEAL")));
            assertPointsAndRules(scanner.scan(keys), 0, Set.of());

            Path three = writeJar(tempDir, "rat_command_three.jar", Map.of(
                    "testmods/commands/Commands.class",
                    classWithStrings("testmods/commands/Commands",
                            "PASSWORD_STEAL", "DISCORD_STEAL", "STREAM_START")));
            ModScanResult threeResult = scanner.scan(three);
            assertPointsAndRules(threeResult, 6, Set.of(26));
            require(finding(threeResult, 26).evidence().contains("3+ команд"),
                    "в правиле 26 нет отметки 3+ команд");

            Path pair = writeJar(tempDir, "rat_file_pair.jar", Map.of(
                    "testmods/commands/Commands.class",
                    classWithStrings("testmods/commands/Commands",
                            "FILE_UPLOAD", "FILE_DOWNLOAD")));
            assertPointsAndRules(scanner.scan(pair), 0, Set.of());

            Path pairPlus = writeJar(tempDir, "rat_file_pair_plus.jar", Map.of(
                    "testmods/commands/Commands.class",
                    classWithStrings("testmods/commands/Commands",
                            "FILE_UPLOAD", "FILE_DOWNLOAD", "PASSWORD_STEAL",
                            "STREAM_START")));
            assertPointsAndRules(scanner.scan(pairPlus), 6, Set.of(26));
        });

        check("Сканер: правило 27 - реальные API, без Camera", () -> {
            record WatchCall(String owner, String name, String descriptor,
                             boolean isInterface, int points) {
            }
            List<WatchCall> calls = List.of(
                    new WatchCall("java/awt/Robot", "createScreenCapture",
                            "(Ljava/awt/Rectangle;)Ljava/awt/image/BufferedImage;", false, 4),
                    new WatchCall("javax/sound/sampled/TargetDataLine", "open",
                            "(Ljavax/sound/sampled/AudioFormat;)V", true, 1),
                    new WatchCall("com/github/sarxos/webcam/Webcam", "getDefault",
                            "()Lcom/github/sarxos/webcam/Webcam;", false, 4),
                    new WatchCall("org/bytedeco/javacv/FrameGrabber", "start",
                            "()V", false, 4),
                    new WatchCall("org/openimaj/image/VideoCapture", "grab",
                            "()V", false, 4),
                    new WatchCall("org/opencv/videoio/VideoCapture", "read",
                            "()Z", false, 4),
                    new WatchCall("org/directshow/VideoCapture", "open",
                            "()V", false, 4),
                    new WatchCall("org/bytedeco/avfoundation/AVFoundationFrameGrabber", "start",
                            "()V", false, 4),
                    new WatchCall("com/example/MyWebcam", "open",
                            "()V", false, 4),
                    new WatchCall("net/minecraft/client/Camera", "setup",
                            "()V", false, 0),
                    new WatchCall("net/neoforged/neoforge/client/Camera", "setup",
                            "()V", false, 0),
                    new WatchCall("com/example/Camera", "setup",
                            "()V", false, 0)
            );
            int index = 0;
            for (WatchCall call : calls) {
                Path jar = writeJar(tempDir, "watch_call_" + index + ".jar", Map.of(
                        "testmods/watch/WatchCalls.class",
                        classWithCallAndString("testmods/watch/WatchCalls",
                                call.owner(), call.name(), call.descriptor(),
                                call.isInterface(), "safe")));
                ModScanResult result = scanner.scan(jar);
                assertPointsAndRules(result, call.points(),
                        call.points() == 0 ? Set.of() : Set.of(27));
                if (call.points() > 0) {
                    require(finding(result, 27).evidence().contains(call.name()),
                            "правило 27 не показало " + call.name());
                }
                index++;
            }
        });

        check("Сканер: скрытый jar + экран даёт ОПАСНО, микрофон нет", () -> {
            byte[] screen = zipBytes(Map.of(
                    "testmods/watch/ScreenOnly.class",
                    classWithCallAndString("testmods/watch/ScreenOnly",
                            "java/awt/Robot", "createScreenCapture",
                            "(Ljava/awt/Rectangle;)Ljava/awt/image/BufferedImage;",
                            false, "safe")));
            Path screenJar = writeJar(tempDir, "hidden_screen_rat.jar",
                    Map.of("assets/hidden.jar", screen));
            ModScanResult screenResult = scanner.scan(screenJar);
            assertPointsRulesAndLinks(screenResult, 20,
                    Set.of(24, 27), Set.of("КРИТИЧЕСКАЯ"));
            require(screenResult.verdict() == Verdict.DANGEROUS,
                    "скрытый jar + захват экрана должен быть ОПАСНО");

            byte[] mic = zipBytes(Map.of(
                    "testmods/watch/MicOnly.class",
                    classWithCallAndString("testmods/watch/MicOnly",
                            "javax/sound/sampled/TargetDataLine", "open",
                            "(Ljavax/sound/sampled/AudioFormat;)V", true, "safe")));
            Path micJar = writeJar(tempDir, "hidden_mic.jar",
                    Map.of("assets/hidden.jar", mic));
            ModScanResult micResult = scanner.scan(micJar);
            assertPointsRulesAndLinks(micResult, 7, Set.of(24, 27), Set.of());
            require(micResult.verdict() == Verdict.UNKNOWN,
                    "микрофон сам по себе не должен давать ОПАСНО");
        });

        check("Сканер: скрытый jar + правило 26 или 28 дают ОПАСНО", () -> {
            byte[] commands = zipBytes(Map.of(
                    "testmods/commands/Commands.class",
                    classWithStrings("testmods/commands/Commands",
                            "STREAM_START", "STREAM_STOP", "MIC_START")));
            Path commandsJar = writeJar(tempDir, "hidden_commands_rat.jar",
                    Map.of("assets/hidden.jar", commands));
            ModScanResult commandsResult = scanner.scan(commandsJar);
            assertPointsRulesAndLinks(commandsResult, 22,
                    Set.of(24, 26), Set.of("КРИТИЧЕСКАЯ"));
            require(commandsResult.verdict() == Verdict.DANGEROUS,
                    "скрытый jar + 3 команды должен быть ОПАСНО");

            byte[] tokens = zipBytes(Map.of(
                    "testmods/discord/TokenSignals.class",
                    classWithStrings("testmods/discord/TokenSignals",
                            ".ldb", "mfa." + "a".repeat(30))));
            Path tokensJar = writeJar(tempDir, "hidden_tokens_rat.jar",
                    Map.of("assets/hidden.jar", tokens));
            ModScanResult tokensResult = scanner.scan(tokensJar);
            assertPointsRulesAndLinks(tokensResult, 21,
                    Set.of(24, 28), Set.of("КРИТИЧЕСКАЯ"));
            require(tokensResult.verdict() == Verdict.DANGEROUS,
                    "скрытый jar + кража токена должна быть ОПАСНО");
        });

        check("Сканер: правило 28 - путь Discord и токен", () -> {
            String token = "mfa." + "a".repeat(30);
            List<String> markers = List.of("Local Storage", "leveldb", ".ldb");
            int index = 0;
            for (String marker : markers) {
                Path jar = writeJar(tempDir, "discord_token_" + index + ".jar", Map.of(
                        "testmods/discord/TokenSignals.class",
                        classWithStrings("testmods/discord/TokenSignals", marker, token)));
                ModScanResult result = scanner.scan(jar);
                if ("Local Storage".equals(marker) || "leveldb".equals(marker)) {
                    assertPointsAndRules(result, 9, Set.of(4, 28));
                } else {
                    assertPointsAndRules(result, 5, Set.of(28));
                }
                require(finding(result, 28).evidence().contains("шаблон токена"),
                        "правило 28 не показало шаблон токена");
                index++;
            }

            Path regexSource = writeJar(tempDir, "discord_token_regex.jar", Map.of(
                    "testmods/discord/TokenSignals.class",
                    classWithStrings("testmods/discord/TokenSignals",
                            ".ldb", "[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}|mfa\\.[\\w-]{84}")));
            assertPointsAndRules(scanner.scan(regexSource), 5, Set.of(28));
        });

        check("Сканер: правило 29 - только туннели и публичные IP", () -> {
            Path portmap = writeJar(tempDir, "c2_portmap.jar", Map.of(
                    "testmods/net/SocketEndpoint.class",
                    classWithSocket("testmods/net/SocketEndpoint",
                            "example.portmap.host", 61233)));
            ModScanResult c2 = scanner.scan(portmap);
            assertPointsAndRules(c2, 5, Set.of(14, 29));
            require(finding(c2, 29).evidence().contains("example.portmap.host"),
                    "правило 29 не показало хост");

            List<String> ordinary = List.of(
                    "mojang.com", "api.cfwidget.com", "api.mclo.gs", "example.com");
            int index = 0;
            for (String host : ordinary) {
                Path jar = writeJar(tempDir, "c2_ordinary_" + index + ".jar", Map.of(
                        "testmods/net/KnownEndpoint.class",
                        classWithSocket("testmods/net/KnownEndpoint", host, 443)));
                assertPointsAndRules(scanner.scan(jar), 2, Set.of(14));
                index++;
            }

            List<String> privateIps = List.of(
                    "10.1.2.3", "172.16.5.4", "172.31.0.1", "192.168.1.10",
                    "169.254.1.1", "127.0.0.1", "100.64.0.1");
            index = 0;
            for (String host : privateIps) {
                Path jar = writeJar(tempDir, "c2_private_" + index + ".jar", Map.of(
                        "testmods/net/PrivateEndpoint.class",
                        classWithSocket("testmods/net/PrivateEndpoint", host, 25565)));
                assertPointsAndRules(scanner.scan(jar), 2, Set.of(14));
                index++;
            }

            Path publicIp = writeJar(tempDir, "c2_public_ip.jar", Map.of(
                    "testmods/net/PublicEndpoint.class",
                    classWithSocket("testmods/net/PublicEndpoint", "8.8.8.8", 443)));
            assertPointsAndRules(scanner.scan(publicIp), 5, Set.of(14, 29));

            List<String> tunnels = List.of(
                    "abc.ngrok.io", "a.duckdns.org", "x.loca.lt",
                    "x.trycloudflare.com", "x.serveo.net", "x.no-ip.org");
            index = 0;
            for (String host : tunnels) {
                Path jar = writeJar(tempDir, "c2_tunnel_" + index + ".jar", Map.of(
                        "testmods/net/TunnelEndpoint.class",
                        classWithSocket("testmods/net/TunnelEndpoint", host, 443)));
                assertPointsAndRules(scanner.scan(jar), 5, Set.of(14, 29));
                index++;
            }

            Path url = writeJar(tempDir, "c2_url.jar", Map.of(
                    "testmods/net/UrlEndpoint.class",
                    classWithUrl("testmods/net/UrlEndpoint",
                            "https://abc.ngrok.io/api")));
            assertPointsAndRules(scanner.scan(url), 3, Set.of(29));

            Path knownUrl = writeJar(tempDir, "c2_known_url.jar", Map.of(
                    "testmods/net/KnownUrl.class",
                    classWithUrl("testmods/net/KnownUrl",
                            "https://api.cfwidget.com/mod")));
            assertPointsAndRules(scanner.scan(knownUrl), 0, Set.of());
        });

        check("Отчёт: ссылки, домены, IP и токены", () -> {
            Path jar = writeJar(tempDir, "entities.jar", Map.of(
                    "testmods/report/Entities.class",
                    classWithStrings("testmods/report/Entities",
                            "https://discord.com/api/webhooks/123456789012345678/abcdef",
                            "https://api.cfwidget.com/mod",
                            "8.8.8.8",
                            "mfa." + "a".repeat(30))));
            ModScanResult result = scanner.scan(jar);
            assertPointsAndRules(result, 4, Set.of(1));
            require(result.foundEntities().stream()
                            .anyMatch(entity -> entity.kind().equals("вебхук Discord")),
                    "не найден вебхук Discord");
            require(result.foundEntities().stream()
                            .anyMatch(entity -> entity.kind().equals("домен")
                                    && entity.value().equals("api.cfwidget.com")),
                    "не найден обычный домен");
            require(result.foundEntities().stream()
                            .anyMatch(entity -> entity.kind().equals("IP")
                                    && entity.value().equals("8.8.8.8")),
                    "не найден IP-адрес");
            require(result.foundEntities().stream()
                            .anyMatch(entity -> entity.kind().equals("токен Discord")),
                    "не найден токен Discord");

            String report = renderReport(result, new OnlineCheckResult(
                    "0".repeat(40), OnlineStatus.SKIPPED, OnlineStatus.SKIPPED));
            require(report.contains("Ссылки, домены, IP и токены:"),
                    "в отчёте нет раздела ссылок");
            require(report.contains("вебхук Discord:")
                            && report.contains("домен: api.cfwidget.com")
                            && report.contains("IP: 8.8.8.8")
                            && report.contains("токен Discord:"),
                    "в отчёте не все найденные сущности");
        });

        check("Сканер: fake_visual_rat остаётся ОПАСНО", () -> {
            ModScanResult result = scanner.scan(
                    extraDir.resolve("fake_visual_rat.jar"));
            assertPointsRulesAndLinks(result, 21,
                    Set.of(14, 24, 25, 29), Set.of("КРИТИЧЕСКАЯ"));
            require(result.verdict() == Verdict.DANGEROUS,
                    "fake_visual_rat должен быть ОПАСНО, получен "
                            + result.verdict().label());

            LinkFinding critical = link(result, "КРИТИЧЕСКАЯ");
            require(critical.points() == 10,
                    "критическая связка должна давать +10");
            require(critical.firstLocation().contains("assets/fake/libs.jar")
                            && critical.secondLocation().contains("assets/fake/libs.jar"),
                    "в критической связке нет мест обеих частей: "
                            + critical.firstLocation() + " / " + critical.secondLocation());
            require(result.evidenceLocations(24).stream()
                            .anyMatch(location -> location.scope()
                                    .equals("assets/fake/libs.jar")),
                    "правило 24 должно относиться к области спрятанного jar");

            String report = renderReport(result, new OnlineCheckResult(
                    "0".repeat(40), OnlineStatus.SKIPPED, OnlineStatus.SKIPPED));
            require(report.contains("!!! КРИТИЧЕСКАЯ СВЯЗКА (RAT): +10 !!!"),
                    "в отчёте нет крупной критической связки");
            require(report.contains("часть 1:")
                            && report.contains("часть 2:")
                            && report.contains("assets/fake/libs.jar"),
                    "в отчёте нет мест обеих частей критической связки");
            require(report.contains("Ссылки, домены, IP и токены:")
                            && report.contains("домен: example.portmap.host"),
                    "в отчёте нет найденного домена");
            require(report.contains("ОПАСНО: 1"),
                    "в итогах отчёта нет ОПАСНО");
        });

        check("Вердикт: подтверждение сайта не даёт ОПАСНО", () -> {
            ModScanResult result = scanner.scan(
                    extraDir.resolve("fake_visual_rat.jar"));
            require(result.verdict() == Verdict.DANGEROUS,
                    "до подтверждения fake_visual_rat должен быть ОПАСНО");
            result.markOnlineConfirmed();
            require(result.verdict() == Verdict.SUSPICIOUS,
                    "подтверждённый сайт не может быть ОПАСНО: "
                            + result.verdict().label());
            String report = renderReport(result, new OnlineCheckResult(
                    "0".repeat(40), OnlineStatus.CONFIRMED, OnlineStatus.SKIPPED));
            require(report.contains("вердикт ограничен ПОДОЗРИТЕЛЬНО"),
                    "в отчёте нет пояснения об ограничении вердикта");
        });

        check("Вердикт: ручное доверие не отменяет ОПАСНО, ошибка важнее", () -> {
            ModScanResult result = scanner.scan(
                    extraDir.resolve("fake_visual_rat.jar"));
            result.markManuallyTrusted("тест", "тест");
            require(result.verdict() == Verdict.DANGEROUS,
                    "ручное доверие не должно отменять ОПАСНО");
            result.markError("тестовая ошибка");
            require(result.verdict() == Verdict.ERROR,
                    "ОШИБКА должна быть важнее ОПАСНО");
        });

        check("Таблица: ОПАСНО идёт выше ПОДОЗРИТЕЛЬНО", () -> {
            ModTableModel model = new ModTableModel();
            model.setReports(List.of(
                    tableReport("danger.jar", 10, false, false, true),
                    tableReport("suspicious.jar", 12, false, false)));
            var sorter = ModTableModel.createSorter(model);
            sorter.sort();
            ModReport first = model.reportAt(sorter.convertRowIndexToModel(0));
            require(first.scan().verdict() == Verdict.DANGEROUS,
                    "ОПАСНО должно сортироваться выше ПОДОЗРИТЕЛЬНО");
        });
    }

    /** Байткод числового XOR и обработки байтов: только генерируется, не загружается. */
    private static byte[] classWithBufferXor(boolean mutateBytes) {
        var writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "testmods/hash/BufferHash",
                null, "java/lang/Object", null);
        var method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "process", "()[B", null, null);
        method.visitCode();
        method.visitInsn(Opcodes.ICONST_4);
        method.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE);
        method.visitVarInsn(Opcodes.ASTORE, 0);
        method.visitInsn(Opcodes.ICONST_0);
        method.visitVarInsn(Opcodes.ISTORE, 1);
        method.visitInsn(Opcodes.ICONST_0);
        method.visitVarInsn(Opcodes.ISTORE, 2);
        var loop = new org.objectweb.asm.Label();
        var done = new org.objectweb.asm.Label();
        method.visitLabel(loop);
        method.visitVarInsn(Opcodes.ILOAD, 1);
        method.visitInsn(Opcodes.ICONST_4);
        method.visitJumpInsn(Opcodes.IF_ICMPGE, done);
        if (!mutateBytes) {
            method.visitVarInsn(Opcodes.ILOAD, 2);
            method.visitVarInsn(Opcodes.ILOAD, 1);
            method.visitInsn(Opcodes.IXOR);
            method.visitVarInsn(Opcodes.ISTORE, 2);
        }
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitVarInsn(Opcodes.ILOAD, 1);
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitVarInsn(Opcodes.ILOAD, 1);
        method.visitInsn(Opcodes.BALOAD);
        if (mutateBytes) {
            method.visitIntInsn(Opcodes.BIPUSH, 0x5A);
            method.visitInsn(Opcodes.IXOR);
            method.visitInsn(Opcodes.I2B);
        }
        method.visitInsn(Opcodes.BASTORE);
        method.visitIincInsn(1, 1);
        method.visitJumpInsn(Opcodes.GOTO, loop);
        method.visitLabel(done);
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(0, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static void assertPointsAndRules(ModScanResult result, int expectedPoints,
                                             Set<Integer> expectedRules) {
        assertPointsRulesAndLinks(result, expectedPoints, expectedRules, Set.of());
    }

    private static void assertPointsRulesAndLinks(ModScanResult result, int expectedPoints,
                                                  Set<Integer> expectedRules,
                                                  Set<String> expectedLinks) {
        require(!result.hasError(), "неожиданная ошибка: " + result.error());

        Set<Integer> actualRules = new LinkedHashSet<>();
        for (Finding finding : result.findings()) {
            actualRules.add(finding.rule());
        }
        Set<String> actualLinks = new LinkedHashSet<>();
        for (LinkFinding link : result.links()) {
            actualLinks.add(link.name());
        }

        require(result.points() == expectedPoints,
                "ожидалось очков " + expectedPoints + ", получено " + result.points()
                        + "; правила: " + actualRules + "; связки: " + actualLinks);
        require(actualRules.equals(expectedRules),
                "ожидались правила " + expectedRules + ", получены " + actualRules);
        require(actualLinks.equals(expectedLinks),
                "ожидались связки " + expectedLinks + ", получены " + actualLinks);
    }

    private static void assertFinalPoints(ScanService scanner, Path file, int expectedPoints) {
        ModScanResult result = scanner.scan(file);
        require(!result.hasError(),
                file.getFileName() + ": неожиданная ошибка: " + result.error());
        require(result.points() == expectedPoints,
                file.getFileName() + ": ожидалось очков " + expectedPoints
                        + ", получено " + result.points()
                        + "; находки: " + result.findings()
                        + "; связки: " + result.links());
    }

    private static void assertVerdict(ScanService scanner, Path file, Verdict expectedVerdict) {
        ModScanResult result = scanner.scan(file);
        require(result.verdict() == expectedVerdict,
                file.getFileName() + ": ожидался вердикт " + expectedVerdict.label()
                        + ", получен " + result.verdict().label()
                        + " (" + result.points() + " очков)"
                        + (result.hasError() ? ", ошибка: " + result.error() : ""));
    }

    private static ModReport tableReport(String name, int points,
                                         boolean error, boolean confirmed) {
        return tableReport(name, points, error, confirmed, false);
    }

    private static ModReport tableReport(String name, int points,
                                         boolean error, boolean confirmed,
                                         boolean dangerous) {
        ModScanResult scan = new ModScanResult(Path.of(name));
        if (error) {
            scan.markError("файл битый или не мод");
        }
        if (points > 0) {
            scan.addFinding(new Finding(7, "Тест", points, "test", "test"));
        }
        if (confirmed) {
            scan.markOnlineConfirmed();
        }
        if (dangerous) {
            scan.markDangerous();
        }
        OnlineCheckResult online = new OnlineCheckResult(
                "0".repeat(40), OnlineStatus.SKIPPED, OnlineStatus.SKIPPED);
        return new ModReport(scan, online);
    }

    private static Finding finding(ModScanResult result, int rule) {
        return result.findings().stream()
                .filter(finding -> finding.rule() == rule)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "нет находки правила " + rule + " в " + result.name()));
    }

    private static LinkFinding link(ModScanResult result, String name) {
        return result.links().stream()
                .filter(link -> link.name().equals(name))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "нет связки " + name + " в " + result.name()));
    }

    private static byte[] classWithNamedMethods(String className, String... methodNames) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, className, null,
                "java/lang/Object", null);

        for (String methodName : methodNames) {
            MethodVisitor method = writer.visitMethod(
                    Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                    methodName, "()V", null, null);
            method.visitCode();
            method.visitInsn(Opcodes.RETURN);
            method.visitMaxs(0, 0);
            method.visitEnd();
        }

        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] classWithStrings(String className, String... values) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, className, null,
                "java/lang/Object", null);

        MethodVisitor method = writer.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "value", "()V", null, null);
        method.visitCode();
        for (String value : values) {
            method.visitLdcInsn(value);
            method.visitInsn(Opcodes.POP);
        }
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(1, 0);
        method.visitEnd();

        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] classWithSocket(String className, String host, int port) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, className, null,
                "java/lang/Object", null);

        MethodVisitor method = writer.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "connect", "()V", null, null);
        method.visitCode();
        method.visitTypeInsn(Opcodes.NEW, "java/net/Socket");
        method.visitInsn(Opcodes.DUP);
        method.visitLdcInsn(host);
        method.visitLdcInsn(port);
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/net/Socket",
                "<init>", "(Ljava/lang/String;I)V", false);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(4, 0);
        method.visitEnd();

        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] classWithUrl(String className, String url) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, className, null,
                "java/lang/Object", null);

        MethodVisitor method = writer.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "endpoint", "()V", null, null);
        method.visitCode();
        method.visitTypeInsn(Opcodes.NEW, "java/net/URL");
        method.visitInsn(Opcodes.DUP);
        method.visitLdcInsn(url);
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/net/URL",
                "<init>", "(Ljava/lang/String;)V", false);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(3, 0);
        method.visitEnd();

        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] classWithString(String className, String value) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, className, null,
                "java/lang/Object", null);

        MethodVisitor method = writer.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "value", "()Ljava/lang/String;", null, null);
        method.visitCode();
        method.visitLdcInsn(value);
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(1, 0);
        method.visitEnd();

        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] classWithCallAndString(String className, String owner,
                                                 String calledName, String descriptor,
                                                 boolean isInterface, String value) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, className, null,
                "java/lang/Object", null);

        MethodVisitor method = writer.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "run", "()V", null, null);
        method.visitCode();
        method.visitLdcInsn(value);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitMethodInsn(
                isInterface ? Opcodes.INVOKEINTERFACE : Opcodes.INVOKEVIRTUAL,
                owner, calledName, descriptor, isInterface);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(1, 0);
        method.visitEnd();

        writer.visitEnd();
        return writer.toByteArray();
    }

    /**
     * Runtime.exec в open(), а команда открытия - в соседнем методе класса.
     * Так устроен, например, meteordevelopment.meteorclient.Main$OperatingSystem.
     */
    private static byte[] classWithOpenHelper(String className, String command) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, className, null,
                "java/lang/Object", null);

        MethodVisitor helper = writer.visitMethod(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
                "getURLOpenCommand", "()[Ljava/lang/String;", null, null);
        helper.visitCode();
        helper.visitInsn(Opcodes.ICONST_1);
        helper.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/String");
        helper.visitInsn(Opcodes.DUP);
        helper.visitInsn(Opcodes.ICONST_0);
        helper.visitLdcInsn(command);
        helper.visitInsn(Opcodes.AASTORE);
        helper.visitInsn(Opcodes.ARETURN);
        helper.visitMaxs(4, 0);
        helper.visitEnd();

        MethodVisitor open = writer.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "open", "()V", null, null);
        open.visitCode();
        open.visitInsn(Opcodes.ACONST_NULL);
        open.visitMethodInsn(Opcodes.INVOKESTATIC, className,
                "getURLOpenCommand", "()[Ljava/lang/String;", false);
        open.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Runtime",
                "exec", "([Ljava/lang/String;)Ljava/lang/Process;", false);
        open.visitInsn(Opcodes.POP);
        open.visitInsn(Opcodes.RETURN);
        open.visitMaxs(2, 0);
        open.visitEnd();

        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] classWithHardwareCollector(String className) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, className, null,
                "java/lang/Object", null);

        MethodVisitor method = writer.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "collect", "()V", null, null);
        method.visitCode();
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE,
                "oshi/hardware/ComputerSystem", "getHardwareUUID",
                "()Ljava/lang/String;", true);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL,
                "java/net/NetworkInterface", "getHardwareAddress",
                "()[B", false);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(1, 0);
        method.visitEnd();

        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] classWithHardwareCall(String className, String owner,
                                                String calledName, String descriptor,
                                                boolean isInterface) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, className, null,
                "java/lang/Object", null);

        MethodVisitor method = writer.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "collect", "()V", null, null);
        method.visitCode();
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitMethodInsn(
                isInterface ? Opcodes.INVOKEINTERFACE : Opcodes.INVOKEVIRTUAL,
                owner, calledName, descriptor, isInterface);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(1, 0);
        method.visitEnd();

        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] emptyClass(String className) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, className, null,
                "java/lang/Object", null);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] classWithStringAndDefineClass(String className, String value) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, className, null,
                "java/lang/Object", null);

        MethodVisitor method = writer.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "load", "([B)Ljava/lang/Class;", null, null);
        method.visitCode();
        method.visitLdcInsn(value);
        method.visitInsn(Opcodes.POP);
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitInsn(Opcodes.ICONST_0);
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitInsn(Opcodes.ARRAYLENGTH);
        method.visitMethodInsn(Opcodes.INVOKESTATIC,
                "java/lang/ClassLoader", "defineClass",
                "([BII)Ljava/lang/Class;", false);
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(4, 1);
        method.visitEnd();

        writer.visitEnd();
        return writer.toByteArray();
    }

    private static Path writeJar(Path directory, String name,
                                 Map<String, byte[]> entries) throws IOException {
        Path jar = directory.resolve(name);
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(jar))) {
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                zip.putNextEntry(new ZipEntry(entry.getKey()));
                zip.write(entry.getValue());
                zip.closeEntry();
            }
        }
        return jar;
    }

    private static byte[] zipBytes(Map<String, byte[]> entries) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(output)) {
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                zip.putNextEntry(new ZipEntry(entry.getKey()));
                zip.write(entry.getValue());
                zip.closeEntry();
            }
        }
        return output.toByteArray();
    }

    private static byte[] utf8(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    private static String hex(String text) {
        StringBuilder result = new StringBuilder();
        for (byte value : text.getBytes(StandardCharsets.UTF_8)) {
            result.append(Character.forDigit((value >> 4) & 0x0F, 16));
            result.append(Character.forDigit(value & 0x0F, 16));
        }
        return result.toString();
    }

    private static String reverse(String text) {
        return new StringBuilder(text).reverse().toString();
    }

    private static String randomToken(int length, long seed) {
        Random random = new Random(seed);
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder result = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            result.append(alphabet.charAt(random.nextInt(alphabet.length())));
        }
        return result.toString();
    }

    private static String randomUnicodeToken(int length, long seed) {
        Random random = new Random(seed);
        StringBuilder result = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            result.append((char) (0x0410 + random.nextInt(64)));
        }
        return result.toString();
    }

    private static String renderReport(ModScanResult scan, OnlineCheckResult online) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (PrintStream out = new PrintStream(
                bytes, true, StandardCharsets.UTF_8)) {
            ReportPrinter.print(List.of(new ModReport(scan, online)), out);
        }
        return bytes.toString(StandardCharsets.UTF_8);
    }

    private static boolean hasUrlClassLoaderInStaticInitializer(byte[] classBytes) {
        boolean[] found = {false};
        ClassReader reader = new ClassReader(classBytes);
        reader.accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                if (!"<clinit>".equals(name)) {
                    return null;
                }
                return new MethodVisitor(Opcodes.ASM9) {
                    @Override
                    public void visitTypeInsn(int opcode, String type) {
                        if ("java/net/URLClassLoader".equals(type)) {
                            found[0] = true;
                        }
                    }

                    @Override
                    public void visitMethodInsn(int opcode, String owner, String name,
                                                String descriptor, boolean isInterface) {
                        if ("java/net/URLClassLoader".equals(owner)) {
                            found[0] = true;
                        }
                    }
                };
            }
        }, 0);
        return found[0];
    }

    private static boolean hasOpcode(Map<String, byte[]> entries, int opcode) {
        boolean[] found = {false};
        for (byte[] classBytes : classEntries(entries).values()) {
            ClassReader reader = new ClassReader(classBytes);
            reader.accept(new ClassVisitor(Opcodes.ASM9) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                 String signature, String[] exceptions) {
                    return new MethodVisitor(Opcodes.ASM9) {
                        @Override
                        public void visitInsn(int instruction) {
                            if (instruction == opcode) {
                                found[0] = true;
                            }
                        }
                    };
                }
            }, 0);
        }
        return found[0];
    }

    private static List<String> stringConstants(byte[] classBytes) {
        List<String> result = new ArrayList<>();
        ClassReader reader = new ClassReader(classBytes);
        reader.accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                return new MethodVisitor(Opcodes.ASM9) {
                    @Override
                    public void visitLdcInsn(Object value) {
                        if (value instanceof String string) {
                            result.add(string);
                        }
                    }
                };
            }
        }, 0);
        return result;
    }

    private static Map<String, byte[]> classEntries(Map<String, byte[]> entries) {
        Map<String, byte[]> result = new LinkedHashMap<>();
        entries.forEach((name, bytes) -> {
            if (name.endsWith(".class")) {
                result.put(name, bytes);
            }
        });
        return result;
    }

    private static boolean containsInAnyEntry(Map<String, byte[]> entries, String text) {
        for (byte[] bytes : entries.values()) {
            if (contains(bytes, text)) {
                return true;
            }
        }
        return false;
    }

    private static boolean contains(byte[] data, String text) {
        byte[] needle = text.getBytes(StandardCharsets.ISO_8859_1);
        outer:
        for (int i = 0; i <= data.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (data[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    private static Map<String, byte[]> readEntries(Path jar) throws IOException {
        Map<String, byte[]> result = new LinkedHashMap<>();
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            var entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (!entry.isDirectory()) {
                    try (var input = zip.getInputStream(entry)) {
                        result.put(entry.getName(), input.readAllBytes());
                    }
                }
            }
        }
        return result;
    }

    private static List<String> listJarNames(Path directory) throws IOException {
        try (Stream<Path> paths = Files.list(directory)) {
            return paths
                    .filter(Files::isRegularFile)
                    .map(path -> path.getFileName().toString())
                    .filter(name -> name.endsWith(".jar"))
                    .sorted(Comparator.naturalOrder())
                    .toList();
        }
    }

    private static double entropy(String text) {
        if (text.isEmpty()) {
            return 0.0;
        }
        Map<Character, Integer> counts = new LinkedHashMap<>();
        for (int i = 0; i < text.length(); i++) {
            counts.merge(text.charAt(i), 1, Integer::sum);
        }
        double result = 0.0;
        for (int count : counts.values()) {
            double probability = (double) count / text.length();
            result -= probability * (Math.log(probability) / Math.log(2.0));
        }
        return result;
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }

    private static void check(String name, CheckedAction action) {
        try {
            action.run();
            passed++;
            System.out.println("[OK]   " + name);
        } catch (Exception | AssertionError e) {
            failed++;
            System.out.println("[FAIL] " + name + ": " + e.getMessage());
        }
    }

    @FunctionalInterface
    private interface CheckedAction {
        void run() throws Exception;
    }
}
