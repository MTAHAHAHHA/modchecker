package modchecker.selftest;

import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.stream.Stream;

/**
 * Создаёт тестовые mod-jar'ы. Классы только компилируются и упаковываются,
 * но никогда не загружаются в JVM и не выполняются.
 */
public final class TestModsBuilder {

    private static final String DISCORD_WEBHOOK =
            "https://discord.com/api/webhooks/123456789012345678/test-token";
    private static final String HIDDEN_WEBHOOK =
            "https://discord.com/api/webhooks/1/test";
    private static final String TELEGRAM_HOST = "api.telegram.org";
    private static final String PASTEBIN_URL = "https://pastebin.com/raw/x";
    private static final int XOR_KEY = 42;
    private static final int LOADER_KEY = 0x33;

    private TestModsBuilder() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            throw new IllegalArgumentException("Нужны пути: outputDir, workDir и extraOutputDir");
        }

        Path outputDir = Path.of(args[0]).toAbsolutePath().normalize();
        Path workDir = Path.of(args[1]).toAbsolutePath().normalize();
        Path extraOutputDir = Path.of(args[2]).toAbsolutePath().normalize();

        resetDirectory(outputDir);
        resetDirectory(extraOutputDir);
        resetDirectory(workDir);

        Path sourcesDir = workDir.resolve("sources");
        Path classesDir = workDir.resolve("classes");
        Files.createDirectories(sourcesDir);
        Files.createDirectories(classesDir);

        buildJar(outputDir, sourcesDir, classesDir, "clean", "testmods.clean",
                "CleanMod", cleanSource());
        buildJar(outputDir, sourcesDir, classesDir, "discord_integration", "testmods.discord",
                "DiscordIntegration", discordSource());
        buildJar(outputDir, sourcesDir, classesDir, "stealer", "testmods.stealer",
                "Stealer", stealerSource());
        buildJar(outputDir, sourcesDir, classesDir, "hidden_stealer", "testmods.hidden",
                "HiddenStealer", hiddenStealerSource());
        buildJar(outputDir, sourcesDir, classesDir, "xor_stealer", "testmods.xor",
                "XorStealer", xorStealerSource());
        buildJar(outputDir, sourcesDir, classesDir, "loader", "testmods.loader",
                "LoaderMod", loaderSource());
        buildJar(outputDir, sourcesDir, classesDir, "fractureiser", "testmods.fractureiser",
                "FractureiserTest", fractureiserSource());
        buildJar(outputDir, sourcesDir, classesDir, "obfuscated", "testmods.obfuscated",
                "ObfuscatedMod", obfuscatedSource());

        Path broken = outputDir.resolve("broken.jar");
        Files.writeString(broken, "This is not a ZIP archive. It is a broken test mod.\n",
                StandardCharsets.UTF_8);

        buildExtraFixtures(extraOutputDir, sourcesDir, classesDir);

        System.out.println("Тестовые моды собраны в " + outputDir);
        printJars(outputDir);
        System.out.println("Дополнительные тестовые моды собраны в " + extraOutputDir);
        printJars(extraOutputDir);
    }

    private static void buildExtraFixtures(Path outputDir, Path sourcesDir,
                                           Path classesDir) throws IOException {
        buildJar(outputDir, sourcesDir, classesDir, "asm_calls", "testmods.asmcalls",
                "AsmCalls", asmCallsSource());
        buildJar(outputDir, sourcesDir, classesDir, "clinit_exec", "testmods.clinitexec",
                "ClinitExec", clinitExecSource());
        buildJar(outputDir, sourcesDir, classesDir, "paths", "testmods.paths",
                "PathsMod", pathsSource());
        buildJar(outputDir, sourcesDir, classesDir, "safe_xor", "testmods.safexor",
                "SafeXor", safeXorSource());
        buildJar(outputDir, sourcesDir, classesDir, "symbol_assembly",
                "testmods.symbols", "SymbolAssembly", symbolAssemblySource());
        buildJar(outputDir, sourcesDir, classesDir, "symbol_chars",
                "testmods.symbolchars", "SymbolChars", symbolCharsSource());
        buildJar(outputDir, sourcesDir, classesDir, "hidden_max_10",
                "testmods.max10", "HiddenMax10", hiddenMax10Source());

        Path fakeWork = outputDir.resolve(".fake_visual_rat_work");
        Files.createDirectories(fakeWork);
        buildJar(fakeWork, sourcesDir, classesDir, "fake_visual_rat_inner",
                "testmods.fakerat", "FakeVisualRat", fakeVisualRatSource());
        byte[] fakeInner = Files.readAllBytes(
                fakeWork.resolve("fake_visual_rat_inner.jar"));
        createDataJar(outputDir.resolve("fake_visual_rat.jar"),
                Map.of("assets/fake/libs.jar", fakeInner));
        deleteTree(fakeWork);

        String pastebin = Base64.getEncoder().encodeToString(
                PASTEBIN_URL.getBytes(StandardCharsets.UTF_8));
        String webhook = Base64.getEncoder().encodeToString(
                HIDDEN_WEBHOOK.getBytes(StandardCharsets.UTF_8));
        createDataJar(outputDir.resolve("hidden_max_9.jar"), Map.of(
                "assets/data.txt", utf8(pastebin + "\n" + webhook)
        ));
    }

    private static void printJars(Path directory) throws IOException {
        try (Stream<Path> files = Files.list(directory)) {
            files.filter(path -> path.getFileName().toString().endsWith(".jar"))
                    .sorted(Comparator.comparing(path -> path.getFileName().toString()))
                    .forEach(path -> System.out.println("  " + path.getFileName()));
        }
    }

    private static String cleanSource() {
        return """
                package testmods.clean;

                public final class CleanMod {
                    public static final String GREETING = "Hello, Minecraft!";

                    public static String description() {
                        return "A friendly building mod.";
                    }
                }
                """;
    }

    private static String discordSource() {
        return """
                package testmods.discord;

                public final class DiscordIntegration {
                    public static final String WEBHOOK = "%s";

                    public static String webhook() {
                        return WEBHOOK;
                    }

                    public static java.net.http.HttpClient client() {
                        return java.net.http.HttpClient.newHttpClient();
                    }
                }
                """.formatted(DISCORD_WEBHOOK);
    }

    private static String stealerSource() {
        return """
                package testmods.stealer;

                public final class Stealer {
                    public static String webhook() {
                        return "%s";
                    }

                    public static String storagePath() {
                        return "Local Storage";
                    }
                }
                """.formatted(DISCORD_WEBHOOK);
    }

    private static String hiddenStealerSource() {
        String encoded = Base64.getEncoder().encodeToString(
                HIDDEN_WEBHOOK.getBytes(StandardCharsets.UTF_8));

        return """
                package testmods.hidden;

                public final class HiddenStealer {
                    public static final String PACKED_WEBHOOK = "%s";

                    public static String packed() {
                        return PACKED_WEBHOOK;
                    }

                    public static String storagePath() {
                        return "Local Storage";
                    }
                }
                """.formatted(encoded);
    }

    private static String xorStealerSource() {
        return """
                package testmods.xor;

                public final class XorStealer {
                    public static String endpoint() {
                        byte[] data = { %s };
                        for (int i = 0; i < data.length; i++) {
                            data[i] = (byte) (data[i] ^ %d);
                        }
                        return new String(data, java.nio.charset.StandardCharsets.UTF_8);
                    }

                    public static String accounts() {
                        return "launcher_accounts";
                    }
                }
                """.formatted(xorBytes(TELEGRAM_HOST, XOR_KEY), XOR_KEY);
    }

    private static String loaderSource() {
        return """
                package testmods.loader;

                public final class LoaderMod {
                    private static final String PACKED_URL;

                    static {
                        byte[] data = { %s };
                        for (int i = 0; i < data.length; i++) {
                            data[i] = (byte) (data[i] ^ 0x%02X);
                        }
                        PACKED_URL = new String(data, java.nio.charset.StandardCharsets.UTF_8);
                        try {
                            java.net.URL url = new java.net.URL(PACKED_URL);
                            java.net.URLClassLoader loader =
                                    new java.net.URLClassLoader(new java.net.URL[] { url });
                            if (loader.getURLs().length == 0) {
                                throw new IllegalStateException("empty loader");
                            }
                        } catch (java.net.MalformedURLException e) {
                            throw new IllegalStateException(e);
                        }
                    }

                    public static String url() {
                        return PACKED_URL;
                    }
                }
                """.formatted(xorBytes(PASTEBIN_URL, LOADER_KEY), LOADER_KEY);
    }

    private static String fractureiserSource() {
        return """
                package testmods.fractureiser;

                public final class FractureiserTest {
                    public static String marker() {
                        return "dev/neko";
                    }
                }
                """;
    }

    private static String obfuscatedSource() {
        String token = randomToken();
        StringBuilder source = new StringBuilder();
        source.append("package testmods.obfuscated;\n\n");
        for (char name = 'a'; name <= 'k'; name++) {
            source.append("class ").append(name).append(" {\n")
                    .append("    static final int VALUE = ").append((int) name).append(";\n")
                    .append("}\n\n");
        }
        source.append("class l {\n")
                .append("    static final String TOKEN = \"").append(token).append("\";\n")
                .append("    static String token() { return TOKEN; }\n")
                .append("}\n");
        return source.toString();
    }

    private static String asmCallsSource() {
        return """
                package testmods.asmcalls;

                public final class AsmCalls {
                    public static Process exec() throws Exception {
                        return Runtime.getRuntime().exec("echo safe");
                    }

                    public static ProcessBuilder builder() {
                        return new ProcessBuilder("echo", "safe");
                    }

                    public static void connect() throws Exception {
                        new java.net.URL("http://example.com").openConnection();
                    }

                    public static java.net.Socket socket() throws Exception {
                        return new java.net.Socket();
                    }
                }
                """;
    }

    private static String clinitExecSource() {
        return """
                package testmods.clinitexec;

                public final class ClinitExec {
                    static {
                        new ProcessBuilder("echo", "safe");
                        try {
                            Runtime.getRuntime().exec("echo safe");
                        } catch (java.io.IOException ignored) {
                            // В тестовом классе ничего не запускается.
                        }
                    }

                    public static void touch() {
                    }
                }
                """;
    }

    private static String pathsSource() {
        return """
                package testmods.paths;

                public final class PathsMod {
                    public static String roaming() {
                        return "%APPDATA%/SomeMod";
                    }

                    public static String home() {
                        return System.getProperty("user.home");
                    }
                }
                """;
    }

    private static String safeXorSource() {
        return """
                package testmods.safexor;

                public final class SafeXor {
                    public static String text() {
                        byte[] data = { %s };
                        for (int i = 0; i < data.length; i++) {
                            data[i] = (byte) (data[i] ^ 0x5A);
                        }
                        return new String(data, java.nio.charset.StandardCharsets.UTF_8);
                    }
                }
                """.formatted(xorBytes("hello from a safe mod", 0x5A));
    }

    private static String symbolAssemblySource() {
        return """
                package testmods.symbols;

                public final class SymbolAssembly {
                    public static String endpoint() {
                        return new StringBuilder()%s.toString();
                    }
                }
                """.formatted(charAppendChain(TELEGRAM_HOST));
    }

    private static String symbolCharsSource() {
        return """
                package testmods.symbolchars;

                public final class SymbolChars {
                    public static String webhook() {
                        char[] chars = { %s };
                        return new String(chars);
                    }
                }
                """.formatted(charArray(HIDDEN_WEBHOOK));
    }

    private static String fakeVisualRatSource() {
        return """
                package testmods.fakerat;

                public final class FakeVisualRat {
                    public static String stealTelegramData() {
                        try {
                            java.net.Socket socket =
                                    new java.net.Socket("example.portmap.host", 61233);
                            socket.close();
                        } catch (Exception ignored) {
                        }
                        return "PASSWORD_STEAL";
                    }
                }
                """;
    }

    private static String hiddenMax10Source() {
        int key = 0x2A;
        return """
                package testmods.max10;

                public final class HiddenMax10 {
                    public static String pastebin() {
                        byte[] data = { %s };
                        for (int i = 0; i < data.length; i++) {
                            data[i] = (byte) (data[i] ^ 0x%02X);
                        }
                        return new String(data, java.nio.charset.StandardCharsets.UTF_8);
                    }

                    public static String webhook() {
                        byte[] data = { %s };
                        for (int i = 0; i < data.length; i++) {
                            data[i] = (byte) (data[i] ^ 0x%02X);
                        }
                        return new String(data, java.nio.charset.StandardCharsets.UTF_8);
                    }
                }
                """.formatted(xorBytes(PASTEBIN_URL, key), key,
                xorBytes(HIDDEN_WEBHOOK, key), key);
    }

    private static String charAppendChain(String text) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            result.append(".append(").append(javaChar(text.charAt(i))).append(')');
        }
        return result.toString();
    }

    private static String charArray(String text) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            if (i > 0) {
                result.append(", ");
            }
            result.append(javaChar(text.charAt(i)));
        }
        return result.toString();
    }

    private static String javaChar(char value) {
        return switch (value) {
            case '\'' -> "'\\''";
            case '\\' -> "'\\\\'";
            default -> "'" + value + "'";
        };
    }

    private static String randomToken() {
        Random random = new Random(20261020L);
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder result = new StringBuilder(80);
        for (int i = 0; i < 80; i++) {
            result.append(alphabet.charAt(random.nextInt(alphabet.length())));
        }
        return result.toString();
    }

    private static String xorBytes(String text, int key) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) {
                result.append(", ");
            }
            int value = (bytes[i] ^ key) & 0xFF;
            result.append("(byte)0x").append(String.format(Locale.ROOT, "%02X", value));
        }
        return result.toString();
    }

    private static void buildJar(Path outputDir, Path sourcesDir, Path classesDir,
                                 String jarName, String packageName, String sourceName,
                                 String source) throws IOException {
        Path sourceDir = sourcesDir.resolve(jarName).resolve(packageName.replace('.', '/'));
        Files.createDirectories(sourceDir);
        Path sourceFile = sourceDir.resolve(sourceName + ".java");
        Files.writeString(sourceFile, source, StandardCharsets.UTF_8);

        Path compiledClasses = classesDir.resolve(jarName);
        Files.createDirectories(compiledClasses);
        compile(sourceFile, compiledClasses);

        Path jar = outputDir.resolve(jarName + ".jar");
        createJar(compiledClasses, jar);
        System.out.println("  собран " + jar.getFileName());
    }

    private static void compile(Path sourceFile, Path classesDir) throws IOException {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            throw new IllegalStateException("Нужен JDK, а не JRE: компилятор Java не найден");
        }

        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        try (StandardJavaFileManager fileManager = compiler.getStandardFileManager(
                diagnostics, Locale.ROOT, StandardCharsets.UTF_8)) {

            Iterable<? extends JavaFileObject> units =
                    fileManager.getJavaFileObjects(sourceFile.toFile());

            List<String> options = List.of(
                    "-d", classesDir.toString(),
                    "--release", "17",
                    "-encoding", "UTF-8",
                    "-proc:none"
            );

            boolean success = compiler.getTask(null, fileManager, diagnostics,
                    options, null, units).call();

            if (!success) {
                StringBuilder message = new StringBuilder("Не удалось скомпилировать ")
                        .append(sourceFile).append('\n');
                for (Diagnostic<? extends JavaFileObject> diagnostic : diagnostics.getDiagnostics()) {
                    message.append(diagnostic).append('\n');
                }
                throw new IllegalStateException(message.toString());
            }
        }
    }

    private static void createJar(Path classesDir, Path jarFile) throws IOException {
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().putValue("Created-By", "ModChecker test fixtures");

        try (OutputStream output = Files.newOutputStream(jarFile);
             JarOutputStream jar = new JarOutputStream(output, manifest);
             Stream<Path> paths = Files.walk(classesDir)) {

            List<Path> classFiles = paths.filter(Files::isRegularFile).sorted().toList();
            for (Path classFile : classFiles) {
                String entryName = classesDir.relativize(classFile)
                        .toString().replace('\\', '/');
                JarEntry entry = new JarEntry(entryName);
                entry.setTime(0L);
                jar.putNextEntry(entry);
                Files.copy(classFile, jar);
                jar.closeEntry();
            }
        }
    }

    private static void createDataJar(Path jarFile, Map<String, byte[]> entries) throws IOException {
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().putValue("Created-By", "ModChecker test fixtures");

        try (OutputStream output = Files.newOutputStream(jarFile);
             JarOutputStream jar = new JarOutputStream(output, manifest)) {
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                JarEntry jarEntry = new JarEntry(entry.getKey());
                jarEntry.setTime(0L);
                jar.putNextEntry(jarEntry);
                jar.write(entry.getValue());
                jar.closeEntry();
            }
        }
        System.out.println("  собран " + jarFile.getFileName());
    }

    private static byte[] utf8(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    private static void deleteTree(Path directory) throws IOException {
        if (!Files.exists(directory)) {
            return;
        }
        try (Stream<Path> paths = Files.walk(directory)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }

    private static void resetDirectory(Path directory) throws IOException {
        if (Files.exists(directory)) {
            try (Stream<Path> paths = Files.walk(directory)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                    Files.deleteIfExists(path);
                }
            }
        }
        Files.createDirectories(directory);
    }
}
