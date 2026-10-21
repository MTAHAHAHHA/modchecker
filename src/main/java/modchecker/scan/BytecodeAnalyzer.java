package modchecker.scan;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Разбирает байткод через ASM и ищет правила 10-16, 27 и 29.
 *
 * ClassReader - только парсер. Классы модов не загружаются и не выполняются:
 * здесь нет Class.forName, loadClass или URLClassLoader.
 */
final class BytecodeAnalyzer {

    private static final int MAX_DECODED_ARRAY = 8192;
    private static final int MAX_DECODED_STRING = 4096;

    private BytecodeAnalyzer() {
    }

    static BytecodeAnalysis analyze(byte[] classBytes) {
        List<MethodAnalyzer> methods = new ArrayList<>();
        String[] className = {""};

        ClassReader reader = new ClassReader(classBytes);
        reader.accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public void visit(int version, int access, String name, String signature,
                              String superName, String[] interfaces) {
                className[0] = name.replace('/', '.');
            }

            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodAnalyzer method = new MethodAnalyzer(className[0], name);
                methods.add(method);
                return method;
            }
        }, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);

        String name = className[0];
        List<DangerousCall> calls = new ArrayList<>();
        List<HardwareCall> hardwareCalls = new ArrayList<>();
        List<SurveillanceCall> surveillanceCalls = new ArrayList<>();
        List<C2Call> c2Calls = new ArrayList<>();
        List<String> methodNames = new ArrayList<>();
        boolean dangerousInClinit = false;
        List<DecodedCandidate> xorStrings = new ArrayList<>();
        List<DecodedCandidate> assembledStrings = new ArrayList<>();
        XorLoop xorLoop = null;

        for (MethodAnalyzer method : methods) {
            method.finish();

            calls.addAll(method.calls());
            hardwareCalls.addAll(method.hardwareCalls());
            surveillanceCalls.addAll(method.surveillanceCalls());
            c2Calls.addAll(method.c2Calls());
            methodNames.add(method.methodName());
            if ("<clinit>".equals(method.methodName()) && !method.calls().isEmpty()) {
                dangerousInClinit = true;
            }
            if (xorLoop == null && method.hasXorLoop()) {
                xorLoop = new XorLoop(name, method.methodName());
            }

            for (String value : method.xorStrings()) {
                xorStrings.add(new DecodedCandidate(value, method.methodName(), "XOR"));
            }
            for (String value : method.assembledStrings()) {
                assembledStrings.add(new DecodedCandidate(
                        value, method.methodName(), "сборка по символам"));
            }
        }

        markClassLevelOpenCommands(methods, calls);

        return new BytecodeAnalysis(
                name,
                List.copyOf(calls),
                List.copyOf(hardwareCalls),
                List.copyOf(surveillanceCalls),
                List.copyOf(c2Calls),
                List.copyOf(methodNames),
                dangerousInClinit,
                List.copyOf(deduplicate(xorStrings)),
                List.copyOf(deduplicate(assembledStrings)),
                xorLoop
        );
    }

    private static List<DecodedCandidate> deduplicate(List<DecodedCandidate> candidates) {
        Map<String, DecodedCandidate> unique = new LinkedHashMap<>();
        for (DecodedCandidate candidate : candidates) {
            unique.putIfAbsent(candidate.technique() + '\u0000' + candidate.value(), candidate);
        }
        return List.copyOf(unique.values());
    }

    /**
     * Некоторые моды выносят команду открытия в соседний метод
     * (например, getURLOpenCommand), а Runtime.exec вызывают из open().
     * Если в классе есть такая команда, а сам вызов находится в методе open*,
     * считаем это открытием папки или ссылки.
     */
    private static void markClassLevelOpenCommands(List<MethodAnalyzer> methods,
                                                   List<DangerousCall> calls) {
        boolean classHasOpenCommand = methods.stream()
                .anyMatch(MethodAnalyzer::hasOpenCommandString);
        if (!classHasOpenCommand) {
            return;
        }

        for (int i = 0; i < calls.size(); i++) {
            DangerousCall call = calls.get(i);
            if (call.rule() == 13
                    && !call.openCommandContext()
                    && isOpenMethodName(call.methodName())) {
                calls.set(i, withOpenCommandContext(call));
            }
        }
    }

    private static boolean isOpenMethodName(String methodName) {
        String lower = methodName.toLowerCase(Locale.ROOT);
        return lower.equals("open") || lower.startsWith("open");
    }

    private static DangerousCall withOpenCommandContext(DangerousCall call) {
        return new DangerousCall(
                call.rule(),
                call.className(),
                call.methodName(),
                call.owner(),
                call.calledName(),
                call.descriptor(),
                true
        );
    }

    private static final class MethodAnalyzer extends MethodVisitor {

        private final String className;
        private final String methodName;
        private final List<DangerousCall> calls = new ArrayList<>();
        private final List<HardwareCall> hardwareCalls = new ArrayList<>();
        private final List<SurveillanceCall> surveillanceCalls = new ArrayList<>();
        private final List<C2Call> c2Calls = new ArrayList<>();
        private final List<String> hostCandidates = new ArrayList<>();
        private final List<ArrayValue> arrays = new ArrayList<>();
        private final List<Integer> recentInts = new ArrayList<>();
        private final Set<Label> visitedLabels = new HashSet<>();
        private final Set<Integer> xorKeys = new LinkedHashSet<>();
        private final List<String> builderStrings = new ArrayList<>();

        private ArrayValue currentArray;
        private StringBuilderCapture builder;
        private Integer lastInt;
        private String pendingString;
        private boolean hasByteArray;
        private boolean hasStringFromBytes;
        private boolean hasStringFromChars;
        private boolean hasXor;
        private boolean pendingXorValue;
        private boolean hasXorByteStore;
        private boolean hasOpenCommandString;
        private boolean hasRundll32;
        private boolean hasUrlDll;
        private boolean socketHostConstructor;
        private boolean backwardJump;
        private boolean finished;
        private final List<String> xorStrings = new ArrayList<>();
        private final List<String> assembledStrings = new ArrayList<>();

        private MethodAnalyzer(String className, String methodName) {
            super(Opcodes.ASM9);
            this.className = className;
            this.methodName = methodName;
        }

        List<DangerousCall> calls() {
            return calls;
        }

        List<HardwareCall> hardwareCalls() {
            return hardwareCalls;
        }

        List<SurveillanceCall> surveillanceCalls() {
            return surveillanceCalls;
        }

        List<C2Call> c2Calls() {
            return c2Calls;
        }

        String methodName() {
            return methodName;
        }

        boolean hasXorLoop() {
            // Числовой XOR в хеше или маске изображения сам по себе не похож на декодер.
            // Учитываем запись XOR-результата в байты или преобразование байтов в строку.
            return hasXor && backwardJump && hasByteArray
                    && (hasXorByteStore || hasStringFromBytes);
        }

        boolean hasOpenCommandString() {
            return hasOpenCommandString;
        }

        List<String> xorStrings() {
            return xorStrings;
        }

        List<String> assembledStrings() {
            return assembledStrings;
        }

        @Override
        public void visitInsn(int opcode) {
            boolean xorValue = pendingXorValue;
            if (opcode == Opcodes.BASTORE && xorValue) {
                hasXorByteStore = true;
            }
            if (opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5) {
                setInt(opcode - Opcodes.ICONST_0);
                return;
            }

            switch (opcode) {
                case Opcodes.IXOR -> {
                    hasXor = true;
                    if (lastInt != null) {
                        xorKeys.add(lastInt);
                    }
                    clearPending();
                    recentInts.clear();
                }
                case Opcodes.BASTORE, Opcodes.CASTORE -> {
                    recordArrayWrite(opcode);
                    clearPending();
                    recentInts.clear();
                }
                case Opcodes.ASTORE -> {
                    finishArray();
                    clearPending();
                    recentInts.clear();
                }
                default -> {
                    clearPending();
                    recentInts.clear();
                }
            }
            pendingXorValue = opcode == Opcodes.IXOR
                    || (opcode == Opcodes.I2B && xorValue);
        }

        @Override
        public void visitIntInsn(int opcode, int operand) {
            if (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) {
                setInt(operand);
                return;
            }

            if (opcode == Opcodes.NEWARRAY) {
                startArray(operand);
                return;
            }

            clearPending();
            recentInts.clear();
        }

        @Override
        public void visitVarInsn(int opcode, int varIndex) {
            clearPending();
            recentInts.clear();
        }

        @Override
        public void visitTypeInsn(int opcode, String type) {
            if (opcode == Opcodes.NEW && "java/lang/StringBuilder".equals(type)) {
                builder = new StringBuilderCapture();
            }
            clearPending();
            recentInts.clear();
        }

        @Override
        public void visitFieldInsn(int opcode, String owner, String name, String descriptor) {
            finishArray();
            clearPending();
            recentInts.clear();
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name,
                                    String descriptor, boolean isInterface) {
            // Массив мог быть передан в метод или сохранён в поле: снимаем
            // снимок до возможного цикла расшифровки.
            finishArray();

            int rule = ruleForCall(owner, name, descriptor);
            if (rule != 0) {
                calls.add(new DangerousCall(
                        rule, className, methodName, owner, name, descriptor, false));
            }
            if (isHardwareCall(owner, name)) {
                hardwareCalls.add(new HardwareCall(className, methodName, owner, name));
            }

            String surveillanceKind = surveillanceKind(owner, name);
            if (surveillanceKind != null) {
                surveillanceCalls.add(new SurveillanceCall(
                        className, methodName, owner, name, surveillanceKind));
            }

            if (isSocketHostConstructor(owner, name, descriptor)) {
                socketHostConstructor = true;
            }
            if (isUrlStringConstructor(owner, name, descriptor)
                    && pendingString != null) {
                String host = hostFrom(pendingString);
                if (host != null && isSuspiciousHost(host)) {
                    c2Calls.add(new C2Call(
                            className, methodName, "URL", host, pendingString));
                }
            }

            if (isStringFromBytes(owner, name, descriptor)) {
                hasStringFromBytes = true;
            }
            if (isStringFromChars(owner, name, descriptor)) {
                hasStringFromChars = true;
            }

            handleStringBuilder(owner, name, descriptor);

            clearPending();
            recentInts.clear();
        }

        @Override
        public void visitInvokeDynamicInsn(String name, String descriptor,
                                           Handle bootstrapMethodHandle,
                                           Object... bootstrapMethodArguments) {
            clearPending();
            recentInts.clear();
        }

        @Override
        public void visitJumpInsn(int opcode, Label label) {
            if (visitedLabels.contains(label)) {
                backwardJump = true;
            }
            clearPending();
            recentInts.clear();
        }

        @Override
        public void visitLabel(Label label) {
            visitedLabels.add(label);
            clearPending();
            recentInts.clear();
        }

        @Override
        public void visitLdcInsn(Object value) {
            if (value instanceof Integer integer) {
                setInt(integer);
            } else if (value instanceof String string) {
                pendingString = string;
                lastInt = null;
                String candidateHost = hostFrom(string);
                if (candidateHost != null) {
                    hostCandidates.add(string);
                }
                String lower = string.strip().toLowerCase(Locale.ROOT);
                if (lower.contains("rundll32")) {
                    hasRundll32 = true;
                }
                if (lower.contains("url.dll")) {
                    hasUrlDll = true;
                }
                if (isOpenCommandString(string)
                        || (hasRundll32 && hasUrlDll)) {
                    hasOpenCommandString = true;
                }
            } else {
                clearPending();
            }
        }

        @Override
        public void visitIincInsn(int varIndex, int increment) {
            clearPending();
            recentInts.clear();
        }

        @Override
        public void visitTableSwitchInsn(int min, int max, Label dflt, Label... labels) {
            if (visitedLabels.contains(dflt)) {
                backwardJump = true;
            }
            for (Label label : labels) {
                if (visitedLabels.contains(label)) {
                    backwardJump = true;
                }
            }
            clearPending();
            recentInts.clear();
        }

        @Override
        public void visitLookupSwitchInsn(Label dflt, int[] keys, Label[] labels) {
            if (visitedLabels.contains(dflt)) {
                backwardJump = true;
            }
            for (Label label : labels) {
                if (visitedLabels.contains(label)) {
                    backwardJump = true;
                }
            }
            clearPending();
            recentInts.clear();
        }

        @Override
        public void visitMultiANewArrayInsn(String descriptor, int numDimensions) {
            clearPending();
            recentInts.clear();
        }

        @Override
        public void visitEnd() {
            finish();
        }

        void finish() {
            if (finished) {
                return;
            }
            finished = true;
            finishArray();

            Set<String> decoded = new LinkedHashSet<>();
            if (hasStringFromBytes && hasXor) {
                for (ArrayValue array : arrays) {
                    if (array.type != Opcodes.T_BYTE) {
                        continue;
                    }
                    for (int key : xorKeys) {
                        String value = array.decodeXor(key);
                        if (value != null) {
                            decoded.add(value);
                        }
                    }
                }
            }
            for (String value : decoded) {
                addIfDangerous(xorStrings, value);
            }

            Set<String> assembled = new LinkedHashSet<>(builderStrings);
            if (hasStringFromChars) {
                for (ArrayValue array : arrays) {
                    if (array.type == Opcodes.T_CHAR) {
                        assembled.add(array.asChars());
                    }
                }
            }
            for (String value : assembled) {
                addIfDangerous(assembledStrings, value);
            }

            markOpenCommandCalls();
            markSocketHostCalls();
        }

        /**
         * LDC с хостом может стоять до new Socket(host, port), поэтому
         * проверяем кандидатов в конце метода, когда конструктор уже найден.
         */
        private void markSocketHostCalls() {
            if (!socketHostConstructor) {
                return;
            }
            for (String candidate : hostCandidates) {
                String host = hostFrom(candidate);
                if (host != null && isSuspiciousHost(host)) {
                    c2Calls.add(new C2Call(
                            className, methodName, "Socket", host, candidate));
                    return;
                }
            }
        }

        /**
         * Runtime.exec/ProcessBuilder рядом с командой открытия папки или
         * ссылки - это обычно штатное действие, а не запуск полезной нагрузки.
         */
        private void markOpenCommandCalls() {
            if (!hasOpenCommandString) {
                return;
            }
            for (int i = 0; i < calls.size(); i++) {
                DangerousCall call = calls.get(i);
                if (call.rule() == 13 && !call.openCommandContext()) {
                    calls.set(i, withOpenCommandContext(call));
                }
            }
        }

        private void setInt(int value) {
            pendingXorValue = false;
            lastInt = value;
            pendingString = null;
            recentInts.add(value);
            if (recentInts.size() > 3) {
                recentInts.remove(0);
            }
        }

        private void clearPending() {
            pendingXorValue = false;
            lastInt = null;
            pendingString = null;
        }

        private void startArray(int type) {
            finishArray();
            if (type == Opcodes.T_BYTE || type == Opcodes.T_CHAR) {
                int length = lastInt != null ? Math.max(0, lastInt) : 0;
                currentArray = new ArrayValue(type, length);
                if (type == Opcodes.T_BYTE) {
                    hasByteArray = true;
                }
            }
            clearPending();
            recentInts.clear();
        }

        private void recordArrayWrite(int opcode) {
            if (currentArray == null || recentInts.size() < 2) {
                return;
            }
            if (opcode == Opcodes.BASTORE && currentArray.type == Opcodes.T_BYTE) {
                currentArray.write(recentInts.get(recentInts.size() - 2),
                        recentInts.get(recentInts.size() - 1));
            } else if (opcode == Opcodes.CASTORE && currentArray.type == Opcodes.T_CHAR) {
                currentArray.write(recentInts.get(recentInts.size() - 2),
                        recentInts.get(recentInts.size() - 1));
            }
        }

        private void finishArray() {
            if (currentArray != null) {
                if (currentArray.written > 0) {
                    arrays.add(currentArray);
                }
                currentArray = null;
            }
        }

        private void handleStringBuilder(String owner, String name, String descriptor) {
            if (!"java/lang/StringBuilder".equals(owner)) {
                return;
            }
            if ("<init>".equals(name)) {
                if (builder != null && "(Ljava/lang/String;)V".equals(descriptor)) {
                    if (pendingString != null) {
                        builder.value.append(pendingString);
                    } else {
                        builder.valid = false;
                    }
                }
                return;
            }
            if (builder == null) {
                return;
            }

            if ("append".equals(name)) {
                if (descriptor.startsWith("(C)") || descriptor.startsWith("(I)")) {
                    if (lastInt != null) {
                        builder.value.append((char) lastInt.intValue());
                    } else {
                        builder.valid = false;
                    }
                } else if (descriptor.startsWith("(Ljava/lang/String;)")) {
                    if (pendingString != null) {
                        builder.value.append(pendingString);
                    } else {
                        builder.valid = false;
                    }
                } else {
                    builder.valid = false;
                }
            } else if ("toString".equals(name)) {
                captureBuilderString();
                builder = null;
            }
        }

        private void captureBuilderString() {
            if (builder != null && builder.valid && builder.value.length() > 0) {
                builderStrings.add(builder.value.toString());
            }
        }

        private void addIfDangerous(List<String> target, String value) {
            if (value == null || value.isEmpty() || value.length() > MAX_DECODED_STRING) {
                return;
            }
            if (!SignatureRules.matching(value).isEmpty()) {
                target.add(value);
            }
        }

        /**
         * Правило 22: OSHI и MAC-адрес. Это отдельный список, чтобы сбор HWID
         * не включал правило 16 "опасный вызов в статическом блоке".
         */
        private static boolean isHardwareCall(String owner, String name) {
            if ("java/net/NetworkInterface".equals(owner)) {
                return "getHardwareAddress".equals(name);
            }
            boolean oshi = owner.startsWith("oshi/") || owner.contains("/oshi/");
            return oshi && ("getHardwareUUID".equals(name)
                    || "getSerialNumber".equals(name)
                    || "getSerial".equals(name));
        }

        /**
         * Строки, которыми обычно открывают папку или ссылку в проводнике.
         * "open" проверяем отдельно, чтобы не поймать слово в длинном тексте.
         */
        private static boolean isOpenCommandString(String value) {
            String lower = value.strip().toLowerCase(Locale.ROOT);
            return lower.contains("explorer")
                    || lower.contains("xdg-open")
                    || lower.equals("open")
                    || lower.startsWith("open ")
                    || lower.contains("rundll32 url.dll");
        }

        private static boolean isStringFromBytes(String owner, String name, String descriptor) {
            if (!"java/lang/String".equals(owner)) {
                return false;
            }
            if ("<init>".equals(name) || "valueOf".equals(name)) {
                return descriptor.startsWith("([B");
            }
            return "copyValueOf".equals(name) && descriptor.startsWith("([B");
        }

        private static boolean isStringFromChars(String owner, String name, String descriptor) {
            if (!"java/lang/String".equals(owner)) {
                return false;
            }
            if ("<init>".equals(name) || "valueOf".equals(name)) {
                return descriptor.startsWith("([C");
            }
            return "copyValueOf".equals(name) && descriptor.startsWith("([C");
        }

        private static String surveillanceKind(String owner, String name) {
            if ("java/awt/Robot".equals(owner)
                    && "createScreenCapture".equals(name)) {
                return "экран";
            }
            if ("javax/sound/sampled/TargetDataLine".equals(owner)) {
                return "микрофон";
            }

            String lowerOwner = owner.toLowerCase(Locale.ROOT);
            if (lowerOwner.startsWith("net/minecraft")
                    || lowerOwner.startsWith("net/neoforged")
                    || lowerOwner.startsWith("net/minecraftforge")) {
                return null;
            }
            if (lowerOwner.contains("com/github/sarxos/webcam")
                    || lowerOwner.contains("webcam")
                    || lowerOwner.contains("videocapture")
                    || lowerOwner.contains("javacv")
                    || lowerOwner.contains("openimaj")
                    || lowerOwner.contains("directshow")
                    || lowerOwner.contains("avfoundation")) {
                return "вебкамера";
            }
            return null;
        }

        private static boolean isSocketHostConstructor(String owner, String name,
                                                       String descriptor) {
            return "java/net/Socket".equals(owner)
                    && "<init>".equals(name)
                    && descriptor.startsWith("(Ljava/lang/String;I");
        }

        private static boolean isUrlStringConstructor(String owner, String name,
                                                      String descriptor) {
            return "java/net/URL".equals(owner)
                    && "<init>".equals(name)
                    && "(Ljava/lang/String;)V".equals(descriptor);
        }

        /**
         * Достаёт хост из URL или из строки вида host:port. Строки с пробелами
         * и обычный текст не считаются хостом.
         */
        private static String hostFrom(String value) {
            if (value == null) {
                return null;
            }
            String text = value.strip();
            if (text.isEmpty() || text.length() > 2048 || text.contains(" ")) {
                return null;
            }

            String lower = text.toLowerCase(Locale.ROOT);
            if (lower.startsWith("http://") || lower.startsWith("https://")) {
                try {
                    String host = URI.create(text).getHost();
                    return host == null ? null : host.toLowerCase(Locale.ROOT);
                } catch (IllegalArgumentException ignored) {
                    return null;
                }
            }

            String candidate = text;
            int slash = candidate.indexOf('/');
            if (slash >= 0) {
                candidate = candidate.substring(0, slash);
            }
            if (!candidate.matches("[A-Za-z0-9._:%-]+")) {
                return null;
            }

            int firstColon = candidate.indexOf(':');
            int lastColon = candidate.lastIndexOf(':');
            if (firstColon > 0 && firstColon == lastColon) {
                candidate = candidate.substring(0, firstColon);
            }
            if (candidate.isEmpty()) {
                return null;
            }
            if (candidate.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
                return candidate;
            }
            if (candidate.matches("([A-Za-z0-9-]+\\.)+[A-Za-z]{2,}")) {
                return candidate.toLowerCase(Locale.ROOT);
            }
            return null;
        }

        /**
         * Правило 29 срабатывает только на туннели, динамический DNS
         * и публичные голые IP. Обычные домены и приватные адреса
         * игнорируются, чтобы не ловить API и локальные серверы.
         */
        private static boolean isSuspiciousHost(String host) {
            String lower = host.toLowerCase(Locale.ROOT);
            if (isPublicIpv4(lower)) {
                return true;
            }
            if (lower.equals("localhost")
                    || lower.equals("::1")
                    || lower.equals("[::1]")) {
                return false;
            }
            return lower.endsWith(".portmap.host")
                    || lower.equals("portmap.host")
                    || lower.contains("ngrok")
                    || lower.endsWith(".serveo.net")
                    || lower.equals("serveo.net")
                    || lower.endsWith(".trycloudflare.com")
                    || lower.endsWith(".loca.lt")
                    || lower.endsWith(".duckdns.org")
                    || lower.contains("no-ip")
                    || lower.endsWith(".noip.com")
                    || lower.equals("noip.com");
        }

        private static boolean isPublicIpv4(String host) {
            if (!host.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
                return false;
            }
            String[] parts = host.split("\\.");
            int[] octets = new int[4];
            for (int i = 0; i < parts.length; i++) {
                octets[i] = Integer.parseInt(parts[i]);
                if (octets[i] < 0 || octets[i] > 255) {
                    return false;
                }
            }
            int first = octets[0];
            int second = octets[1];
            if (first == 0 || first == 10 || first == 127) {
                return false;
            }
            if (first == 172 && second >= 16 && second <= 31) {
                return false;
            }
            if (first == 192 && second == 168) {
                return false;
            }
            if (first == 169 && second == 254) {
                return false;
            }
            if (first == 100 && second >= 64 && second <= 127) {
                return false;
            }
            return true;
        }

        private static int ruleForCall(String owner, String name, String descriptor) {
            if ("java/net/URLClassLoader".equals(owner)
                    && ("<init>".equals(name)
                    || "newInstance".equals(name)
                    || "loadClass".equals(name))) {
                return 12;
            }
            if ("defineClass".equals(name) && descriptor.contains("[B")) {
                return 12;
            }
            if ("java/lang/Runtime".equals(owner) && "exec".equals(name)) {
                return 13;
            }
            if ("java/lang/ProcessBuilder".equals(owner)
                    && ("<init>".equals(name) || "start".equals(name))) {
                return 13;
            }
            if ("java/net/URL".equals(owner) && "openConnection".equals(name)) {
                return 14;
            }
            if ("java/net/Socket".equals(owner)
                    || "javax/net/ssl/SSLSocket".equals(owner)) {
                return 14;
            }
            if (owner.startsWith("java/net/http/HttpClient")) {
                return 14;
            }
            return 0;
        }
    }

    private static final class ArrayValue {
        private final int type;
        private int[] values;
        private int written;

        private ArrayValue(int type, int length) {
            this.type = type;
            this.values = new int[Math.min(length, MAX_DECODED_ARRAY)];
        }

        private void write(int index, int value) {
            if (index < 0 || index >= MAX_DECODED_ARRAY) {
                return;
            }
            if (index >= values.length) {
                int newLength = Math.min(MAX_DECODED_ARRAY, Math.max(index + 1, values.length * 2));
                int[] grown = new int[newLength];
                System.arraycopy(values, 0, grown, 0, values.length);
                values = grown;
            }
            values[index] = value;
            written++;
        }

        private String decodeXor(int key) {
            if (values.length == 0) {
                return null;
            }
            byte[] bytes = new byte[values.length];
            for (int i = 0; i < values.length; i++) {
                bytes[i] = (byte) ((values[i] ^ key) & 0xFF);
            }
            return new String(bytes, StandardCharsets.UTF_8);
        }

        private String asChars() {
            char[] chars = new char[values.length];
            for (int i = 0; i < values.length; i++) {
                chars[i] = (char) (values[i] & 0xFFFF);
            }
            return new String(chars);
        }
    }

    private static final class StringBuilderCapture {
        private final StringBuilder value = new StringBuilder();
        private boolean valid = true;
    }
}

record DangerousCall(
        int rule,
        String className,
        String methodName,
        String owner,
        String calledName,
        String descriptor,
        boolean openCommandContext
) {
}

record HardwareCall(
        String className,
        String methodName,
        String owner,
        String calledName
) {
}

record SurveillanceCall(
        String className,
        String methodName,
        String owner,
        String calledName,
        String kind
) {
}

record C2Call(
        String className,
        String methodName,
        String kind,
        String host,
        String rawValue
) {
}

record DecodedCandidate(String value, String methodName, String technique) {
}

record XorLoop(String className, String methodName) {
}

record BytecodeAnalysis(
        String className,
        List<DangerousCall> dangerousCalls,
        List<HardwareCall> hardwareCalls,
        List<SurveillanceCall> surveillanceCalls,
        List<C2Call> c2Calls,
        List<String> methodNames,
        boolean dangerousInClinit,
        List<DecodedCandidate> xorStrings,
        List<DecodedCandidate> assembledStrings,
        XorLoop xorLoop
) {
}
