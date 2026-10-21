package modchecker.scan;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.util.ArrayList;
import java.util.List;

/**
 * Извлекает строковые константы из байткода через ASM ClassReader.
 *
 * ClassReader - это парсер. Он не загружает класс, не создаёт объекты
 * и не выполняет методы.
 */
final class ClassStringExtractor {

    private ClassStringExtractor() {
    }

    static List<StringConstant> extract(byte[] classBytes) {
        List<StringConstant> result = new ArrayList<>();

        ClassReader reader = new ClassReader(classBytes);
        reader.accept(new ClassVisitor(Opcodes.ASM9) {
            private String className;

            @Override
            public void visit(int version, int access, String name, String signature,
                              String superName, String[] interfaces) {
                className = name.replace('/', '.');
            }

            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                return new MethodVisitor(Opcodes.ASM9) {
                    @Override
                    public void visitLdcInsn(Object value) {
                        if (value instanceof String string) {
                            result.add(new StringConstant(string, className, name));
                        }
                    }
                };
            }
        }, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);

        return result;
    }
}
