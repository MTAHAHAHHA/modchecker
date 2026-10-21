package modchecker.online;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Хеши, которые нужны для проверки модов на сайтах.
 *
 * SHA-1 считается по всему jar-файлу. Для CurseForge используется
 * MurmurHash2 с seed 1 по тем же байтам, но без байтов 9, 10, 13 и 32.
 */
public final class Hashes {

    private static final int MURMUR_M = 0x5bd1e995;
    private static final int MURMUR_R = 24;

    private Hashes() {
    }

    public static String sha1(Path file) throws IOException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("В этой Java нет SHA-1", e);
        }

        try (InputStream input = Files.newInputStream(file)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = input.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
        }

        return toHex(digest.digest());
    }

    public static String toHex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            result.append(Character.forDigit((value >> 4) & 0x0F, 16));
            result.append(Character.forDigit(value & 0x0F, 16));
        }
        return result.toString();
    }

    public static byte[] filterForCurseForge(byte[] data) {
        ByteArrayOutputStream filtered = new ByteArrayOutputStream(data.length);
        for (byte item : data) {
            int value = item & 0xFF;
            if (value == 9 || value == 10 || value == 13 || value == 32) {
                continue;
            }
            filtered.write(value);
        }
        return filtered.toByteArray();
    }

    public static long curseForgeFingerprint(Path file) throws IOException {
        return curseForgeFingerprint(Files.readAllBytes(file));
    }

    public static long curseForgeFingerprint(byte[] data) {
        return murmurHash2(filterForCurseForge(data), 1);
    }

    /**
     * MurmurHash2, 32-битное беззнаковое значение.
     */
    public static long murmurHash2(byte[] data, int seed) {
        int length = data.length;
        int h = seed ^ length;
        int roundedEnd = length & 0xFFFFFFFC;

        for (int i = 0; i < roundedEnd; i += 4) {
            int k = (data[i] & 0xFF)
                    | ((data[i + 1] & 0xFF) << 8)
                    | ((data[i + 2] & 0xFF) << 16)
                    | ((data[i + 3] & 0xFF) << 24);

            k *= MURMUR_M;
            k ^= k >>> MURMUR_R;
            k *= MURMUR_M;

            h *= MURMUR_M;
            h ^= k;
        }

        int remaining = length & 3;
        if (remaining == 3) {
            h ^= (data[roundedEnd + 2] & 0xFF) << 16;
        }
        if (remaining >= 2) {
            h ^= (data[roundedEnd + 1] & 0xFF) << 8;
        }
        if (remaining >= 1) {
            h ^= data[roundedEnd] & 0xFF;
            h *= MURMUR_M;
        }

        h ^= h >>> 13;
        h *= MURMUR_M;
        h ^= h >>> 15;

        return h & 0xFFFFFFFFL;
    }
}
