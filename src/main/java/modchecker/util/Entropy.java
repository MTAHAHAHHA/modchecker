package modchecker.util;

import java.util.HashMap;
import java.util.Map;

/**
 * Энтропия Шеннона: показывает, насколько данные «случайные».
 * Для текста считаем по символам, для файлов - по байтам.
 */
public final class Entropy {

    private Entropy() {
    }

    public static double ofString(String text) {
        if (text.isEmpty()) {
            return 0.0;
        }

        Map<Character, Integer> counts = new HashMap<>();
        for (int i = 0; i < text.length(); i++) {
            counts.merge(text.charAt(i), 1, Integer::sum);
        }

        double result = 0.0;
        for (int count : counts.values()) {
            double probability = (double) count / text.length();
            result -= probability * log2(probability);
        }
        return result;
    }

    public static double ofBytes(byte[] data) {
        if (data.length == 0) {
            return 0.0;
        }

        int[] counts = new int[256];
        for (byte value : data) {
            counts[value & 0xFF]++;
        }

        double result = 0.0;
        for (int count : counts) {
            if (count > 0) {
                double probability = (double) count / data.length;
                result -= probability * log2(probability);
            }
        }
        return result;
    }

    private static double log2(double value) {
        return Math.log(value) / Math.log(2.0);
    }
}
