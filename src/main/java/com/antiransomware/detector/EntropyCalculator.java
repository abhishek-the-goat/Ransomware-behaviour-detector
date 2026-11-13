package com.antiransomware.detector;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;

public final class EntropyCalculator {
    private static final double LOG_2 = Math.log(2);
    private static final int MAX_SAMPLE_FOR_ENTROPY = 64 * 1024; // 64 KB

    private EntropyCalculator() {
    }

    /**
     * Calculates Shannon entropy in bits per byte (0.0 to 8.0).
     * Formula: H = - sum(p_i * log2(p_i))
     */
    public static double calculateEntropy(byte[] data) {
        if (data == null || data.length == 0) {
            return 0.0;
        }

        int[] frequencies = new int[256];
        for (byte b : data) {
            frequencies[b & 0xFF]++;
        }

        double entropy = 0.0;
        double length = data.length;

        for (int count : frequencies) {
            if (count > 0) {
                double p = count / length;
                entropy -= p * (Math.log(p) / LOG_2);
            }
        }

        return entropy;
    }

    /**
     * Reads a sample of bytes from the path and computes Shannon entropy.
     */
    public static double calculateEntropy(Path path) throws IOException {
        if (!Files.exists(path) || Files.isDirectory(path)) {
            return 0.0;
        }
        try (InputStream in = Files.newInputStream(path, StandardOpenOption.READ)) {
            byte[] buffer = new byte[MAX_SAMPLE_FOR_ENTROPY];
            int read = in.read(buffer);
            if (read <= 0) {
                return 0.0;
            }
            if (read < buffer.length) {
                return calculateEntropy(Arrays.copyOf(buffer, read));
            }
            return calculateEntropy(buffer);
        }
    }
}

