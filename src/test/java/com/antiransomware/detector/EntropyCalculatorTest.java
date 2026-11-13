package com.antiransomware.detector;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

class EntropyCalculatorTest {

    @Test
    @DisplayName("Entropy of cryptographically random bytes must be > 7.9")
    void testEntropyOfRandomBytesGreaterThan7Point9() {
        SecureRandom random = new SecureRandom();
        byte[] randomBytes = new byte[64 * 1024]; // 64 KB
        random.nextBytes(randomBytes);

        double entropy = EntropyCalculator.calculateEntropy(randomBytes);
        System.out.printf("Random bytes entropy: %.4f%n", entropy);

        assertThat(entropy)
                .as("Cryptographic random bytes should have entropy close to theoretical max (8.0)")
                .isGreaterThan(7.9);
    }

    @Test
    @DisplayName("Entropy of plain text must be < 5.0")
    void testEntropyOfPlainTextLessThan5() {
        String plainText = """
                The quick brown fox jumps over the lazy dog.
                Ransomware behaviour detection is a proactive defense mechanism designed
                to analyze file system modifications, Shannon entropy levels, file rename
                patterns, and canary decoy integrity to neutralize malicious threats
                before widespread file encryption occurs.
                System administrators and security teams deploy layered defenses including
                immutable backups, endpoint detection and response, and network segmentation.
                Software engineering best practices recommend modular architecture, clean
                abstractions, thorough automated testing, and comprehensive audit logs.
                """;

        byte[] textBytes = plainText.getBytes(StandardCharsets.UTF_8);
        double entropy = EntropyCalculator.calculateEntropy(textBytes);
        System.out.printf("Plain text entropy: %.4f%n", entropy);

        assertThat(entropy)
                .as("Natural plain text should have low entropy (< 5.0)")
                .isLessThan(5.0);
    }

    @Test
    @DisplayName("Entropy of zero-byte array or uniform bytes is 0.0")
    void testZeroByteAndUniformData() {
        assertThat(EntropyCalculator.calculateEntropy(new byte[0])).isEqualTo(0.0);
        assertThat(EntropyCalculator.calculateEntropy((byte[]) null)).isEqualTo(0.0);

        byte[] allZeros = new byte[1024];
        assertThat(EntropyCalculator.calculateEntropy(allZeros)).isEqualTo(0.0);

        byte[] allSevens = new byte[1024];
        Arrays.fill(allSevens, (byte) 7);
        assertThat(EntropyCalculator.calculateEntropy(allSevens)).isEqualTo(0.0);
    }

    @Test
    @DisplayName("calculateEntropy directly from file path")
    void testFileEntropyCalculation(@TempDir Path tempDir) throws IOException {
        Path randomFile = tempDir.resolve("encrypted_sample.bin");
        byte[] data = new byte[32 * 1024];
        new SecureRandom().nextBytes(data);
        Files.write(randomFile, data);

        double entropy = EntropyCalculator.calculateEntropy(randomFile);
        assertThat(entropy).isGreaterThan(7.9);

        Path textFile = tempDir.resolve("readme.txt");
        Files.writeString(textFile, "Standard documentation file with ordinary text content.\n");
        double textEntropy = EntropyCalculator.calculateEntropy(textFile);
        assertThat(textEntropy).isLessThan(5.0);
    }

    @Test
    @DisplayName("Entropy of a .locked file must be > 7.5")
    void testEntropyOfLockedFileGreaterThan7Point5(@TempDir Path tempDir) throws Exception {
        Path lockedFile = tempDir.resolve("financial_spreadsheet.xlsx.locked");
        // Simulate 8KB AES encrypted locked file
        byte[] ciphertext = new byte[8192];
        new SecureRandom().nextBytes(ciphertext);
        Files.write(lockedFile, ciphertext);

        double entropy = EntropyCalculator.calculateEntropy(lockedFile);
        System.out.printf("Entropy of .locked file (%s): %.4f%n", lockedFile.getFileName(), entropy);

        assertThat(entropy)
                .as("Entropy of a .locked ciphertext file must exceed suspicious threshold 7.5")
                .isGreaterThan(7.5);
    }
}
