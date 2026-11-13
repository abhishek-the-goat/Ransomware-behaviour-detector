package com.antiransomware.simulator;

import com.antiransomware.detector.EntropyCalculator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RansomwareSimulatorTest {

    @Test
    @DisplayName("SAFETY CHECK: Simulator strictly refuses any path outside sandbox")
    void testSandboxBoundaryEnforced(@TempDir Path tempDir) {
        Path sandbox = tempDir.resolve("sandbox");
        Path outsideFolder = tempDir.resolve("protected_system_dir");

        RansomwareSimulator simulator = new RansomwareSimulator(sandbox);

        // Path outside sandbox must throw SecurityException
        Path illegalFile = outsideFolder.resolve("important_user_file.docx");
        assertThatThrownBy(() -> simulator.validateSandboxPath(illegalFile))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("outside sandbox");

        // Relative path traversal attack (e.g. sandbox/../forbidden) must also be caught
        Path traversalAttack = sandbox.resolve("../forbidden.txt");
        assertThatThrownBy(() -> simulator.validateSandboxPath(traversalAttack))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("outside sandbox");
    }

    @Test
    @DisplayName("Safe simulated attack works strictly within sandbox")
    void testSafeAttackSimulationInsideSandbox(@TempDir Path tempDir) throws Exception {
        Path sandbox = tempDir.resolve("safe_sandbox");
        RansomwareSimulator simulator = new RansomwareSimulator(sandbox);

        // 1. Generate 5 dummy plain text files
        List<Path> created = simulator.createDummyFiles(5);
        assertThat(created).hasSize(5);

        for (Path p : created) {
            assertThat(Files.exists(p)).isTrue();
            double initialEntropy = EntropyCalculator.calculateEntropy(p);
            assertThat(initialEntropy)
                    .as("Initial dummy files must be low-entropy plain text")
                    .isLessThan(5.0);
        }

        // 2. Run simulated attack
        int encryptedCount = simulator.simulateAttack(true, 10);
        assertThat(encryptedCount).isEqualTo(5);

        // 3. Verify files were renamed to .locked and have high entropy (> 7.5, typically ~7.99)
        List<Path> lockedFiles;
        try (var stream = Files.list(sandbox)) {
            lockedFiles = stream.filter(p -> p.getFileName().toString().endsWith(".locked")).toList();
        }

        assertThat(lockedFiles).hasSize(5);
        for (Path locked : lockedFiles) {
            double encryptedEntropy = EntropyCalculator.calculateEntropy(locked);
            System.out.printf("Encrypted locked file entropy (%s): %.4f%n", locked.getFileName(), encryptedEntropy);
            assertThat(encryptedEntropy)
                    .as("Ciphertext should have high entropy (> 7.5)")
                    .isGreaterThan(7.5);
        }

        // 4. Verify ransom note was dropped inside sandbox
        Path notePath = sandbox.resolve("README_DECRYPT.txt");
        assertThat(Files.exists(notePath)).isTrue();
        String noteContent = Files.readString(notePath);
        assertThat(noteContent).containsIgnoringCase("ENCRYPTED");
    }

    @Test
    @DisplayName("Canary tampering inside sandbox")
    void testCanaryTamperingInsideSandbox(@TempDir Path tempDir) throws IOException {
        Path sandbox = tempDir.resolve("sandbox_canary");
        RansomwareSimulator simulator = new RansomwareSimulator(sandbox);

        Path canary = sandbox.resolve("passwords.docx");
        simulator.tamperCanary(canary);

        assertThat(Files.exists(canary)).isTrue();
        assertThat(Files.readString(canary)).contains("MALICIOUS CANARY CORRUPTION");
    }
}

