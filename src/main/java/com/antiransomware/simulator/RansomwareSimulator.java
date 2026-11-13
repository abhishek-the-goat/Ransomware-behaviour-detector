package com.antiransomware.simulator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.*;

public class RansomwareSimulator {
    private static final Logger logger = LoggerFactory.getLogger(RansomwareSimulator.class);

    private final Path sandboxFolder;
    private final SecureRandom secureRandom = new SecureRandom();

    public RansomwareSimulator(Path sandboxFolder) {
        Objects.requireNonNull(sandboxFolder, "sandboxFolder cannot be null");
        this.sandboxFolder = sandboxFolder.toAbsolutePath().normalize();
        try {
            if (!Files.exists(this.sandboxFolder)) {
                Files.createDirectories(this.sandboxFolder);
            }
        } catch (IOException e) {
            throw new RuntimeException("Could not create sandbox folder: " + this.sandboxFolder, e);
        }
    }

    public Path getSandboxFolder() {
        return sandboxFolder;
    }

    /**
     * Enforces strictly that a target path is inside the sandbox.
     */
    public void validateSandboxPath(Path path) {
        Objects.requireNonNull(path, "path cannot be null");
        Path norm = path.toAbsolutePath().normalize();
        if (!norm.startsWith(sandboxFolder)) {
            String err = String.format("SAFETY VIOLATION: Path '%s' is outside sandbox folder '%s'!", norm, sandboxFolder);
            logger.error(err);
            throw new SecurityException(err);
        }
    }

    /**
     * Generates harmless dummy plain-text files inside the sandbox.
     */
    public List<Path> createDummyFiles(int count) throws IOException {
        List<Path> created = new ArrayList<>();
        String[] samples = {
                "Quarterly Financial Performance Report\nRevenue: $1,200,000\nExpenses: $850,000\nNet: $350,000\nNotes: Solid performance across all sectors.",
                "Project Alpha Architecture Notes\nMicroservices architecture deployed on Kubernetes.\nPostgres primary database with read replicas.\nRedis cache for session management.",
                "Team Meeting Agenda\n1. Review sprint deliverables\n2. Pipeline deployment health\n3. Q3 roadmap brainstorming\n4. Open questions.",
                "Employee Handbook and Policies\nWorking hours: Flexible\nHealth insurance provided\nRemote work policy and guidelines."
        };

        for (int i = 1; i <= count; i++) {
            Path file = sandboxFolder.resolve("test_document_" + i + ".txt");
            validateSandboxPath(file);
            StringBuilder sb = new StringBuilder();
            sb.append("=== Confidential Corporate Document #").append(i).append(" ===\n");
            // Generate ~4KB of realistic text so encryption sample has full byte distribution
            String sample = samples[(i - 1) % samples.length];
            while (sb.length() < 4096) {
                sb.append(sample).append("\nSection ").append(sb.length()).append(":\n");
            }
            sb.append("\nFinal Timestamp: ").append(new Date()).append("\n");
            Files.writeString(file, sb.toString(), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE);
            created.add(file);
        }
        logger.info("Created {} dummy files in sandbox: {}", count, sandboxFolder);
        return created;
    }

    /**
     * Safely simulates ransomware encryption strictly inside the sandbox:
     * - Encrypts dummy files with AES
     * - Renames them with .locked extension
     * - Drops a README_DECRYPT.txt ransom note
     */
    public int simulateAttack(boolean dropRansomNote, int delayBetweenFilesMs) throws Exception {
        return simulateAttack(dropRansomNote, delayBetweenFilesMs, false);
    }

    public int simulateAttack(boolean dropRansomNote, int delayBetweenFilesMs, boolean skipCanaries) throws Exception {
        SecretKey key = generateAesKey();
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        List<Path> targetFiles = new ArrayList<>();
        try (var stream = Files.list(sandboxFolder)) {
            stream.filter(Files::isRegularFile)
                  .filter(p -> !p.getFileName().toString().endsWith(".locked"))
                  .filter(p -> !p.getFileName().toString().contains("DECRYPT"))
                  .filter(p -> {
                      if (skipCanaries) {
                          String name = p.getFileName().toString().toLowerCase();
                          return !name.equals("passwords.docx") && !name.equals("photos.zip") &&
                                 !name.equals("confidential_financials.xlsx") && !name.equals("tax_records_2025.pdf");
                      }
                      return true;
                  })
                  .forEach(targetFiles::add);
        }

        int encryptedCount = 0;
        for (Path file : targetFiles) {
            validateSandboxPath(file);

            // Read original content
            byte[] original = Files.readAllBytes(file);

            // AES Encrypt (produces high entropy > 7.9)
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            byte[] ciphertext = cipher.doFinal(original);

            // Write ciphertext to a new .locked file
            Path lockedPath = file.resolveSibling(file.getFileName().toString() + ".locked");
            validateSandboxPath(lockedPath);

            Files.write(lockedPath, ciphertext,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE);

            // Delete original unencrypted file (simulating in-place encryption + rename)
            Files.delete(file);
            encryptedCount++;

            logger.info("Sandbox simulated encryption: {} -> {}", file.getFileName(), lockedPath.getFileName());

            if (delayBetweenFilesMs > 0) {
                Thread.sleep(delayBetweenFilesMs);
            }
        }

        if (dropRansomNote) {
            Path notePath = sandboxFolder.resolve("README_DECRYPT.txt");
            validateSandboxPath(notePath);
            String noteContent = "!!! YOUR FILES ARE ENCRYPTED !!!\n\n" +
                    "All your important files have been encrypted using AES-256.\n" +
                    "To restore your files, send 0.5 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n" +
                    "Contact help_decrypt@sandbox-simulation.local with your key.\n";
            Files.writeString(notePath, noteContent, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE);
            logger.info("Sandbox dropped simulated ransom note at: {}", notePath);
        }

        return encryptedCount;
    }

    /**
     * Simulates modifying a canary file located in the sandbox.
     */
    public void tamperCanary(Path canaryFile) throws IOException {
        validateSandboxPath(canaryFile);
        if (!Files.exists(canaryFile)) {
            Files.writeString(canaryFile, "Original canary decoy content\n", StandardCharsets.UTF_8);
        }
        Files.writeString(canaryFile, "MALICIOUS CANARY CORRUPTION BY SIMULATOR\n", StandardCharsets.UTF_8,
                StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
        logger.info("Sandbox tampered canary file: {}", canaryFile);
    }

    /**
     * Cleans the sandbox directory safely.
     */
    public void cleanSandbox() throws IOException {
        try (var stream = Files.list(sandboxFolder)) {
            for (Path p : stream.toList()) {
                validateSandboxPath(p);
                if (Files.isDirectory(p)) {
                    // recursive delete inside sandbox only
                    deleteRecursively(p);
                } else {
                    Files.delete(p);
                }
            }
        }
        logger.info("Cleaned sandbox: {}", sandboxFolder);
    }

    private void deleteRecursively(Path dir) throws IOException {
        validateSandboxPath(dir);
        try (var stream = Files.list(dir)) {
            for (Path child : stream.toList()) {
                if (Files.isDirectory(child)) {
                    deleteRecursively(child);
                } else {
                    validateSandboxPath(child);
                    Files.delete(child);
                }
            }
        }
        Files.delete(dir);
    }

    private SecretKey generateAesKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256, secureRandom);
        return keyGen.generateKey();
    }
}
