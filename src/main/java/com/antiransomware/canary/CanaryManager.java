package com.antiransomware.canary;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class CanaryManager {
    private static final Logger logger = LoggerFactory.getLogger(CanaryManager.class);

    public static final List<String> DEFAULT_CANARY_FILENAMES = List.of(
            "passwords.docx",
            "photos.zip",
            "confidential_financials.xlsx",
            "tax_records_2025.pdf"
    );

    private final Set<Path> deployedCanaries = ConcurrentHashMap.newKeySet();
    private final Set<Path> watchedFolders = ConcurrentHashMap.newKeySet();

    public CanaryManager() {
    }

    /**
     * Deploys decoy canary files into the specified folders.
     * Redeploys any canary file that is missing or already has a .locked extension.
     */
    public synchronized List<Path> deployCanaries(Collection<Path> folders) {
        if (folders != null) {
            watchedFolders.addAll(folders);
        }
        return ensureCanariesDeployed(folders);
    }

    public synchronized List<Path> ensureCanariesDeployed(Collection<Path> folders) {
        List<Path> created = new ArrayList<>();
        if (folders == null) {
            return created;
        }

        for (Path folder : folders) {
            if (!Files.exists(folder)) {
                try {
                    Files.createDirectories(folder);
                } catch (IOException e) {
                    logger.error("Failed to create folder for canaries: {}", folder, e);
                    continue;
                }
            }

            for (String filename : DEFAULT_CANARY_FILENAMES) {
                Path canaryPath = folder.resolve(filename).toAbsolutePath().normalize();
                Path lockedVariant = folder.resolve(filename + ".locked").toAbsolutePath().normalize();

                // 1. Clean up any leftover .locked canary files from previous attacks
                try {
                    if (Files.exists(lockedVariant)) {
                        Files.delete(lockedVariant);
                        logger.info("Cleaned up breached/locked canary file: {}", lockedVariant);
                    }
                } catch (IOException e) {
                    logger.warn("Could not delete locked canary file: {}", lockedVariant, e);
                }

                // 2. Check if canary file is missing or has 0 bytes
                boolean needsRedeploy = !Files.exists(canaryPath) || Files.isDirectory(canaryPath);
                if (!needsRedeploy) {
                    try {
                        if (Files.size(canaryPath) == 0) {
                            needsRedeploy = true;
                        }
                    } catch (IOException e) {
                        needsRedeploy = true;
                    }
                }

                if (needsRedeploy) {
                    try {
                        byte[] payload = generateDecoyContent(filename);
                        Files.write(canaryPath, payload,
                                StandardOpenOption.CREATE,
                                StandardOpenOption.TRUNCATE_EXISTING,
                                StandardOpenOption.WRITE);
                        deployedCanaries.add(canaryPath);
                        created.add(canaryPath);
                        logger.info("Deployed/Redeployed canary decoy file at: {}", canaryPath);
                    } catch (IOException e) {
                        logger.error("Failed to write canary file: {}", canaryPath, e);
                    }
                } else {
                    deployedCanaries.add(canaryPath);
                }
            }
        }
        return created;
    }

    /**
     * Redeploys all breached canaries automatically across all watched folders so subsequent runs have live canaries.
     */
    public synchronized List<Path> redeployBreachedCanaries() {
        return ensureCanariesDeployed(watchedFolders);
    }

    /**
     * Check if a given file path is a registered canary decoy.
     */
    public boolean isCanary(Path path) {
        if (path == null) {
            return false;
        }
        Path norm = path.toAbsolutePath().normalize();
        if (deployedCanaries.contains(norm)) {
            return true;
        }
        // Also check by filename if it matches default canary names
        String fileName = norm.getFileName() != null ? norm.getFileName().toString() : "";
        for (String canaryName : DEFAULT_CANARY_FILENAMES) {
            if (canaryName.equalsIgnoreCase(fileName)) {
                return true;
            }
        }
        return false;
    }

    public Set<Path> getDeployedCanaries() {
        return Collections.unmodifiableSet(deployedCanaries);
    }

    /**
     * Cleans up all deployed canaries.
     */
    public synchronized void removeCanaries() {
        for (Path path : deployedCanaries) {
            try {
                if (Files.exists(path)) {
                    Files.delete(path);
                    logger.info("Removed canary file: {}", path);
                }
            } catch (IOException e) {
                logger.warn("Could not delete canary file: {}", path, e);
            }
        }
        deployedCanaries.clear();
    }

    private byte[] generateDecoyContent(String filename) {
        String lower = filename.toLowerCase(Locale.ROOT);
        if (lower.endsWith(".zip") || lower.endsWith(".docx") || lower.endsWith(".xlsx")) {
            // Standard ZIP local file header PK\x03\x04
            byte[] header = new byte[]{0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00};
            byte[] body = ("Decoy container file for ransomware entrapment: " + filename +
                    "\nConfidential corporate archive content.\n").getBytes(StandardCharsets.UTF_8);
            byte[] result = new byte[header.length + body.length];
            System.arraycopy(header, 0, result, 0, header.length);
            System.arraycopy(body, 0, result, header.length, body.length);
            return result;
        } else if (lower.endsWith(".pdf")) {
            return ("%PDF-1.5\n%Decoy confidential financial record document\n%%EOF\n").getBytes(StandardCharsets.UTF_8);
        } else {
            return ("CONFIDENTIAL PASSWORD STORE: admin=supersecret123\n").getBytes(StandardCharsets.UTF_8);
        }
    }
}

