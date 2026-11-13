package com.antiransomware.canary;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CanaryManagerTest {

    @Test
    @DisplayName("Deploys decoy files (passwords.docx, photos.zip) with valid headers")
    void testCanaryDeploymentAndDetection(@TempDir Path tempDir) throws IOException {
        CanaryManager manager = new CanaryManager();
        List<Path> deployed = manager.deployCanaries(Collections.singletonList(tempDir));

        assertThat(deployed).isNotEmpty();

        Path docx = tempDir.resolve("passwords.docx");
        Path zip = tempDir.resolve("photos.zip");

        assertThat(Files.exists(docx)).isTrue();
        assertThat(Files.exists(zip)).isTrue();

        // Check ZIP header PK\x03\x04
        byte[] docxBytes = Files.readAllBytes(docx);
        assertThat(docxBytes[0]).isEqualTo((byte) 0x50); // 'P'
        assertThat(docxBytes[1]).isEqualTo((byte) 0x4B); // 'K'

        // Check canary detection
        assertThat(manager.isCanary(docx)).isTrue();
        assertThat(manager.isCanary(zip)).isTrue();
        assertThat(manager.isCanary(tempDir.resolve("normal_file.txt"))).isFalse();
    }

    @Test
    @DisplayName("Canary removal cleans up deployed decoy files")
    void testCanaryRemoval(@TempDir Path tempDir) {
        CanaryManager manager = new CanaryManager();
        manager.deployCanaries(Collections.singletonList(tempDir));

        Path docx = tempDir.resolve("passwords.docx");
        assertThat(Files.exists(docx)).isTrue();

        manager.removeCanaries();
        assertThat(Files.exists(docx)).isFalse();
        assertThat(manager.getDeployedCanaries()).isEmpty();
    }
}

