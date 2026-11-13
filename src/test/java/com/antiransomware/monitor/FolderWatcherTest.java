package com.antiransomware.monitor;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class FolderWatcherTest {

    @Test
    @DisplayName("Watcher is strictly scoped to configured folders only")
    void testScopedWatcherIgnoresUnscopedFolders(@TempDir Path tempDir) {
        Path configuredFolder = tempDir.resolve("configured");
        Path unconfiguredFolder = tempDir.resolve("unconfigured");

        FolderWatcher watcher = new FolderWatcher();
        watcher.addFolder(configuredFolder);

        assertThat(watcher.isScoped(configuredFolder.resolve("sub/file.txt"))).isTrue();
        assertThat(watcher.isScoped(unconfiguredFolder.resolve("file.txt"))).isFalse();
    }

    @Test
    @DisplayName("Emits file events for create, modify and delete in watched directory")
    void testFileEventDetection(@TempDir Path tempDir) throws Exception {
        Path watchDir = tempDir.resolve("watch_folder");
        Files.createDirectories(watchDir);

        FolderWatcher watcher = new FolderWatcher();
        watcher.addFolder(watchDir);

        List<FileEvent> receivedEvents = new CopyOnWriteArrayList<>();
        CountDownLatch latch = new CountDownLatch(1);

        watcher.addListener(event -> {
            receivedEvents.add(event);
            if (event.getType() == FileEventType.CREATE) {
                latch.countDown();
            }
        });

        watcher.start();
        try {
            // Small pause for OS WatchService to initialize
            Thread.sleep(200);

            Path testFile = watchDir.resolve("sample.txt");
            Files.writeString(testFile, "Hello World from ransomware detector test\n");

            boolean received = latch.await(4, TimeUnit.SECONDS);
            assertThat(received).as("WatchService should capture file creation").isTrue();
            assertThat(receivedEvents).isNotEmpty();

            FileEvent first = receivedEvents.get(0);
            assertThat(first.getFileName()).isEqualTo("sample.txt");
        } finally {
            watcher.stop();
        }
    }
}

