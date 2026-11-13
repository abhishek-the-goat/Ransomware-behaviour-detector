package com.antiransomware.monitor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class FolderWatcher implements AutoCloseable {
    private static final Logger logger = LoggerFactory.getLogger(FolderWatcher.class);
    private static final int MAX_SAMPLE_BYTES = 64 * 1024; // 64 KB sample for entropy analysis
    private static final long RENAME_CORRELATION_WINDOW_MS = 600;

    private final Set<Path> configuredFolders = new CopyOnWriteArraySet<>();
    private final List<FileEventListener> listeners = new CopyOnWriteArrayList<>();
    private final Map<WatchKey, Path> watchKeys = new ConcurrentHashMap<>();
    private final Map<Path, Long> recentModifications = new ConcurrentHashMap<>();
    private final Map<String, DeletedEntry> pendingDeletes = new ConcurrentHashMap<>();

    private WatchService watchService;
    private Thread watcherThread;
    private final AtomicBoolean running = new AtomicBoolean(false);

    private static class DeletedEntry {
        final Path path;
        final long timestamp;
        final long size;

        DeletedEntry(Path path, long timestamp, long size) {
            this.path = path;
            this.timestamp = timestamp;
            this.size = size;
        }
    }

    public FolderWatcher() {
    }

    public FolderWatcher(Collection<Path> folders) {
        if (folders != null) {
            folders.forEach(this::addFolder);
        }
    }

    public void addFolder(Path folder) {
        Objects.requireNonNull(folder, "folder cannot be null");
        Path abs = folder.toAbsolutePath().normalize();
        configuredFolders.add(abs);
        if (running.get() && watchService != null) {
            try {
                registerTree(abs);
            } catch (IOException e) {
                logger.error("Failed to register folder tree for {}", abs, e);
            }
        }
    }

    public void removeFolder(Path folder) {
        if (folder == null) return;
        Path abs = folder.toAbsolutePath().normalize();
        configuredFolders.remove(abs);
        // Unregister keys belonging to this subtree
        watchKeys.entrySet().removeIf(entry -> {
            if (entry.getValue().startsWith(abs)) {
                entry.getKey().cancel();
                return true;
            }
            return false;
        });
    }

    public Set<Path> getConfiguredFolders() {
        return Collections.unmodifiableSet(configuredFolders);
    }

    public void addListener(FileEventListener listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    public void removeListener(FileEventListener listener) {
        listeners.remove(listener);
    }

    public synchronized void start() throws IOException {
        if (running.get()) {
            return;
        }
        this.watchService = FileSystems.getDefault().newWatchService();
        this.running.set(true);

        for (Path root : configuredFolders) {
            if (Files.exists(root) && Files.isDirectory(root)) {
                registerTree(root);
            } else if (!Files.exists(root)) {
                Files.createDirectories(root);
                registerTree(root);
            }
        }

        this.watcherThread = new Thread(this::processEvents, "RansomwareDetector-FolderWatcher");
        this.watcherThread.setDaemon(true);
        this.watcherThread.start();
        logger.info("FolderWatcher started. Watching {} roots.", configuredFolders.size());
    }

    public synchronized void stop() {
        if (!running.get()) {
            return;
        }
        running.set(false);
        for (WatchKey key : watchKeys.keySet()) {
            key.cancel();
        }
        watchKeys.clear();

        if (watchService != null) {
            try {
                watchService.close();
            } catch (IOException e) {
                logger.warn("Error closing watch service", e);
            }
        }

        if (watcherThread != null) {
            watcherThread.interrupt();
        }
        logger.info("FolderWatcher stopped.");
    }

    public boolean isRunning() {
        return running.get();
    }

    private void registerTree(Path start) throws IOException {
        Files.walkFileTree(start, new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                registerDirectory(dir);
                return FileVisitResult.CONTINUE;
            }
        });
    }

    private void registerDirectory(Path dir) throws IOException {
        if (!isScoped(dir)) {
            return;
        }
        WatchKey key = dir.register(watchService,
                StandardWatchEventKinds.ENTRY_CREATE,
                StandardWatchEventKinds.ENTRY_MODIFY,
                StandardWatchEventKinds.ENTRY_DELETE);
        watchKeys.put(key, dir);
        logger.debug("Registered watch for directory: {}", dir);
    }

    public boolean isScoped(Path path) {
        Path norm = path.toAbsolutePath().normalize();
        for (Path root : configuredFolders) {
            if (norm.startsWith(root)) {
                return true;
            }
        }
        return false;
    }

    private void processEvents() {
        while (running.get()) {
            WatchKey key;
            try {
                key = watchService.take();
            } catch (InterruptedException | ClosedWatchServiceException e) {
                break;
            }

            Path dir = watchKeys.get(key);
            if (dir == null) {
                key.reset();
                continue;
            }

            for (WatchEvent<?> event : key.pollEvents()) {
                WatchEvent.Kind<?> kind = event.kind();
                if (kind == StandardWatchEventKinds.OVERFLOW) {
                    logger.warn("WatchService overflow event detected on {}", dir);
                    continue;
                }

                @SuppressWarnings("unchecked")
                WatchEvent<Path> ev = (WatchEvent<Path>) event;
                Path filename = ev.context();
                Path child = dir.resolve(filename).toAbsolutePath().normalize();

                if (!isScoped(child)) {
                    continue;
                }

                try {
                    handleWatchEvent(kind, child);
                } catch (Exception ex) {
                    logger.error("Error handling file watch event for {}", child, ex);
                }
            }

            boolean valid = key.reset();
            if (!valid) {
                watchKeys.remove(key);
                if (watchKeys.isEmpty()) {
                    logger.warn("All watch keys became invalid.");
                }
            }
        }
    }

    private void handleWatchEvent(WatchEvent.Kind<?> kind, Path target) {
        long now = System.currentTimeMillis();
        cleanPendingDeletes(now);

        if (kind == StandardWatchEventKinds.ENTRY_CREATE) {
            if (Files.isDirectory(target)) {
                try {
                    registerTree(target);
                } catch (IOException e) {
                    logger.error("Failed to register new directory tree: {}", target, e);
                }
                return;
            }

            // Check if this create is part of a rename operation
            Path oldPath = checkRenameCandidate(target, now);
            byte[] sample = readSampleSafely(target);
            long size = getFileSizeSafely(target);

            if (oldPath != null) {
                FileEvent event = new FileEvent(target, oldPath, FileEventType.RENAME, Instant.now(), size, sample);
                notifyListeners(event);
            } else {
                FileEvent event = new FileEvent(target, FileEventType.CREATE, Instant.now(), size, sample);
                notifyListeners(event);
            }
        } else if (kind == StandardWatchEventKinds.ENTRY_MODIFY) {
            if (Files.isDirectory(target)) {
                return;
            }

            // Debounce rapid continuous modify bursts on the same file (within 100ms)
            Long lastTime = recentModifications.get(target);
            if (lastTime != null && (now - lastTime) < 100) {
                return;
            }
            recentModifications.put(target, now);

            byte[] sample = readSampleSafely(target);
            long size = getFileSizeSafely(target);
            FileEvent event = new FileEvent(target, FileEventType.MODIFY, Instant.now(), size, sample);
            notifyListeners(event);
        } else if (kind == StandardWatchEventKinds.ENTRY_DELETE) {
            // Track in pending deletes for rename correlation
            String fileName = target.getFileName() != null ? target.getFileName().toString() : "";
            pendingDeletes.put(fileName, new DeletedEntry(target, now, 0));

            FileEvent event = new FileEvent(target, FileEventType.DELETE, Instant.now(), 0, new byte[0]);
            notifyListeners(event);
        }
    }

    private Path checkRenameCandidate(Path target, long now) {
        String targetName = target.getFileName() != null ? target.getFileName().toString() : "";
        for (Iterator<Map.Entry<String, DeletedEntry>> it = pendingDeletes.entrySet().iterator(); it.hasNext(); ) {
            Map.Entry<String, DeletedEntry> entry = it.next();
            DeletedEntry deleted = entry.getValue();
            if ((now - deleted.timestamp) <= RENAME_CORRELATION_WINDOW_MS) {
                // If parent directory is the same or extensions/names match rename pattern
                if (Objects.equals(deleted.path.getParent(), target.getParent())) {
                    it.remove();
                    return deleted.path;
                }
            } else {
                it.remove();
            }
        }
        return null;
    }

    private void cleanPendingDeletes(long now) {
        pendingDeletes.entrySet().removeIf(e -> (now - e.getValue().timestamp) > (RENAME_CORRELATION_WINDOW_MS * 2));
        recentModifications.entrySet().removeIf(e -> (now - e.getValue()) > 2000);
    }

    public byte[] readSampleSafely(Path path) {
        if (path == null) {
            return new byte[0];
        }
        for (int retry = 0; retry < 2; retry++) {
            Path targetPath = path;
            if (!Files.exists(targetPath) || Files.isDirectory(targetPath)) {
                // If original file was already renamed, check for .locked extension
                Path lockedVariant = Paths.get(path.toString() + ".locked");
                if (Files.exists(lockedVariant) && !Files.isDirectory(lockedVariant)) {
                    targetPath = lockedVariant;
                } else {
                    return new byte[0];
                }
            }

            try (InputStream in = Files.newInputStream(targetPath, StandardOpenOption.READ)) {
                byte[] buffer = new byte[MAX_SAMPLE_BYTES];
                int read = in.read(buffer);
                if (read > 0) {
                    if (read == buffer.length) {
                        return buffer;
                    }
                    return Arrays.copyOf(buffer, read);
                }
            } catch (IOException e) {
                // File might be momentarily locked by writer on Windows
                try {
                    Thread.sleep(5);
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        return new byte[0];
    }

    public long getFileSizeSafely(Path path) {
        try {
            if (Files.exists(path) && !Files.isDirectory(path)) {
                return Files.size(path);
            }
        } catch (IOException ignored) {
        }
        return 0;
    }

    private void notifyListeners(FileEvent event) {
        for (FileEventListener listener : listeners) {
            try {
                listener.onFileEvent(event);
            } catch (Exception e) {
                logger.error("Error in FileEventListener", e);
            }
        }
    }

    @Override
    public void close() {
        stop();
    }
}
