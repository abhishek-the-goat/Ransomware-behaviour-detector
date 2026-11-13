package com.antiransomware.monitor;

import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

public class FileEvent {
    private final Path path;
    private final Path oldPath;
    private final FileEventType type;
    private final Instant timestamp;
    private final long fileSize;
    private final byte[] sampleBytes;
    private Double entropy;
    private Long suspectedPid;
    private String suspectedProcessPath;

    public FileEvent(Path path, Path oldPath, FileEventType type, Instant timestamp, long fileSize, byte[] sampleBytes) {
        this.path = Objects.requireNonNull(path, "path cannot be null");
        this.oldPath = oldPath;
        this.type = Objects.requireNonNull(type, "type cannot be null");
        this.timestamp = timestamp != null ? timestamp : Instant.now();
        this.fileSize = fileSize;
        this.sampleBytes = sampleBytes != null ? sampleBytes : new byte[0];
    }

    public FileEvent(Path path, FileEventType type, Instant timestamp, long fileSize, byte[] sampleBytes) {
        this(path, null, type, timestamp, fileSize, sampleBytes);
    }

    public Path getPath() {
        return path;
    }

    public Optional<Path> getOldPath() {
        return Optional.ofNullable(oldPath);
    }

    public FileEventType getType() {
        return type;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public long getFileSize() {
        return fileSize;
    }

    public byte[] getSampleBytes() {
        return sampleBytes;
    }

    public Optional<Double> getEntropy() {
        return Optional.ofNullable(entropy);
    }

    public void setEntropy(Double entropy) {
        this.entropy = entropy;
    }

    public Optional<Long> getSuspectedPid() {
        return Optional.ofNullable(suspectedPid);
    }

    public void setSuspectedPid(Long suspectedPid) {
        this.suspectedPid = suspectedPid;
    }

    public Optional<String> getSuspectedProcessPath() {
        return Optional.ofNullable(suspectedProcessPath);
    }

    public void setSuspectedProcessPath(String suspectedProcessPath) {
        this.suspectedProcessPath = suspectedProcessPath;
    }

    public String getFileName() {
        Path fn = path.getFileName();
        return fn != null ? fn.toString() : "";
    }

    public String getFileExtension() {
        String name = getFileName();
        int idx = name.lastIndexOf('.');
        return (idx > 0 && idx < name.length() - 1) ? name.substring(idx + 1).toLowerCase() : "";
    }

    @Override
    public String toString() {
        return "FileEvent{" +
                "path=" + path +
                ", oldPath=" + oldPath +
                ", type=" + type +
                ", timestamp=" + timestamp +
                ", fileSize=" + fileSize +
                ", entropy=" + (entropy != null ? String.format("%.3f", entropy) : "N/A") +
                ", suspectedPid=" + suspectedPid +
                '}';
    }
}

