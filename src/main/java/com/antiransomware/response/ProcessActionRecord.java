package com.antiransomware.response;

import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

public class ProcessActionRecord {
    private static final DateTimeFormatter ISO_FORMATTER =
            DateTimeFormatter.ofPattern("uuuu-MM-dd HH:mm:ss.SSS").withZone(ZoneId.systemDefault());

    private final Instant timestamp;
    private final long pid;
    private final String pidSource;
    private final String processName;
    private final String exePath;
    private final double alertScore;
    private final Path triggerFile;
    private final String reason;
    private final String action;
    private final boolean success;

    public ProcessActionRecord(Instant timestamp,
                               long pid,
                               String pidSource,
                               String processName,
                               String exePath,
                               double alertScore,
                               Path triggerFile,
                               String reason,
                               String action,
                               boolean success) {
        this.timestamp = timestamp != null ? timestamp : Instant.now();
        this.pid = pid;
        this.pidSource = pidSource != null ? pidSource : "UNKNOWN";
        this.processName = processName != null ? processName : "unknown";
        this.exePath = exePath != null ? exePath : "unknown";
        this.alertScore = alertScore;
        this.triggerFile = triggerFile;
        this.reason = reason;
        this.action = action;
        this.success = success;
    }

    public ProcessActionRecord(Instant timestamp,
                               long pid,
                               String processName,
                               String exePath,
                               double alertScore,
                               Path triggerFile,
                               String reason,
                               String action,
                               boolean success) {
        this(timestamp, pid, "UNKNOWN", processName, exePath, alertScore, triggerFile, reason, action, success);
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public long getPid() {
        return pid;
    }

    public String getPidSource() {
        return pidSource;
    }

    public String getProcessName() {
        return processName;
    }

    public String getExePath() {
        return exePath;
    }

    public double getAlertScore() {
        return alertScore;
    }

    public Path getTriggerFile() {
        return triggerFile;
    }

    public String getReason() {
        return reason;
    }

    public String getAction() {
        return action;
    }

    public boolean isSuccess() {
        return success;
    }

    public String formattedLog() {
        return String.format(Locale.ROOT,
                "[%s] RESPONSE ACTION: %s | PID: %d (via %s) | Exe: %s | Score: %.1f | Reason: %s | File: %s",
                ISO_FORMATTER.format(timestamp),
                action, pid, pidSource, exePath, alertScore, reason,
                triggerFile != null ? triggerFile.toString() : "N/A");
    }

    @Override
    public String toString() {
        return formattedLog();
    }
}
