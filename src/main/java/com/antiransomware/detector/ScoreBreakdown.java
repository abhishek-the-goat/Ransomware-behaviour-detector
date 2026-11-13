package com.antiransomware.detector;

import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

public class ScoreBreakdown {
    private static final DateTimeFormatter ISO_FORMATTER =
            DateTimeFormatter.ofPattern("uuuu-MM-dd HH:mm:ss.SSS").withZone(ZoneId.systemDefault());

    private final Instant timestamp;
    private final double windowDurationSeconds;
    private final int filesModifiedCount;
    private final double filesPerSecond;
    private final double filesPerSecondScore;
    private final double avgEntropy;
    private final int highEntropyWritesCount;
    private final int samplesReadCount;
    private final double highEntropyFraction;
    private final double entropyScore;
    private final int massRenamesCount;
    private final double renamesScore;
    private final int ransomNotesCount;
    private final double ransomNotesScore;
    private final boolean canaryTouched;
    private final double canaryScore;
    private final double totalScore;
    private final boolean alert;
    private final Path triggerFile;
    private final Instant firstSuspiciousEventTime;
    private final String summary;

    public ScoreBreakdown(Instant timestamp,
                          double windowDurationSeconds,
                          int filesModifiedCount,
                          double filesPerSecond,
                          double filesPerSecondScore,
                          double avgEntropy,
                          int highEntropyWritesCount,
                          int samplesReadCount,
                          double highEntropyFraction,
                          double entropyScore,
                          int massRenamesCount,
                          double renamesScore,
                          int ransomNotesCount,
                          double ransomNotesScore,
                          boolean canaryTouched,
                          double canaryScore,
                          double totalScore,
                          boolean alert,
                          Path triggerFile,
                          Instant firstSuspiciousEventTime,
                          String summary) {
        this.timestamp = timestamp;
        this.windowDurationSeconds = windowDurationSeconds;
        this.filesModifiedCount = filesModifiedCount;
        this.filesPerSecond = filesPerSecond;
        this.filesPerSecondScore = filesPerSecondScore;
        this.avgEntropy = avgEntropy;
        this.highEntropyWritesCount = highEntropyWritesCount;
        this.samplesReadCount = samplesReadCount;
        this.highEntropyFraction = highEntropyFraction;
        this.entropyScore = entropyScore;
        this.massRenamesCount = massRenamesCount;
        this.renamesScore = renamesScore;
        this.ransomNotesCount = ransomNotesCount;
        this.ransomNotesScore = ransomNotesScore;
        this.canaryTouched = canaryTouched;
        this.canaryScore = canaryScore;
        this.totalScore = totalScore;
        this.alert = alert;
        this.triggerFile = triggerFile;
        this.firstSuspiciousEventTime = firstSuspiciousEventTime;
        this.summary = summary;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public double getWindowDurationSeconds() {
        return windowDurationSeconds;
    }

    public int getFilesModifiedCount() {
        return filesModifiedCount;
    }

    public double getFilesPerSecond() {
        return filesPerSecond;
    }

    public double getFilesPerSecondScore() {
        return filesPerSecondScore;
    }

    public double getAvgEntropy() {
        return avgEntropy;
    }

    public int getHighEntropyWritesCount() {
        return highEntropyWritesCount;
    }

    public int getSamplesReadCount() {
        return samplesReadCount;
    }

    public double getHighEntropyFraction() {
        return highEntropyFraction;
    }

    public double getEntropyScore() {
        return entropyScore;
    }

    public int getMassRenamesCount() {
        return massRenamesCount;
    }

    public double getRenamesScore() {
        return renamesScore;
    }

    public int getRansomNotesCount() {
        return ransomNotesCount;
    }

    public double getRansomNotesScore() {
        return ransomNotesScore;
    }

    public boolean isCanaryTouched() {
        return canaryTouched;
    }

    public double getCanaryScore() {
        return canaryScore;
    }

    public double getTotalScore() {
        return totalScore;
    }

    public boolean isAlert() {
        return alert;
    }

    public Path getTriggerFile() {
        return triggerFile;
    }

    public Instant getFirstSuspiciousEventTime() {
        return firstSuspiciousEventTime != null ? firstSuspiciousEventTime : timestamp;
    }

    public String getSummary() {
        return summary;
    }

    public String formattedLog() {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format(Locale.ROOT, "[%s] DECISION: %s (Score: %.1f/100)%n",
                ISO_FORMATTER.format(timestamp),
                alert ? ">>> ALERT: RANSOMWARE BEHAVIOUR DETECTED <<<" : "NORMAL",
                totalScore));
        sb.append(String.format(Locale.ROOT, "  - Files Modified: %d (%.2f files/sec) -> Score: %.1f%n",
                filesModifiedCount, filesPerSecond, filesPerSecondScore));
        sb.append(String.format(Locale.ROOT, "  - Write Entropy: %.1f%% > 7.5 (%d/%d writes > 7.5, avg: %.3f) -> Score: %.1f%n",
                highEntropyFraction * 100.0, highEntropyWritesCount, samplesReadCount, avgEntropy, entropyScore));
        sb.append(String.format(Locale.ROOT, "  - Mass Renames / Ext changes: %d -> Score: %.1f%n",
                massRenamesCount, renamesScore));
        sb.append(String.format(Locale.ROOT, "  - Ransom Notes: %d -> Score: %.1f%n",
                ransomNotesCount, ransomNotesScore));
        sb.append(String.format(Locale.ROOT, "  - Canary Touched: %s -> Score: %.1f%n",
                canaryTouched ? "YES (BREACH)" : "NO", canaryScore));
        if (triggerFile != null) {
            sb.append(String.format(Locale.ROOT, "  - Trigger File: %s%n", triggerFile));
        }
        sb.append(String.format(Locale.ROOT, "  - Summary: %s", summary));
        return sb.toString();
    }

    @Override
    public String toString() {
        return "ScoreBreakdown{" +
                "timestamp=" + timestamp +
                ", totalScore=" + String.format(Locale.ROOT, "%.1f", totalScore) +
                ", alert=" + alert +
                ", filesPerSec=" + String.format(Locale.ROOT, "%.2f", filesPerSecond) +
                ", highEntropyFraction=" + String.format(Locale.ROOT, "%.1f%%", highEntropyFraction * 100.0) +
                ", samplesRead=" + samplesReadCount +
                ", renames=" + massRenamesCount +
                ", ransomNotes=" + ransomNotesCount +
                ", canaryTouched=" + canaryTouched +
                '}';
    }
}
