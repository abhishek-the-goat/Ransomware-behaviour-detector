package com.antiransomware.detector;

import com.antiransomware.monitor.FileEvent;
import com.antiransomware.monitor.FileEventType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import java.util.function.Predicate;

public class ScoringEngine {
    private static final Logger logger = LoggerFactory.getLogger(ScoringEngine.class);

    public static final double ALERT_THRESHOLD = 70.0;
    public static final Duration DEFAULT_WINDOW_DURATION = Duration.ofSeconds(5);
    private static final int MAX_SAMPLE_READ_BYTES = 64 * 1024;

    private final Duration windowDuration;
    private final Deque<FileEvent> eventWindow = new ConcurrentLinkedDeque<>();
    private final List<Consumer<ScoreBreakdown>> decisionListeners = new CopyOnWriteArrayList<>();
    private final List<Consumer<ScoreBreakdown>> alertListeners = new CopyOnWriteArrayList<>();
    private Predicate<Path> canaryPredicate = p -> false;

    public ScoringEngine() {
        this(DEFAULT_WINDOW_DURATION);
    }

    public ScoringEngine(Duration windowDuration) {
        this.windowDuration = windowDuration != null ? windowDuration : DEFAULT_WINDOW_DURATION;
    }

    public void setCanaryPredicate(Predicate<Path> canaryPredicate) {
        this.canaryPredicate = canaryPredicate != null ? canaryPredicate : p -> false;
    }

    public void addDecisionListener(Consumer<ScoreBreakdown> listener) {
        if (listener != null) {
            decisionListeners.add(listener);
        }
    }

    public void addAlertListener(Consumer<ScoreBreakdown> listener) {
        if (listener != null) {
            alertListeners.add(listener);
        }
    }

    public synchronized ScoreBreakdown processEvent(FileEvent event) {
        Objects.requireNonNull(event, "event cannot be null");
        Instant now = event.getTimestamp();

        // 1. Calculate entropy if needed (skip for DELETE events and canary files)
        boolean isCanaryEvent = canaryPredicate.test(event.getPath()) ||
                (event.getOldPath().isPresent() && canaryPredicate.test(event.getOldPath().get()));
        if (event.getType() != FileEventType.DELETE && !isCanaryEvent && event.getEntropy().isEmpty()) {
            byte[] data = event.getSampleBytes();
            if (data == null || data.length == 0) {
                data = tryReadSampleFromDisk(event.getPath());
            }
            if (data != null && data.length > 0) {
                double entropy = EntropyCalculator.calculateEntropy(data);
                event.setEntropy(entropy);
            }
        }

        // 2. Add to sliding window and purge old events outside the window
        eventWindow.addLast(event);
        purgeExpiredEvents(now);

        // 3. Compute score breakdown on every file event so response triggers immediately
        ScoreBreakdown breakdown = evaluateWindow(now, event);

        // 4. Log every decision with timestamp and score breakdown
        logger.info("\n{}", breakdown.formattedLog());

        // 5. Notify listeners immediately
        for (Consumer<ScoreBreakdown> listener : decisionListeners) {
            try {
                listener.accept(breakdown);
            } catch (Exception e) {
                logger.error("Error notifying decision listener", e);
            }
        }

        if (breakdown.isAlert()) {
            for (Consumer<ScoreBreakdown> listener : alertListeners) {
                try {
                    listener.accept(breakdown);
                } catch (Exception e) {
                    logger.error("Error notifying alert listener", e);
                }
            }
        }

        return breakdown;
    }

    private byte[] tryReadSampleFromDisk(Path path) {
        if (path == null) {
            return new byte[0];
        }
        for (int retry = 0; retry < 2; retry++) {
            Path target = path;
            if (!Files.exists(target) || Files.isDirectory(target)) {
                // Check if already renamed with .locked
                Path lockedVariant = Paths.get(path.toString() + ".locked");
                if (Files.exists(lockedVariant) && !Files.isDirectory(lockedVariant)) {
                    target = lockedVariant;
                } else {
                    return new byte[0];
                }
            }
            try (InputStream in = Files.newInputStream(target, StandardOpenOption.READ)) {
                byte[] buf = new byte[MAX_SAMPLE_READ_BYTES];
                int read = in.read(buf);
                if (read > 0) {
                    return read == buf.length ? buf : Arrays.copyOf(buf, read);
                }
            } catch (IOException e) {
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

    private void purgeExpiredEvents(Instant currentTime) {
        long windowMillis = windowDuration.toMillis();
        while (!eventWindow.isEmpty()) {
            FileEvent oldest = eventWindow.peekFirst();
            if (oldest != null && Duration.between(oldest.getTimestamp(), currentTime).toMillis() > windowMillis) {
                eventWindow.pollFirst();
            } else {
                break;
            }
        }
    }

    public ScoreBreakdown evaluateWindow(Instant now, FileEvent latestEvent) {
        double windowSeconds = Math.max(1.0, windowDuration.toMillis() / 1000.0);

        int filesModifiedCount = 0;
        int massRenamesCount = 0;
        int ransomNotesCount = 0;
        boolean canaryTouched = false;
        Path canaryPath = null;
        Instant firstSuspiciousEventTime = null;

        List<Double> nonCanaryEntropyValues = new ArrayList<>();
        int highEntropyWritesCount = 0;

        for (FileEvent ev : eventWindow) {
            Path p = ev.getPath();
            String fileName = ev.getFileName();
            boolean isSuspiciousThisEvent = false;

            // Check if canary touched (create/modify/rename/delete)
            boolean isCanary = canaryPredicate.test(p) || (ev.getOldPath().isPresent() && canaryPredicate.test(ev.getOldPath().get()));
            if (isCanary) {
                canaryTouched = true;
                canaryPath = p;
                isSuspiciousThisEvent = true;
            }

            // Check ransom note
            if (RansomNotePatterns.isRansomNote(fileName)) {
                ransomNotesCount++;
                isSuspiciousThisEvent = true;
            }

            // Check renames and extensions
            if (ev.getType() == FileEventType.RENAME || RansomNotePatterns.hasSuspiciousExtension(fileName)) {
                massRenamesCount++;
                isSuspiciousThisEvent = true;
            }

            // Check modifications / creates / renames with content
            if (ev.getType() == FileEventType.MODIFY || ev.getType() == FileEventType.CREATE || ev.getType() == FileEventType.RENAME) {
                filesModifiedCount++;
                // EXCLUDE canary files from entropy calculations to avoid dilution by small decoy files
                if (!isCanary && ev.getEntropy().isPresent()) {
                    double ent = ev.getEntropy().get();
                    nonCanaryEntropyValues.add(ent);
                    if (ent > 7.5) {
                        highEntropyWritesCount++;
                        isSuspiciousThisEvent = true;
                    }
                }
            }

            if (isSuspiciousThisEvent && firstSuspiciousEventTime == null) {
                firstSuspiciousEventTime = ev.getTimestamp();
            }
        }

        if (firstSuspiciousEventTime == null) {
            firstSuspiciousEventTime = !eventWindow.isEmpty() ? eventWindow.peekFirst().getTimestamp() : now;
        }

        // Factor 2: Files modified per second (Weight: 25 max)
        // Rate is evaluated using window duration, with burst-rate detection if events occur in a fast burst
        double filesPerSec = filesModifiedCount / windowSeconds;
        if (eventWindow.size() >= 2) {
            long spanMs = Duration.between(eventWindow.peekFirst().getTimestamp(), eventWindow.peekLast().getTimestamp()).toMillis();
            if (spanMs > 0) {
                double burstSec = Math.max(0.5, spanMs / 1000.0);
                double burstRate = filesModifiedCount / burstSec;
                filesPerSec = Math.max(filesPerSec, burstRate);
            }
        }
        double filesPerSecScore;
        if (filesPerSec <= 1.0) {
            filesPerSecScore = 0.0;
        } else if (filesPerSec <= 5.0) {
            filesPerSecScore = (filesPerSec - 1.0) * (15.0 / 4.0); // Up to 15
        } else {
            filesPerSecScore = 15.0 + Math.min(10.0, (filesPerSec - 5.0) * 2.0); // Up to 25
        }

        // Factor 3: Entropy of non-canary writes scored by fraction of writes > 7.5 (Weight: 35 max)
        int samplesReadCount = nonCanaryEntropyValues.size();
        double avgEntropy = 0.0;
        if (!nonCanaryEntropyValues.isEmpty()) {
            double sum = 0.0;
            for (double v : nonCanaryEntropyValues) {
                sum += v;
            }
            avgEntropy = sum / nonCanaryEntropyValues.size();
        }

        double highEntropyFraction = samplesReadCount > 0 ? ((double) highEntropyWritesCount / samplesReadCount) : 0.0;
        double entropyScore = 0.0;

        if (highEntropyWritesCount > 0) {
            // Score by the fraction of sampled writes above 7.5
            entropyScore = highEntropyFraction * 25.0;
            if (highEntropyWritesCount >= 2) {
                entropyScore += 5.0;
            }
            if (highEntropyWritesCount >= 5) {
                entropyScore += 5.0;
            }
            entropyScore = Math.min(35.0, entropyScore);

            // If raw average is also > 7.5, ensure top tier score
            if (avgEntropy > 7.5) {
                double avgRatio = (avgEntropy - 7.5) / 0.5;
                entropyScore = Math.max(entropyScore, 25.0 + Math.min(10.0, avgRatio * 10.0));
            }
        } else if (avgEntropy > 6.5) {
            entropyScore = (avgEntropy - 6.5) * 10.0;
        }

        // Factor 4: Mass renames / extension changes (Weight: 25 max)
        double renamesScore;
        if (massRenamesCount == 0) {
            renamesScore = 0.0;
        } else if (massRenamesCount == 1) {
            renamesScore = 5.0;
        } else if (massRenamesCount < 4) {
            renamesScore = 15.0;
        } else {
            renamesScore = Math.min(25.0, 15.0 + (massRenamesCount - 3) * 1.5);
        }

        // If any event had explicit ransomware extension (.locked, etc.), ensure max rename score
        for (FileEvent ev : eventWindow) {
            if (RansomNotePatterns.hasSuspiciousExtension(ev.getFileName())) {
                renamesScore = Math.max(renamesScore, 25.0);
                break;
            }
        }

        // Factor 5: Ransom notes created (Weight: 25 max)
        double ransomNotesScore = (ransomNotesCount > 0) ? 25.0 : 0.0;

        // Canary score
        double canaryScore = canaryTouched ? 100.0 : 0.0;

        // Total score & alert decision
        double totalScore;
        boolean isAlert;
        StringBuilder summary = new StringBuilder();

        if (canaryTouched) {
            totalScore = 100.0;
            isAlert = true;
            summary.append("CRITICAL ALERT: Canary decoy file tampered (")
                   .append(canaryPath != null ? canaryPath.getFileName() : "decoy")
                   .append(")! Immediate response triggered.");
        } else {
            totalScore = filesPerSecScore + entropyScore + renamesScore + ransomNotesScore;
            totalScore = Math.min(100.0, Math.max(0.0, totalScore));
            isAlert = totalScore >= ALERT_THRESHOLD;

            if (isAlert) {
                summary.append("ALERT triggered: Score ").append(String.format(Locale.ROOT, "%.1f", totalScore))
                        .append(" >= ").append(ALERT_THRESHOLD).append(". Indicators:");
                if (filesPerSecScore > 10) summary.append(" [High write rate: ").append(String.format(Locale.ROOT, "%.1f", filesPerSec)).append("/s]");
                if (entropyScore >= 20) summary.append(" [High entropy writes: ").append(String.format(Locale.ROOT, "%.0f%% > 7.5", highEntropyFraction * 100.0)).append("]");
                if (renamesScore >= 15) summary.append(" [Mass renames: ").append(massRenamesCount).append("]");
                if (ransomNotesScore > 0) summary.append(" [Ransom note detected]");
            } else {
                summary.append("Normal activity. Score: ").append(String.format(Locale.ROOT, "%.1f", totalScore));
            }
        }

        return new ScoreBreakdown(
                now, windowSeconds, filesModifiedCount,
                filesPerSec, filesPerSecScore,
                avgEntropy, highEntropyWritesCount, samplesReadCount,
                highEntropyFraction, entropyScore,
                massRenamesCount, renamesScore,
                ransomNotesCount, ransomNotesScore,
                canaryTouched, canaryScore,
                totalScore, isAlert,
                canaryTouched && canaryPath != null ? canaryPath : latestEvent.getPath(),
                firstSuspiciousEventTime,
                summary.toString()
        );
    }

    public synchronized void reset() {
        eventWindow.clear();
    }
}
