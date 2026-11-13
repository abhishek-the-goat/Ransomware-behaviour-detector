package com.antiransomware.detector;

import com.antiransomware.monitor.FileEvent;
import com.antiransomware.monitor.FileEventType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

class ScoringEngineTest {

    private ScoringEngine engine;
    private final SecureRandom random = new SecureRandom();

    @BeforeEach
    void setUp() {
        engine = new ScoringEngine(Duration.ofSeconds(5));
    }

    @Test
    @DisplayName("Scoring triggers ALERT on simulated ransomware attack (score >= 70/100)")
    void testScoringTriggersOnSimulatedAttack() {
        AtomicBoolean alertTriggered = new AtomicBoolean(false);
        List<ScoreBreakdown> alerts = new ArrayList<>();
        engine.addAlertListener(b -> {
            alertTriggered.set(true);
            alerts.add(b);
        });

        Instant now = Instant.now();

        // Simulate 8 files being encrypted with high entropy (> 7.5) and renamed to .locked in 2 seconds
        ScoreBreakdown lastBreakdown = null;
        for (int i = 1; i <= 8; i++) {
            byte[] cipherBytes = new byte[8192];
            random.nextBytes(cipherBytes); // Entropy ~ 7.99

            Path oldPath = Paths.get("C:/sandbox/document_" + i + ".docx");
            Path newPath = Paths.get("C:/sandbox/document_" + i + ".docx.locked");

            FileEvent event = new FileEvent(newPath, oldPath, FileEventType.RENAME, now.plusMillis(i * 150),
                    cipherBytes.length, cipherBytes);

            lastBreakdown = engine.processEvent(event);
        }

        // Simulate drop of ransom note
        Path notePath = Paths.get("C:/sandbox/README_DECRYPT.txt");
        byte[] noteBytes = "All your files are encrypted! Pay ransom in BTC.".getBytes(StandardCharsets.UTF_8);
        FileEvent noteEvent = new FileEvent(notePath, FileEventType.CREATE, now.plusMillis(1400),
                noteBytes.length, noteBytes);
        lastBreakdown = engine.processEvent(noteEvent);

        System.out.println("Simulated attack breakdown:\n" + lastBreakdown.formattedLog());

        assertThat(alertTriggered.get())
                .as("Alert listener must be triggered during simulated attack")
                .isTrue();
        assertThat(lastBreakdown.isAlert())
                .as("Alert status must be true")
                .isTrue();
        assertThat(lastBreakdown.getTotalScore())
                .as("Total score should exceed threshold of 70/100")
                .isGreaterThanOrEqualTo(70.0);
        assertThat(lastBreakdown.getAvgEntropy())
                .as("Average entropy should be high (> 7.5)")
                .isGreaterThan(7.5);
        assertThat(lastBreakdown.getMassRenamesCount())
                .as("Mass renames should be tracked")
                .isGreaterThanOrEqualTo(5);
        assertThat(lastBreakdown.getRansomNotesCount())
                .as("Ransom note count should be detected")
                .isGreaterThanOrEqualTo(1);
    }

    @Test
    @DisplayName("No trigger on normal benign file copy operations (score < 70/100)")
    void testNoTriggerOnNormalFileCopy() {
        AtomicBoolean alertTriggered = new AtomicBoolean(false);
        engine.addAlertListener(b -> alertTriggered.set(true));

        Instant now = Instant.now();
        String benignText = "Standard office text document.\nNormal entropy English text for review.\n";
        byte[] plainBytes = benignText.getBytes(StandardCharsets.UTF_8);

        ScoreBreakdown lastBreakdown = null;
        // Simulate normal file creation/modification of 3 files
        for (int i = 1; i <= 3; i++) {
            Path file = Paths.get("C:/sandbox/meeting_notes_" + i + ".txt");
            FileEvent event = new FileEvent(file, FileEventType.CREATE, now.plusMillis(i * 800),
                    plainBytes.length, plainBytes);
            lastBreakdown = engine.processEvent(event);
        }

        System.out.println("Normal file copy breakdown:\n" + lastBreakdown.formattedLog());

        assertThat(alertTriggered.get())
                .as("No alert must be triggered on benign file operations")
                .isFalse();
        assertThat(lastBreakdown.isAlert())
                .isFalse();
        assertThat(lastBreakdown.getTotalScore())
                .as("Total score must be well below alert threshold 70/100")
                .isLessThan(70.0);
        assertThat(lastBreakdown.getAvgEntropy())
                .as("Average entropy of plain text must be low (< 5.0)")
                .isLessThan(5.0);
    }

    @Test
    @DisplayName("Canary file modification triggers INSTANT 100/100 max score alert")
    void testCanaryTamperingTriggersInstantMaxScore() {
        Path canaryPath = Paths.get("C:/sandbox/passwords.docx");
        engine.setCanaryPredicate(p -> p.equals(canaryPath));

        AtomicBoolean alertTriggered = new AtomicBoolean(false);
        engine.addAlertListener(b -> alertTriggered.set(true));

        FileEvent canaryWrite = new FileEvent(canaryPath, FileEventType.MODIFY, Instant.now(),
                100, "corrupted content".getBytes(StandardCharsets.UTF_8));

        ScoreBreakdown breakdown = engine.processEvent(canaryWrite);
        System.out.println("Canary breach breakdown:\n" + breakdown.formattedLog());

        assertThat(alertTriggered.get()).isTrue();
        assertThat(breakdown.isAlert()).isTrue();
        assertThat(breakdown.getTotalScore()).isEqualTo(100.0);
        assertThat(breakdown.isCanaryTouched()).isTrue();
        assertThat(breakdown.getSummary()).containsIgnoringCase("canary");
    }

    @Test
    @DisplayName("21 renames in a window scores > 0")
    void testTwentyOneRenamesInAWindowScoresGreaterThanZero() {
        Instant now = Instant.now();
        ScoreBreakdown lastBreakdown = null;

        for (int i = 1; i <= 21; i++) {
            Path oldPath = Paths.get("C:/sandbox/doc_" + i + ".txt");
            Path newPath = Paths.get("C:/sandbox/doc_" + i + ".txt.locked");
            FileEvent event = new FileEvent(newPath, oldPath, FileEventType.RENAME, now.plusMillis(i * 50),
                    1024, new byte[0]);
            lastBreakdown = engine.processEvent(event);
        }

        assertThat(lastBreakdown).isNotNull();
        System.out.println("21 renames score breakdown:\n" + lastBreakdown.formattedLog());

        assertThat(lastBreakdown.getMassRenamesCount())
                .as("Should count all 21 renames")
                .isEqualTo(21);
        assertThat(lastBreakdown.getRenamesScore())
                .as("21 renames in a window must score > 0")
                .isGreaterThan(0.0);
        assertThat(lastBreakdown.getRenamesScore())
                .as("Mass renames should reach max score 25.0")
                .isEqualTo(25.0);
    }

    @Test
    @DisplayName("A ransom-note filename scores > 0")
    void testRansomNoteFilenameScoresGreaterThanZero() {
        Path notePath = Paths.get("C:/sandbox/README_DECRYPT.txt");
        byte[] noteContent = "All your files have been locked! Pay ransom to restore.\n".getBytes(StandardCharsets.UTF_8);

        FileEvent event = new FileEvent(notePath, FileEventType.CREATE, Instant.now(),
                noteContent.length, noteContent);

        ScoreBreakdown breakdown = engine.processEvent(event);
        System.out.println("Ransom note score breakdown:\n" + breakdown.formattedLog());

        assertThat(breakdown.getRansomNotesCount())
                .as("Should detect 1 ransom note")
                .isEqualTo(1);
        assertThat(breakdown.getRansomNotesScore())
                .as("A ransom-note filename must score > 0")
                .isGreaterThan(0.0);
        assertThat(breakdown.getRansomNotesScore())
                .as("Ransom note filename detection should contribute 25 points")
                .isEqualTo(25.0);
    }

    @Test
    @DisplayName("Events outside the 5-second window are safely purged")
    void testWindowPurge() {
        Instant t0 = Instant.now().minusSeconds(10);
        byte[] bytes = "Some sample text".getBytes(StandardCharsets.UTF_8);

        // Event 10 seconds ago
        FileEvent oldEvent = new FileEvent(Paths.get("C:/sandbox/old.txt"), FileEventType.CREATE, t0, bytes.length, bytes);
        engine.processEvent(oldEvent);

        // Event now
        FileEvent currentEvent = new FileEvent(Paths.get("C:/sandbox/current.txt"), FileEventType.CREATE, Instant.now(), bytes.length, bytes);
        ScoreBreakdown breakdown = engine.processEvent(currentEvent);

        assertThat(breakdown.getFilesModifiedCount())
                .as("Expired event must not be counted in the current 5-second window")
                .isEqualTo(1);
    }

    @Test
    @DisplayName("Simulated attack with no canary and no ransom note must cross 70 before the final event")
    void testSimulatedAttackWithoutCanaryAndWithoutRansomNoteCrossesThresholdBeforeFinalEvent() throws Exception {
        // Explicitly disable canary triggers
        engine.setCanaryPredicate(p -> false);

        AtomicBoolean alertTriggered = new AtomicBoolean(false);
        engine.addAlertListener(b -> alertTriggered.set(true));

        Instant now = Instant.now();
        // Generate high-entropy ciphertext (> 7.9)
        byte[] cipherBytes = new byte[8192];
        random.nextBytes(cipherBytes);

        int totalFiles = 10;
        int alertTriggeredAtEventIndex = -1;
        ScoreBreakdown alertBreakdown = null;

        for (int i = 1; i <= totalFiles; i++) {
            Path oldPath = Paths.get("C:/sandbox/test_doc_" + i + ".txt");
            Path newPath = Paths.get("C:/sandbox/test_doc_" + i + ".txt.locked");

            // Event spaced by 50ms mimicking rapid ransomware encryption
            FileEvent event = new FileEvent(newPath, oldPath, FileEventType.RENAME,
                    now.plusMillis(i * 50), cipherBytes.length, cipherBytes);

            ScoreBreakdown breakdown = engine.processEvent(event);
            if (breakdown.isAlert() && alertTriggeredAtEventIndex == -1) {
                alertTriggeredAtEventIndex = i;
                alertBreakdown = breakdown;
            }
        }

        System.out.println("No-canary, no-note attack alerted at file index: " + alertTriggeredAtEventIndex);
        if (alertBreakdown != null) {
            System.out.println("Alert breakdown:\n" + alertBreakdown.formattedLog());
        }

        /*
         * Threshold Trade-off Documentation:
         * - Threshold 70/100 prevents false alarms on benign high-rate file operations (plain text copy: entropy < 5.0, score ~25.0)
         *   and benign high-entropy writes without renames (saving zip/video: renames = 0, score ~35-50).
         * - High-entropy writes (>7.5) combined with .locked renames in a rapid burst achieve:
         *     entropyScore (35) + renamesScore (25) + burstRateScore (15-21) = 75-81 > 70.
         * - This ensures an attack without canaries and without ransom notes is alerted on file 3 or 4,
         *   well before the 10th and final file is encrypted.
         */
        assertThat(alertTriggered.get())
                .as("Attack must trigger alert even without canaries or ransom notes")
                .isTrue();

        assertThat(alertTriggeredAtEventIndex)
                .as("Alert must cross 70/100 well before the final 10th event (expected at file 3 or 4)")
                .isGreaterThan(0)
                .isLessThan(totalFiles);

        assertThat(alertBreakdown).isNotNull();
        assertThat(alertBreakdown.getTotalScore())
                .as("Score must be >= 70.0")
                .isGreaterThanOrEqualTo(70.0);
        assertThat(alertBreakdown.getRansomNotesCount())
                .as("Must alert with 0 ransom notes")
                .isEqualTo(0);
        assertThat(alertBreakdown.isCanaryTouched())
                .as("Must alert without canary breach")
                .isFalse();
    }
}

