package com.antiransomware.response;

import com.antiransomware.detector.ScoreBreakdown;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ProcessTerminatorTest {

    @Test
    @DisplayName("Kills offending process via ProcessHandle, records exe path and logs action")
    void testProcessTerminationViaProcessHandle(@TempDir Path tempDir) throws Exception {
        Path auditLog = tempDir.resolve("audit.log");
        ProcessTerminator terminator = new ProcessTerminator(auditLog);

        // Spawn a harmless background process (e.g., ping localhost with delay)
        ProcessBuilder pb = new ProcessBuilder("ping", "-n", "20", "127.0.0.1");
        Process process = pb.start();
        long pid = process.pid();
        assertThat(process.isAlive()).isTrue();

        try {
            // Act: trigger kill
            Path triggerFile = tempDir.resolve("encrypted_doc.docx.locked");
            ProcessActionRecord record = terminator.killProcess(pid, 85.0, triggerFile,
                    "High entropy writes and mass renames");

            System.out.println("Terminated record:\n" + record.formattedLog());

            boolean exited = process.waitFor(3, java.util.concurrent.TimeUnit.SECONDS);

            // Assert
            assertThat(record.getPid()).isEqualTo(pid);
            assertThat(record.isSuccess()).isTrue();
            assertThat(record.getAction()).isEqualTo("TERMINATED_FORCIBLY");
            assertThat(record.getExePath()).isNotEmpty();
            assertThat(exited).isTrue();
            assertThat(process.isAlive()).isFalse();

            // Verify audit log written
            assertThat(Files.exists(auditLog)).isTrue();
            String logContent = Files.readString(auditLog);
            assertThat(logContent).contains("PID: " + pid);
            assertThat(logContent).contains("TERMINATED_FORCIBLY");
        } finally {
            if (process.isAlive()) {
                process.destroyForcibly();
            }
        }
    }

    @Test
    @DisplayName("Protected PIDs (PID <= 4 and self PID) are protected from termination")
    void testProtectedPidNotKilled() {
        ProcessTerminator terminator = new ProcessTerminator();
        long currentPid = ProcessHandle.current().pid();

        ProcessActionRecord selfRecord = terminator.killProcess(currentPid, 100.0, null, "Self test");
        assertThat(selfRecord.getAction()).isEqualTo("PROTECTED_SKIPPED");
        assertThat(selfRecord.isSuccess()).isFalse();

        ProcessActionRecord systemRecord = terminator.killProcess(4, 100.0, null, "System test");
        assertThat(systemRecord.getAction()).isEqualTo("PROTECTED_SKIPPED");
        assertThat(systemRecord.isSuccess()).isFalse();
    }

    @Test
    @DisplayName("respondToAlert finds and kills registered suspect process")
    void testRespondToAlertWithRegisteredSuspectProcess(@TempDir Path tempDir) throws Exception {
        ProcessTerminator terminator = new ProcessTerminator();

        Process process = new ProcessBuilder("ping", "-n", "15", "127.0.0.1").start();
        long pid = process.pid();
        terminator.registerSuspectPid(pid);

        try {
            ScoreBreakdown alertBreakdown = new ScoreBreakdown(
                    Instant.now(), 5.0, 10, 5.0, 20.0,
                    7.95, 8, 8, 1.0, 35.0,
                    10, 25.0, 1, 20.0,
                    false, 0.0, 95.0, true,
                    tempDir.resolve("target.locked"),
                    Instant.now().minusSeconds(2),
                    "Simulated ransomware alert"
            );

            List<ProcessActionRecord> records = terminator.respondToAlert(alertBreakdown, null);

            assertThat(records).isNotEmpty();
            assertThat(records.get(0).getPid()).isEqualTo(pid);
            assertThat(records.get(0).isSuccess()).isTrue();
            assertThat(records.get(0).getPidSource()).isEqualTo("REGISTERED");
            boolean exited = process.waitFor(3, java.util.concurrent.TimeUnit.SECONDS);
            assertThat(exited).isTrue();
            assertThat(process.isAlive()).isFalse();
        } finally {
            if (process.isAlive()) {
                process.destroyForcibly();
            }
        }
    }

    @Test
    @DisplayName("Fallback PID attribution selects and kills youngest process started within 10s before event")
    void testFallbackPidAttributionWhenRestartManagerFindsNothing(@TempDir Path tempDir) throws Exception {
        ProcessTerminator terminator = new ProcessTerminator();

        // Spawn a child process right now
        Process process = new ProcessBuilder("ping", "-n", "25", "127.0.0.1").start();
        long pid = process.pid();
        assertThat(process.isAlive()).isTrue();

        try {
            Thread.sleep(60); // Allow process start time to register in OS

            Path nonLockedFile = tempDir.resolve("already_closed_doc.locked");
            Files.writeString(nonLockedFile, "ciphertext bytes");

            Instant now = Instant.now();
            ScoreBreakdown breakdown = new ScoreBreakdown(
                    now, 5.0, 10, 2.0, 15.0,
                    7.96, 10, 10, 1.0, 35.0,
                    10, 25.0, 1, 25.0,
                    false, 0.0, 100.0, true,
                    nonLockedFile,
                    now.plusMillis(500), // First suspicious event occurred AFTER process started
                    "Alert: mass encryption with file handles already closed"
            );

            // Act: respond to alert with no explicit PID and no open handle
            List<ProcessActionRecord> records = terminator.respondToAlert(breakdown, null);

            assertThat(records).isNotEmpty();
            ProcessActionRecord record = records.get(0);
            System.out.println("Fallback termination record:\n" + record.formattedLog());

            // Assert fallback attribution
            assertThat(record.getPidSource()).isEqualTo("FALLBACK");
            assertThat(record.getPid()).isEqualTo(pid);
            assertThat(record.isSuccess()).isTrue();
            assertThat(record.getAction()).isEqualTo("TERMINATED_FORCIBLY");

            boolean exited = process.waitFor(3, java.util.concurrent.TimeUnit.SECONDS);
            assertThat(exited).isTrue();
            assertThat(process.isAlive()).isFalse();
        } finally {
            if (process.isAlive()) {
                process.destroyForcibly();
            }
        }
    }

    @Test
    @DisplayName("Incident latch suppresses multiple responses during the same incident")
    void testIncidentLatchSuppressesRedundantKillAttempts(@TempDir Path tempDir) throws Exception {
        ProcessTerminator terminator = new ProcessTerminator();

        Process process = new ProcessBuilder("ping", "-n", "30", "127.0.0.1").start();
        long pid = process.pid();
        terminator.registerSuspectPid(pid);

        try {
            Instant now = Instant.now();
            ScoreBreakdown breakdown = new ScoreBreakdown(
                    now, 5.0, 10, 2.0, 15.0,
                    7.96, 10, 10, 1.0, 35.0,
                    10, 25.0, 1, 25.0,
                    true, 100.0, 100.0, true,
                    tempDir.resolve("canary.docx"),
                    now,
                    "Canary alert"
            );

            // First alert triggers response
            List<ProcessActionRecord> firstRecords = terminator.respondToAlert(breakdown, null);
            assertThat(firstRecords).isNotEmpty();
            assertThat(firstRecords.get(0).getAction()).isEqualTo("TERMINATED_FORCIBLY");
            assertThat(terminator.isIncidentActive()).isTrue();

            // Second alert immediately afterwards must be suppressed by the latch
            List<ProcessActionRecord> secondRecords = terminator.respondToAlert(breakdown, null);
            assertThat(secondRecords).isNotEmpty();
            assertThat(secondRecords.get(0).getAction()).isEqualTo("SUPPRESSED_INCIDENT_LATCH");

            // When latch is reset, response is allowed again
            terminator.resetIncidentLatch("Canary reset by operator");
            assertThat(terminator.isIncidentActive()).isFalse();
        } finally {
            if (process.isAlive()) {
                process.destroyForcibly();
            }
        }
    }

    @Test
    @DisplayName("Suspect snapshot captures candidate on score >= 40 and logs ALERT_PROCESS_ALREADY_EXITED if exited before alert")
    void testSuspectSnapshotAndProcessAlreadyExited(@TempDir Path tempDir) throws Exception {
        ProcessTerminator terminator = new ProcessTerminator();

        Process process = new ProcessBuilder("ping", "-n", "30", "127.0.0.1").start();
        long pid = process.pid();
        assertThat(process.isAlive()).isTrue();

        try {
            Instant t0 = Instant.now().plusMillis(500);

            // 1. Early warning score (score: 45.0 >= 40.0)
            ScoreBreakdown earlyWarning = new ScoreBreakdown(
                    t0, 5.0, 3, 0.6, 0.0,
                    7.8, 3, 3, 1.0, 20.0,
                    3, 25.0, 0, 0.0,
                    false, 0.0, 45.0, false,
                    tempDir.resolve("doc1.locked"),
                    t0,
                    "Early warning suspicious activity"
            );

            terminator.onScoreUpdate(earlyWarning);
            ProcessTerminator.CandidateInfo snapshot = terminator.getSnapshottedSuspect();
            assertThat(snapshot).as("Suspect snapshot should be captured on score >= 40").isNotNull();

            // 2. Simulate process exiting before the alert threshold is crossed
            process.destroyForcibly();
            process.waitFor(2, java.util.concurrent.TimeUnit.SECONDS);
            assertThat(process.isAlive()).isFalse();

            // 3. Score crosses alert threshold (85.0 >= 70.0)
            ScoreBreakdown alertBreakdown = new ScoreBreakdown(
                    Instant.now(), 5.0, 6, 1.2, 0.0,
                    7.9, 6, 6, 1.0, 35.0,
                    6, 25.0, 1, 25.0,
                    false, 0.0, 85.0, true,
                    tempDir.resolve("doc_final.locked"),
                    t0,
                    "Mass encryption alert after process exit"
            );

            List<ProcessActionRecord> records = terminator.respondToAlert(alertBreakdown, null);
            assertThat(records).isNotEmpty();

            ProcessActionRecord record = records.get(0);
            System.out.println("Snapshot exited record:\n" + record.formattedLog());

            assertThat(record.getAction())
                    .as("Must record ALERT_PROCESS_ALREADY_EXITED when snapshotted process has exited")
                    .isEqualTo("ALERT_PROCESS_ALREADY_EXITED");
            assertThat(record.getPid())
                    .as("Must report the snapshotted PID")
                    .isEqualTo(snapshot.pid());
        } finally {
            if (process.isAlive()) {
                process.destroyForcibly();
            }
        }
    }
}
