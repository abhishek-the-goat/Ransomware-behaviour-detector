package com.antiransomware.dashboard;

import com.antiransomware.detector.ScoreBreakdown;
import com.antiransomware.monitor.FileEvent;
import com.antiransomware.response.ProcessActionRecord;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

public class ConsoleDashboard {
    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("HH:mm:ss.SSS").withZone(ZoneId.systemDefault());

    public void printBanner() {
        System.out.println("================================================================================");
        System.out.println("            JAVA RANSOMWARE BEHAVIOUR DETECTOR & ACTIVE RESPONSE                ");
        System.out.println("                   Windows / Java 17+ / Shannon Entropy Engine                  ");
        System.out.println("================================================================================");
    }

    public void onFileEvent(FileEvent event) {
        String entStr = event.getEntropy().isPresent()
                ? String.format(Locale.ROOT, "Entropy: %.3f", event.getEntropy().get())
                : "Entropy: N/A";
        String changeStr = event.getOldPath().isPresent()
                ? event.getOldPath().get().getFileName() + " -> " + event.getFileName()
                : event.getFileName();

        System.out.printf("[%s] [FILE EVENT] %-7s | %-32s | Size: %6d B | %s%n",
                TIME_FMT.format(event.getTimestamp()),
                event.getType(),
                changeStr,
                event.getFileSize(),
                entStr);
    }

    public void onScoreDecision(ScoreBreakdown breakdown) {
        if (breakdown.isAlert()) {
            System.out.println();
            System.out.println("********************************************************************************");
            System.out.printf(">>> [ALERT TRIGGERED] Score: %.1f/100 (Threshold: 70) Time: %s%n",
                    breakdown.getTotalScore(), TIME_FMT.format(breakdown.getTimestamp()));
            System.out.printf(">>> %s%n", breakdown.getSummary());
            System.out.println("********************************************************************************");
            System.out.println();
        } else {
            System.out.printf("[%s] [SCORE] %.1f/100 | Rate: %.1f/s | AvgEntropy: %.2f (%d samples) | Renames: %d | RansomNotes: %d | Canary: %s%n",
                    TIME_FMT.format(breakdown.getTimestamp()),
                    breakdown.getTotalScore(),
                    breakdown.getFilesPerSecond(),
                    breakdown.getAvgEntropy(),
                    breakdown.getSamplesReadCount(),
                    breakdown.getMassRenamesCount(),
                    breakdown.getRansomNotesCount(),
                    breakdown.isCanaryTouched() ? "BREACHED" : "Safe");
        }
    }

    public void onProcessAction(ProcessActionRecord record) {
        System.out.println();
        System.out.println("================================================================================");
        System.out.printf("[RESPONSE ACTION] %s%n", record.getAction());
        System.out.printf("  Target PID     : %d (via %s)%n", record.getPid(), record.getPidSource());
        System.out.printf("  Process Exe    : %s%n", record.getExePath());
        System.out.printf("  Trigger File   : %s%n", record.getTriggerFile());
        System.out.printf("  Score Reason   : %.1f - %s%n", record.getAlertScore(), record.getReason());
        System.out.printf("  Kill Verified  : %s%n", record.isSuccess() ? "YES" : "NO");
        System.out.println("================================================================================");
        System.out.println();
    }
}

