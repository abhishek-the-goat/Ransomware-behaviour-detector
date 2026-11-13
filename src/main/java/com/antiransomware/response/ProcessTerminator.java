package com.antiransomware.response;

import com.antiransomware.detector.ScoreBreakdown;
import com.antiransomware.detector.ScoringEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

public class ProcessTerminator {
    private static final Logger logger = LoggerFactory.getLogger(ProcessTerminator.class);
    private static final long CURRENT_PID = ProcessHandle.current().pid();

    static {
        // Pre-warm JNA and native libraries at startup so there is zero latency during alert response
        try {
            if (com.sun.jna.Platform.isWindows()) {
                WindowsRestartManager.findProcessesLockingFile(Path.of("pom.xml"));
                queryProcessImageName(CURRENT_PID);
            }
        } catch (Throwable ignored) {
        }
    }

    private static final Set<String> EXCLUDED_PROCESS_NAMES = Set.of(
            // Browsers (must never be killed)
            "brave.exe", "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", "vivaldi.exe",
            // Shells & Command Line Utilities
            "tasklist.exe", "conhost.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "explorer.exe",
            "wscript.exe", "cscript.exe",
            // Windows System Core
            "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
            "lsass.exe", "svchost.exe", "fontdrvhost.exe", "winlogon.exe", "dwm.exe",
            "spoolsv.exe", "sihost.exe", "taskhostw.exe", "ctfmon.exe", "searchhost.exe",
            "startmenuexperiencehost.exe", "shellexperiencehost.exe", "runtimebroker.exe",
            "textinputhost.exe", "wmiapsrv.exe", "wmiprvse.exe", "dllhost.exe", "audiodg.exe",
            "securityhealthservice.exe", "msmpeng.exe"
    );

    private final List<ProcessActionRecord> actionHistory = new CopyOnWriteArrayList<>();
    private final List<Consumer<ProcessActionRecord>> responseListeners = new CopyOnWriteArrayList<>();
    private final Set<Long> registeredSuspectPids = ConcurrentHashMap.newKeySet();
    private Path auditLogFile;

    // Incident Latch: one alert = one kill attempt per incident
    private final AtomicBoolean incidentActive = new AtomicBoolean(false);
    private volatile Instant incidentStartTime;
    private volatile Instant belowThresholdSince;

    // Suspect Snapshot: captured when score first crosses 40 (early warning)
    private volatile CandidateInfo snapshottedSuspect;

    public record CandidateInfo(ProcessHandle handle, long pid, String exe, Instant start) {}

    public ProcessTerminator() {
        this(null);
    }

    public ProcessTerminator(Path auditLogFile) {
        this.auditLogFile = auditLogFile;
    }

    public void setAuditLogFile(Path auditLogFile) {
        this.auditLogFile = auditLogFile;
    }

    public void registerSuspectPid(long pid) {
        if (pid > 4 && pid != CURRENT_PID) {
            registeredSuspectPids.add(pid);
        }
    }

    public void unregisterSuspectPid(long pid) {
        registeredSuspectPids.remove(pid);
    }

    public void addResponseListener(Consumer<ProcessActionRecord> listener) {
        if (listener != null) {
            responseListeners.add(listener);
        }
    }

    public List<ProcessActionRecord> getActionHistory() {
        return Collections.unmodifiableList(actionHistory);
    }

    public boolean isIncidentActive() {
        return incidentActive.get();
    }

    public synchronized void resetIncidentLatch(String reason) {
        if (incidentActive.getAndSet(false)) {
            logger.info("Incident latch cleared ({}) at {}", reason, Instant.now());
        }
        incidentStartTime = null;
        belowThresholdSince = null;
        snapshottedSuspect = null;
    }

    public CandidateInfo getSnapshottedSuspect() {
        return snapshottedSuspect;
    }

    /**
     * Updates latch status on score evaluation:
     * - Early Warning Suspect Snapshot: when score first rises >= 40, snapshot candidate immediately.
     * - Suppress further responses until score stays below threshold for 10 seconds.
     */
    public synchronized void onScoreUpdate(ScoreBreakdown breakdown) {
        if (breakdown == null) return;

        // Suspect snapshot: when the score first rises above 40 (early warning), snapshot the fallback candidate list immediately
        if (breakdown.getTotalScore() >= 40.0 && snapshottedSuspect == null && !incidentActive.get()) {
            CandidateInfo snapshot = findFallbackCandidateInfo(breakdown);
            if (snapshot != null) {
                this.snapshottedSuspect = snapshot;
                logger.info("Early warning suspect snapshot captured (score: {}/100): PID {} ('{}') started at {}",
                        breakdown.getTotalScore(), snapshot.pid(), snapshot.exe(), snapshot.start());
            }
        }

        if (incidentActive.get()) {
            if (!breakdown.isAlert() && breakdown.getTotalScore() < ScoringEngine.ALERT_THRESHOLD) {
                if (belowThresholdSince == null) {
                    belowThresholdSince = Instant.now();
                } else if (Duration.between(belowThresholdSince, Instant.now()).getSeconds() >= 10) {
                    resetIncidentLatch("Score stayed below threshold for 10 seconds");
                }
            } else {
                // Still alerting or above threshold, reset quiet timer
                belowThresholdSince = null;
            }
        } else if (breakdown.getTotalScore() < 40.0 && snapshottedSuspect != null) {
            // If score drops below early warning threshold, discard stale snapshot
            snapshottedSuspect = null;
        }
    }

    /**
     * Responds to an alert by identifying and killing the offending process.
     * Enforces the Incident Latch: One alert = one kill attempt per incident.
     */
    public synchronized List<ProcessActionRecord> respondToAlert(ScoreBreakdown breakdown, Long explicitPid) {
        List<ProcessActionRecord> results = new ArrayList<>();
        if (breakdown == null || !breakdown.isAlert()) {
            return results;
        }

        // Incident latch: after the first response for an incident, suppress further responses
        if (incidentActive.get()) {
            logger.warn("Alert received but suppressed by active incident latch (incident initiated at {}). One kill attempt per incident.", incidentStartTime);
            ProcessActionRecord suppressed = new ProcessActionRecord(
                    Instant.now(), -1, "LATCH_SUPPRESSED", "incident_active", "suppressed",
                    breakdown.getTotalScore(), breakdown.getTriggerFile(),
                    "Suppressed by incident latch - kill already attempted for this incident",
                    "SUPPRESSED_INCIDENT_LATCH", false
            );
            recordAction(suppressed);
            results.add(suppressed);
            return results;
        }

        Map<Long, String> candidatePids = new LinkedHashMap<>();

        // 1. Explicit PID if provided
        if (explicitPid != null && explicitPid > 4 && explicitPid != CURRENT_PID) {
            candidatePids.put(explicitPid, "EXPLICIT");
        }

        // 2. Any registered suspect PIDs (e.g. from simulator or active runner)
        for (Long pid : registeredSuspectPids) {
            candidatePids.put(pid, "REGISTERED");
        }

        // 3. Find processes actively locking the trigger file via Windows Restart Manager
        if (breakdown.getTriggerFile() != null && Files.exists(breakdown.getTriggerFile())) {
            List<Long> lockingPids = WindowsRestartManager.findProcessesLockingFile(breakdown.getTriggerFile());
            for (Long pid : lockingPids) {
                if (pid > 4 && pid != CURRENT_PID && !isExcludedPid(pid)) {
                    candidatePids.put(pid, "RESTART_MANAGER");
                }
            }
        }

        // 4. Fallback PID attribution if Restart Manager found nothing
        if (candidatePids.isEmpty()) {
            if (snapshottedSuspect != null) {
                // Use early-warning suspect snapshot captured when score first crossed 40
                long snapPid = snapshottedSuspect.pid();
                Optional<ProcessHandle> handleOpt = ProcessHandle.of(snapPid);
                if (handleOpt.isPresent() && handleOpt.get().isAlive()) {
                    candidatePids.put(snapPid, "FALLBACK");
                    logger.warn("Identified offending process via early-warning suspect snapshot: PID {}", snapPid);
                } else {
                    // Snapshotted process has already exited
                    logger.warn("Offending process PID {} ('{}') snapshotted during early warning has already exited.",
                            snapPid, snapshottedSuspect.exe());
                    ProcessActionRecord record = new ProcessActionRecord(
                            Instant.now(), snapPid, "SNAPSHOT_EXITED",
                            extractProcessName(snapshottedSuspect.exe()), snapshottedSuspect.exe(),
                            breakdown.getTotalScore(), breakdown.getTriggerFile(),
                            breakdown.getSummary(), "ALERT_PROCESS_ALREADY_EXITED", false
                    );
                    recordAction(record);
                    results.add(record);
                    return results;
                }
            } else {
                Long fallbackPid = findFallbackOffendingProcess(breakdown);
                if (fallbackPid != null) {
                    candidatePids.put(fallbackPid, "FALLBACK");
                    logger.warn("Identified offending process via FALLBACK attribution: PID {}", fallbackPid);
                }
            }
        }

        if (candidatePids.isEmpty()) {
            ProcessActionRecord record = new ProcessActionRecord(
                    Instant.now(), -1, "NONE", "unknown", "unknown",
                    breakdown.getTotalScore(), breakdown.getTriggerFile(),
                    breakdown.getSummary(), "ALERT_NO_LOCKING_PROCESS_FOUND", false
            );
            recordAction(record);
            results.add(record);
            return results;
        }

        // Engage incident latch now that kill response is starting
        incidentActive.set(true);
        incidentStartTime = Instant.now();
        belowThresholdSince = null;

        for (Map.Entry<Long, String> entry : candidatePids.entrySet()) {
            long pid = entry.getKey();
            String pidSource = entry.getValue();
            ProcessActionRecord record = killProcess(pid, pidSource, breakdown.getTotalScore(),
                    breakdown.getTriggerFile(), breakdown.getSummary());
            results.add(record);
        }

        return results;
    }

    /**
     * Fallback PID attribution:
     * Enumerate ProcessHandle.allProcesses():
     * - Candidates must have started BEFORE the first suspicious event (never after), within 10s before it.
     * - Exclude browsers, shells, utilities, system processes, and our own PID.
     * - Log the full candidate list (PID, exe, start time).
     * - Prefer java.exe processes started within 10s before the first suspicious event.
     */
    public Long findFallbackOffendingProcess(ScoreBreakdown breakdown) {
        CandidateInfo chosen = findFallbackCandidateInfo(breakdown);
        if (chosen != null) {
            logger.info("Selected offending process via FALLBACK: PID {} ('{}') started at {}",
                    chosen.pid(), chosen.exe(), chosen.start());
            return chosen.pid();
        }
        return null;
    }

    public CandidateInfo findFallbackCandidateInfo(ScoreBreakdown breakdown) {
        Instant firstSuspicious = breakdown != null ? breakdown.getFirstSuspiciousEventTime() : null;
        if (firstSuspicious == null) {
            firstSuspicious = breakdown != null && breakdown.getTimestamp() != null
                    ? breakdown.getTimestamp()
                    : Instant.now();
        }

        Instant cutoff = firstSuspicious.minusSeconds(10);

        List<CandidateInfo> candidates = new ArrayList<>();

        for (ProcessHandle ph : ProcessHandle.allProcesses().toList()) {
            long pid = ph.pid();
            if (pid <= 4 || pid == CURRENT_PID) {
                continue;
            }

            Optional<Instant> startOpt = ph.info().startInstant();
            if (startOpt.isEmpty()) {
                continue;
            }

            Instant start = startOpt.get();
            // Candidates MUST have started BEFORE or at the first suspicious event (never after)
            // and within 10 seconds before it.
            if (!start.isAfter(cutoff) || start.isAfter(firstSuspicious)) {
                continue;
            }

            if (isExcludedProcess(ph)) {
                continue;
            }

            String exe = getExecutablePath(ph);
            if ("unknown".equalsIgnoreCase(exe) && snapshottedSuspect != null && snapshottedSuspect.pid() == pid) {
                exe = snapshottedSuspect.exe();
            }
            candidates.add(new CandidateInfo(ph, pid, exe, start));
        }

        // Log the full candidate list so the choice is completely auditable
        logger.info("Fallback PID attribution evaluated {} candidate processes (started between {} and {}):",
                candidates.size(), cutoff, firstSuspicious);
        for (CandidateInfo c : candidates) {
            logger.info("  -> Candidate PID={}: exe='{}', started={}", c.pid, c.exe, c.start);
        }

        if (candidates.isEmpty()) {
            logger.warn("No fallback candidates started between {} and {}", cutoff, firstSuspicious);
            return null;
        }

        // Prefer java.exe processes started within 10s before the first suspicious event
        List<CandidateInfo> javaCandidates = candidates.stream()
                .filter(c -> {
                    String name = extractProcessName(c.exe()).toLowerCase(Locale.ROOT);
                    return name.equals("java.exe") || name.equals("javaw.exe") || name.equals("java");
                })
                .toList();

        List<CandidateInfo> selectionPool = !javaCandidates.isEmpty() ? javaCandidates : candidates;

        // Pick the youngest process in the selection pool (latest start time)
        return selectionPool.stream()
                .max(Comparator.comparing(CandidateInfo::start).thenComparingLong(CandidateInfo::pid))
                .orElse(null);
    }

    private boolean isExcludedPid(long pid) {
        return ProcessHandle.of(pid).map(this::isExcludedProcess).orElse(false);
    }

    public boolean isExcludedProcess(ProcessHandle ph) {
        long pid = ph.pid();
        if (pid <= 4 || pid == CURRENT_PID) {
            return true;
        }

        // Exclude parent and ancestors of current process (e.g. Maven, IDE, CLI harness)
        ProcessHandle parent = ProcessHandle.current().parent().orElse(null);
        while (parent != null) {
            if (parent.pid() == pid) {
                return true;
            }
            try {
                parent = parent.parent().orElse(null);
            } catch (Exception e) {
                break;
            }
        }

        String cmd = getExecutablePath(ph).toLowerCase(Locale.ROOT);
        String name = extractProcessName(cmd).toLowerCase(Locale.ROOT);

        if (EXCLUDED_PROCESS_NAMES.contains(name)) {
            return true;
        }

        return false;
    }

    public static String getExecutablePath(ProcessHandle ph) {
        if (ph == null) return "unknown";
        ProcessHandle.Info info = ph.info();
        if (info.command().isPresent() && !info.command().get().isBlank()) {
            return info.command().get();
        }
        if (info.commandLine().isPresent() && !info.commandLine().get().isBlank()) {
            return info.commandLine().get();
        }
        // JNA query for Windows when ProcessHandle has empty command
        long pid = ph.pid();
        String nativeExe = queryProcessImageName(pid);
        if (!nativeExe.isBlank()) {
            return nativeExe;
        }
        return "unknown";
    }

    private static String queryProcessImageName(long pid) {
        if (!com.sun.jna.Platform.isWindows()) return "";
        try {
            com.sun.jna.platform.win32.WinNT.HANDLE h =
                    com.sun.jna.platform.win32.Kernel32.INSTANCE.OpenProcess(0x1000, false, (int) pid);
            if (h == null) return "";
            try {
                char[] buf = new char[1024];
                com.sun.jna.ptr.IntByReference len = new com.sun.jna.ptr.IntByReference(buf.length);
                if (com.sun.jna.platform.win32.Kernel32.INSTANCE.QueryFullProcessImageName(h, 0, buf, len)) {
                    return new String(buf, 0, len.getValue());
                }
            } finally {
                com.sun.jna.platform.win32.Kernel32.INSTANCE.CloseHandle(h);
            }
        } catch (Throwable ignored) {
        }
        return "";
    }

    public ProcessActionRecord killProcess(long pid, double score, Path triggerFile, String reason) {
        return killProcess(pid, "UNKNOWN", score, triggerFile, reason);
    }

    /**
     * Kills a process by PID via ProcessHandle, records its executable path and logs the action.
     */
    public ProcessActionRecord killProcess(long pid, String pidSource, double score, Path triggerFile, String reason) {
        Instant now = Instant.now();
        if (pid <= 4 || pid == CURRENT_PID) {
            logger.warn("Refusing to terminate protected PID: {}", pid);
            return new ProcessActionRecord(now, pid, pidSource, "system/self", "protected",
                    score, triggerFile, reason, "PROTECTED_SKIPPED", false);
        }

        Optional<ProcessHandle> handleOpt = ProcessHandle.of(pid);
        if (handleOpt.isEmpty()) {
            return new ProcessActionRecord(now, pid, pidSource, "not_found", "unknown",
                    score, triggerFile, reason, "PROCESS_NOT_FOUND", false);
        }

        ProcessHandle handle = handleOpt.get();
        ProcessHandle.Info info = handle.info();
        String exePath = info.command().orElse(info.commandLine().orElse("unknown.exe"));
        String procName = extractProcessName(exePath);

        // Destroy descendants then process itself
        try {
            handle.descendants().forEach(ProcessHandle::destroyForcibly);
        } catch (Exception ignored) {
        }
        boolean destroyed = handle.destroyForcibly();

        // Verify termination
        boolean killed = false;
        try {
            for (int i = 0; i < 25; i++) {
                if (!handle.isAlive()) {
                    killed = true;
                    break;
                }
                Thread.sleep(60);
            }
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }

        killed = killed || !handle.isAlive();

        String action = killed ? "TERMINATED_FORCIBLY" : (destroyed ? "TERMINATE_SIGNALED" : "TERMINATION_FAILED");
        ProcessActionRecord record = new ProcessActionRecord(
                now, pid, pidSource, procName, exePath, score, triggerFile, reason, action, killed
        );

        logger.warn("\n{}", record.formattedLog());
        recordAction(record);
        return record;
    }

    private String extractProcessName(String exePath) {
        if (exePath == null || exePath.isBlank()) return "unknown";
        int idx = Math.max(exePath.lastIndexOf('/'), exePath.lastIndexOf('\\'));
        return (idx >= 0 && idx < exePath.length() - 1) ? exePath.substring(idx + 1) : exePath;
    }

    private void recordAction(ProcessActionRecord record) {
        actionHistory.add(record);

        // Notify listeners
        for (Consumer<ProcessActionRecord> listener : responseListeners) {
            try {
                listener.accept(record);
            } catch (Exception e) {
                logger.error("Error in responseListener", e);
            }
        }

        // Persist to audit log if configured
        if (auditLogFile != null) {
            try {
                if (auditLogFile.getParent() != null && !Files.exists(auditLogFile.getParent())) {
                    Files.createDirectories(auditLogFile.getParent());
                }
                String line = record.formattedLog() + System.lineSeparator();
                Files.writeString(auditLogFile, line,
                        StandardOpenOption.CREATE,
                        StandardOpenOption.APPEND,
                        StandardOpenOption.WRITE);
            } catch (IOException e) {
                logger.error("Failed to write to audit log file: {}", auditLogFile, e);
            }
        }
    }
}
