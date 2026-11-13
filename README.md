# Java Ransomware Behaviour Detector & Active Defense Shield

A high-performance ransomware behaviour detector and active response system built in **Java 17** with **Maven** for Windows environments. It continuously observes target folders for mass-encryption patterns, calculates Shannon entropy on file modifications, detects canary trap tampering, and terminates offending processes via Windows APIs and `ProcessHandle` before damage can spread.

---

## Architecture & Package Structure

The system is structured into dedicated packages:

```
com.antiransomware/
├── monitor/          # Recursive WatchService watcher scoped to configured folders
│   ├── FileEventType.java      (CREATE, MODIFY, RENAME, DELETE)
│   ├── FileEvent.java          (Event payload with timestamps, entropy, PIDs)
│   ├── FileEventListener.java  (Functional listener interface)
│   └── FolderWatcher.java      (Recursive directory registration, debouncing, rename correlation)
│
├── detector/         # Shannon entropy calculator and window scoring engine
│   ├── EntropyCalculator.java   (Shannon entropy: H = -sum(p_i * log2(p_i)))
│   ├── RansomNotePatterns.java  (Regex detection for ransom notes & ransomware extensions)
│   ├── ScoreBreakdown.java      (Detailed scoring metrics & audit formatting)
│   └── ScoringEngine.java       (5-second sliding window scoring, threshold >= 70 = ALERT)
│
├── response/         # Process termination and Windows handle resolution
│   ├── WindowsRestartManager.java (Windows Restart Manager API via JNA for active file lock detection)
│   ├── ProcessActionRecord.java   (Record of process termination decisions)
│   └── ProcessTerminator.java     (Forcible termination via ProcessHandle, exe path resolution, audit log)
│
├── canary/           # Decoy trap generation and monitoring
│   └── CanaryManager.java       (Deploys passwords.docx, photos.zip; write = instant 100 max score)
│
├── simulator/        # Safe sandboxed testing tool
│   ├── RansomwareSimulator.java (AES-256 encryption, .locked renaming, strictly sandboxed)
│   └── SimulatorApp.java        (Standalone subprocess test runner)
│
├── dashboard/        # Live operator interfaces
│   ├── ConsoleDashboard.java    (Real-time formatted console output)
│   └── DashboardApp.java        (JavaFX tables: Events, 5s Scores, Blocked Processes, and Control Panel)
│
└── Main.java         # Unified application entry point (Console / JavaFX auto-fallback)
```

---

## Detection & Scoring Logic

The scoring engine evaluates file operations across a **5-second sliding window**:

| Factor | Description | Weight / Points |
| :--- | :--- | :--- |
| **Canary Decoy Tampering** | Any write, modify, rename, or delete to a canary file (`passwords.docx`, `photos.zip`) | **Instant 100 / 100** (Immediate Alert) |
| **Write Entropy** | Average Shannon entropy of writes: **> 7.5** is suspicious (AES/ciphertext reaches ~7.99, plain text < 5.0) | Up to **35 Points** |
| **Mass Renames / Extensions** | Multiple renames or switching extensions to `.locked`, `.crypto`, `.enc`, etc. | Up to **25 Points** |
| **Modification Rate** | Files modified per second within the 5-second window | Up to **25 Points** |
| **Ransom Note Drop** | Creation of ransom notes matching `README_DECRYPT`, `HOW_TO_DECRYPT`, etc. | Up to **25 Points** |

**Alert Threshold:** When the total score reaches or exceeds **70 / 100**, the system triggers an alert and invokes the `ProcessTerminator`.

---

## Active Response Mechanism & Process Identification

Upon an alert:
1. **Windows Restart Manager API (`rstrtmgr.dll`)**: Queries Windows natively via JNA to determine what process holds active locks or handles to the affected file(s). If found, targets the process with PID attribution source `RESTART_MANAGER`.
2. **Fallback PID Attribution**: When files are quickly closed before the alert (e.g. ransomware closing handles within milliseconds), enumerates `ProcessHandle.allProcesses()` to identify the **youngest process started within 10 seconds before the first suspicious event**, excluding Windows system processes and our own PID. Targets this process with PID attribution source `FALLBACK`.
3. **Immediate Event-Driven Evaluation**: Evaluates the sliding window scoring on every file event rather than waiting for a window timer to expire, ensuring active defense begins immediately upon detection.
4. **ProcessHandle Termination**: Retrieves OS process info (executable path and command line) and calls `ProcessHandle.destroyForcibly()`.
5. **Safety Guards**: Protected processes (PID <= 4, System, and Self PID) are explicitly protected from termination.
6. **Audit Logging**: Every alert and termination is recorded with timestamps, offending PID, PID attribution source (`RESTART_MANAGER` or `FALLBACK`), full executable path, score breakdown, and action taken.

---

## Safety Guarantees (Ransomware Simulator)

- **Strict Sandbox Enforcement**: `RansomwareSimulator` verifies that every path operation is strictly within its designated sandbox directory (`target/sandbox`).
- Any attempt to access or modify paths outside the sandbox immediately throws a `SecurityException`.
- **Never Test Real Ransomware**: The test suite and simulator utilize synthetic AES-256 encryption on dummy text files.

---

## Automated Test Suite (JUnit 5)

All tests can be executed with Maven:
```powershell
.\mvn.cmd test
```

### Verified Test Assertions (25/25 Tests Passing):
1. `EntropyCalculatorTest`:
   - Cryptographic random byte entropy **> 7.9** (empirical: ~7.997).
   - Natural plain text entropy **< 5.0** (empirical: ~4.369).
   - Zero-byte and uniform byte distributions = **0.0**.
   - Entropy of a `.locked` ciphertext file **> 7.5** (empirical: ~7.97).
2. `ScoringEngineTest`:
   - Alert triggers on simulated mass-encryption attack (score **>= 70**).
   - Benign file copy operations remain low-score without alert (**< 70**).
   - Canary file modification results in instant **100/100** alert score while retaining full breakdown metrics.
   - **21 renames in a window scores > 0** (evaluates to max 25.0 points).
   - **A ransom-note filename scores > 0** (evaluates to 25.0 points).
   - **Simulated attack without canary or ransom note crosses threshold before final event** (alerts at file 2/10).
   - 5-second window purges expired events.
3. `RansomwareSimulatorTest`:
   - Throws `SecurityException` if path is outside sandbox folder.
   - Encrypts dummy files with AES producing `.locked` files with entropy **> 7.5**.
   - Drops `README_DECRYPT.txt` safely inside sandbox.
4. `CanaryManagerTest`:
   - Deploys decoy files (`passwords.docx`, `photos.zip`) with valid ZIP/Office headers (`PK\x03\x04`).
   - Tracks, auto-redeploys after breaches, and cleans up deployed canaries.
5. `FolderWatcherTest`:
   - Scopes watching to configured folders only (ignores unscoped directories).
   - Emits events on file creation, modification, and deletion.
6. `ProcessTerminatorTest`:
   - Spawns background process, triggers kill via `ProcessHandle.destroyForcibly()`, verifies termination, and confirms executable path is logged to the audit log.
   - **Fallback PID Attribution**: When `RmGetList` finds no open file handles, enumerates `ProcessHandle.allProcesses()` to attribute and kill the youngest process started within 10s before the event, logging source as `FALLBACK`.
   - **Early Warning Suspect Snapshot**: Captures suspect at score >= 40; handles `ALERT_PROCESS_ALREADY_EXITED` gracefully.
   - **Incident Latch**: Ensures exactly 1 kill attempt per incident latch cycle.
   - Protects system and self PIDs.

---

## Verified Results & Live Demonstrations

The system has been comprehensively verified across both automated regression suites and live end-to-end attacks:

- **25/25 JUnit 5 tests passing** across all modules (`com.antiransomware.*`).
- **Live kill verified twice**:
  - **Canary Run**: Simulator PID 3512 was terminated within milliseconds of touching a decoy canary file, saving 9 out of 10 dummy files unencrypted.
  - **No-Canary Run**: Simulator PID 23072 was killed mid-attack at score **70.3 / 100** via fallback attribution (early-warning suspect snapshot) before completing encryption, with **zero ransom notes dropped** and **canary files completely intact**.
- **Incident Latch**: Exactly 1 kill attempt per incident; subsequent file event spikes are cleanly suppressed to prevent duplicate kills or collateral process damage.
- **JavaFX Dashboard**: Verified rendering with real-time file event stream, entropy indicators (> 7.5 flags), 5-second sliding window score timeline, blocked processes table, and manual canary reset controls.
- **Safety**: Simulator is strictly sandboxed to `target/sandbox` and protected by boundary verification that prevents touching any files outside the sandbox.

---

## Running the Application

### 1. Build and Package
```powershell
.\mvn.cmd clean package
```

### 2. Launch Graphical JavaFX Dashboard
```powershell
.\mvn.cmd exec:java -Dexec.mainClass="com.antiransomware.dashboard.DashboardApp"
```
Or with JavaFX plugin:
```powershell
.\mvn.cmd javafx:run
```

### 3. Launch Console Dashboard
```powershell
.\mvn.cmd exec:java -Dexec.mainClass="com.antiransomware.Main" -Dexec.args="--console --watch target/sandbox"
```

### 4. Run Standalone Safe Simulator (in a second terminal)
```powershell
java -cp "target/ransomware-detector-1.0.0.jar;target/dependency/*" com.antiransomware.simulator.SimulatorApp --sandbox target/sandbox --count 6 --delay 50
```
