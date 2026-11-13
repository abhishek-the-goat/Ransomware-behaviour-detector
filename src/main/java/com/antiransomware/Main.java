package com.antiransomware;

import com.antiransomware.canary.CanaryManager;
import com.antiransomware.dashboard.ConsoleDashboard;
import com.antiransomware.dashboard.DashboardApp;
import com.antiransomware.detector.ScoringEngine;
import com.antiransomware.monitor.FolderWatcher;
import com.antiransomware.response.ProcessTerminator;
import com.antiransomware.simulator.RansomwareSimulator;
import javafx.application.Application;

import java.awt.GraphicsEnvironment;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;

public class Main {
    public static void main(String[] args) {
        boolean forceConsole = false;
        boolean forceGui = false;
        boolean runSim = false;
        Path watchDir = Paths.get("target/sandbox").toAbsolutePath().normalize();
        boolean deployCanary = true;

        for (int i = 0; i < args.length; i++) {
            if ("--console".equalsIgnoreCase(args[i])) {
                forceConsole = true;
            } else if ("--gui".equalsIgnoreCase(args[i])) {
                forceGui = true;
            } else if ("--simulate".equalsIgnoreCase(args[i])) {
                runSim = true;
            } else if ("--watch".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                watchDir = Paths.get(args[++i]).toAbsolutePath().normalize();
            } else if ("--no-canary".equalsIgnoreCase(args[i])) {
                deployCanary = false;
            }
        }

        boolean headless = GraphicsEnvironment.isHeadless();

        if (forceGui && !headless) {
            Application.launch(DashboardApp.class, args);
            return;
        }

        if (headless || forceConsole) {
            runConsoleMode(watchDir, deployCanary, runSim);
        } else {
            // Attempt GUI launch
            try {
                Application.launch(DashboardApp.class, args);
            } catch (Throwable t) {
                System.out.println("Could not initialize JavaFX GUI (" + t.getMessage() + "), falling back to console mode.");
                runConsoleMode(watchDir, deployCanary, runSim);
            }
        }
    }

    public static void runConsoleMode(Path watchDir, boolean deployCanary, boolean runSim) {
        ConsoleDashboard console = new ConsoleDashboard();
        console.printBanner();

        System.out.println("Configuring Watcher on folder: " + watchDir);

        CanaryManager canaryManager = new CanaryManager();
        if (deployCanary) {
            canaryManager.deployCanaries(Collections.singletonList(watchDir));
        }

        ScoringEngine scoringEngine = new ScoringEngine();
        scoringEngine.setCanaryPredicate(canaryManager::isCanary);

        Path auditLog = Paths.get("target/audit.log");
        ProcessTerminator terminator = new ProcessTerminator(auditLog);

        FolderWatcher watcher = new FolderWatcher();
        watcher.addFolder(watchDir);

        // Connect pipeline
        watcher.addListener(event -> {
            console.onFileEvent(event);
            scoringEngine.processEvent(event);
        });

        scoringEngine.addDecisionListener(console::onScoreDecision);
        scoringEngine.addDecisionListener(terminator::onScoreUpdate);
        scoringEngine.addAlertListener(breakdown -> {
            var records = terminator.respondToAlert(breakdown, null);
            for (var record : records) {
                console.onProcessAction(record);
            }
            if (breakdown.isCanaryTouched()) {
                // Redeploy a canary automatically after its breach is handled, so the next run has live canaries
                canaryManager.redeployBreachedCanaries();
            }
        });

        try {
            watcher.start();
            System.out.println("System active and monitoring folder. Press Ctrl+C to exit.");

            if (runSim) {
                System.out.println("Running sandboxed ransomware simulation in 1.5 seconds...");
                Thread.sleep(1500);
                RansomwareSimulator simulator = new RansomwareSimulator(watchDir);
                simulator.createDummyFiles(5);
                Thread.sleep(500);
                simulator.simulateAttack(true, 50);
            }

            // Keep main thread alive
            Thread.currentThread().join();
        } catch (InterruptedException e) {
            System.out.println("Shutting down monitor...");
        } catch (Exception e) {
            System.err.println("Fatal error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            watcher.stop();
        }
    }
}

