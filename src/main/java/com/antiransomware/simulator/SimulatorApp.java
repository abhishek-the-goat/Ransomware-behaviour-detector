package com.antiransomware.simulator;

import java.nio.file.Path;
import java.nio.file.Paths;

public class SimulatorApp {
    public static void main(String[] args) {
        System.out.println("=== Safe Ransomware Simulator (Sandbox Mode) ===");
        System.out.println("Simulator PID: " + ProcessHandle.current().pid());

        Path sandbox = Paths.get("target/sandbox");
        boolean dropNote = true;
        int count = 10;
        int delayMs = 50;
        boolean skipCanary = false;

        for (int i = 0; i < args.length; i++) {
            if ("--sandbox".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                sandbox = Paths.get(args[++i]);
            } else if ("--count".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                count = Integer.parseInt(args[++i]);
            } else if ("--delay".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                delayMs = Integer.parseInt(args[++i]);
            } else if ("--skip-canary".equalsIgnoreCase(args[i])) {
                skipCanary = true;
            }
        }

        try {
            RansomwareSimulator simulator = new RansomwareSimulator(sandbox);
            System.out.println("Sandbox verified at: " + simulator.getSandboxFolder());
            simulator.createDummyFiles(count);

            System.out.println("Starting simulated encryption attack inside sandbox in 1 second...");
            Thread.sleep(1000);

            int encrypted = simulator.simulateAttack(dropNote, delayMs, skipCanary);
            System.out.println("Simulated encryption completed. Files encrypted: " + encrypted);
        } catch (SecurityException se) {
            System.err.println("SECURITY CHECK FAILED: " + se.getMessage());
            System.exit(2);
        } catch (Exception e) {
            System.err.println("Simulator error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}

