package com.antiransomware.dashboard;

import com.antiransomware.canary.CanaryManager;
import com.antiransomware.detector.ScoreBreakdown;
import com.antiransomware.detector.ScoringEngine;
import com.antiransomware.monitor.FileEvent;
import com.antiransomware.monitor.FolderWatcher;
import com.antiransomware.response.ProcessActionRecord;
import com.antiransomware.response.ProcessTerminator;
import com.antiransomware.simulator.RansomwareSimulator;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.stage.DirectoryChooser;
import javafx.stage.Stage;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.Locale;

public class DashboardApp extends Application {
    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("HH:mm:ss.SSS").withZone(ZoneId.systemDefault());

    // Core components
    private FolderWatcher folderWatcher;
    private ScoringEngine scoringEngine;
    private CanaryManager canaryManager;
    private ProcessTerminator processTerminator;
    private RansomwareSimulator simulator;

    // Observable data for tables
    private final ObservableList<EventItem> eventList = FXCollections.observableArrayList();
    private final ObservableList<ScoreItem> scoreList = FXCollections.observableArrayList();
    private final ObservableList<BlockedProcessItem> blockedList = FXCollections.observableArrayList();

    // UI elements
    private Label statusLabel;
    private Label scoreMetricLabel;
    private Label eventsMetricLabel;
    private Label blockedMetricLabel;
    private TextArea logArea;
    private TextField folderField;
    private Button watchToggleButton;

    private Path currentWatchFolder;
    private Path sandboxFolder;
    private int eventCount = 0;
    private int blockedCount = 0;

    public static class EventItem {
        private final SimpleStringProperty time;
        private final SimpleStringProperty type;
        private final SimpleStringProperty fileName;
        private final SimpleStringProperty fileSize;
        private final SimpleStringProperty entropy;
        private final SimpleStringProperty status;

        public EventItem(String time, String type, String fileName, String fileSize, String entropy, String status) {
            this.time = new SimpleStringProperty(time);
            this.type = new SimpleStringProperty(type);
            this.fileName = new SimpleStringProperty(fileName);
            this.fileSize = new SimpleStringProperty(fileSize);
            this.entropy = new SimpleStringProperty(entropy);
            this.status = new SimpleStringProperty(status);
        }

        public String getTime() { return time.get(); }
        public String getType() { return type.get(); }
        public String getFileName() { return fileName.get(); }
        public String getFileSize() { return fileSize.get(); }
        public String getEntropy() { return entropy.get(); }
        public String getStatus() { return status.get(); }
    }

    public static class ScoreItem {
        private final SimpleStringProperty time;
        private final SimpleStringProperty score;
        private final SimpleStringProperty rate;
        private final SimpleStringProperty avgEntropy;
        private final SimpleStringProperty renames;
        private final SimpleStringProperty ransomNotes;
        private final SimpleStringProperty canary;
        private final SimpleStringProperty decision;

        public ScoreItem(String time, String score, String rate, String avgEntropy,
                         String renames, String ransomNotes, String canary, String decision) {
            this.time = new SimpleStringProperty(time);
            this.score = new SimpleStringProperty(score);
            this.rate = new SimpleStringProperty(rate);
            this.avgEntropy = new SimpleStringProperty(avgEntropy);
            this.renames = new SimpleStringProperty(renames);
            this.ransomNotes = new SimpleStringProperty(ransomNotes);
            this.canary = new SimpleStringProperty(canary);
            this.decision = new SimpleStringProperty(decision);
        }

        public String getTime() { return time.get(); }
        public String getScore() { return score.get(); }
        public String getRate() { return rate.get(); }
        public String getAvgEntropy() { return avgEntropy.get(); }
        public String getRenames() { return renames.get(); }
        public String getRansomNotes() { return ransomNotes.get(); }
        public String getCanary() { return canary.get(); }
        public String getDecision() { return decision.get(); }
    }

    public static class BlockedProcessItem {
        private final SimpleStringProperty time;
        private final SimpleStringProperty pid;
        private final SimpleStringProperty source;
        private final SimpleStringProperty name;
        private final SimpleStringProperty path;
        private final SimpleStringProperty score;
        private final SimpleStringProperty action;
        private final SimpleStringProperty success;

        public BlockedProcessItem(String time, String pid, String source, String name, String path,
                                  String score, String action, String success) {
            this.time = new SimpleStringProperty(time);
            this.pid = new SimpleStringProperty(pid);
            this.source = new SimpleStringProperty(source);
            this.name = new SimpleStringProperty(name);
            this.path = new SimpleStringProperty(path);
            this.score = new SimpleStringProperty(score);
            this.action = new SimpleStringProperty(action);
            this.success = new SimpleStringProperty(success);
        }

        public String getTime() { return time.get(); }
        public String getPid() { return pid.get(); }
        public String getSource() { return source.get(); }
        public String getName() { return name.get(); }
        public String getPath() { return path.get(); }
        public String getScore() { return score.get(); }
        public String getAction() { return action.get(); }
        public String getSuccess() { return success.get(); }
    }

    @Override
    public void init() {
        // Initialize default core components
        this.canaryManager = new CanaryManager();
        this.scoringEngine = new ScoringEngine();
        this.scoringEngine.setCanaryPredicate(canaryManager::isCanary);
        this.processTerminator = new ProcessTerminator(Paths.get("target/audit.log"));
        this.folderWatcher = new FolderWatcher();

        // Default folders
        this.sandboxFolder = Paths.get("target/sandbox").toAbsolutePath().normalize();
        this.currentWatchFolder = sandboxFolder;
        this.simulator = new RansomwareSimulator(sandboxFolder);

        // Wire event pipeline
        wireListeners();
    }

    public void configureComponents(FolderWatcher watcher, ScoringEngine engine,
                                    CanaryManager canary, ProcessTerminator terminator,
                                    RansomwareSimulator sim) {
        this.folderWatcher = watcher;
        this.scoringEngine = engine;
        this.canaryManager = canary;
        this.processTerminator = terminator;
        this.simulator = sim;
        wireListeners();
    }

    private void wireListeners() {
        if (folderWatcher != null) {
            folderWatcher.addListener(this::handleIncomingFileEvent);
        }

        if (scoringEngine != null) {
            scoringEngine.addDecisionListener(this::handleScoreBreakdown);
            if (processTerminator != null) {
                scoringEngine.addDecisionListener(processTerminator::onScoreUpdate);
            }
            scoringEngine.addAlertListener(breakdown -> {
                if (processTerminator != null) {
                    processTerminator.respondToAlert(breakdown, null);
                }
                if (canaryManager != null && breakdown.isCanaryTouched()) {
                    canaryManager.redeployBreachedCanaries();
                }
            });
        }

        if (processTerminator != null) {
            processTerminator.addResponseListener(this::handleProcessBlocked);
        }
    }

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("Java Ransomware Behaviour Detector & Response Shield");

        BorderPane root = new BorderPane();
        root.setPadding(new Insets(12));
        root.setStyle("-fx-background-color: #1e1e24; -fx-font-family: 'Segoe UI', sans-serif;");

        // Top Header and Metrics
        VBox topBox = createHeaderAndMetrics();
        root.setTop(topBox);

        // Center: TabPane with Tables
        TabPane tabPane = createTabPane();
        root.setCenter(tabPane);

        // Bottom: Controls and Console Log
        VBox bottomBox = createControlsAndLogArea(primaryStage);
        root.setBottom(bottomBox);

        Scene scene = new Scene(root, 1050, 750);
        primaryStage.setScene(scene);
        primaryStage.setOnCloseRequest(e -> {
            if (folderWatcher != null) {
                folderWatcher.stop();
            }
        });
        primaryStage.show();

        // Start watcher initially on sandbox folder
        toggleWatcher();
    }

    private VBox createHeaderAndMetrics() {
        VBox box = new VBox(10);
        box.setPadding(new Insets(0, 0, 12, 0));

        Label title = new Label("SHIELD: RANSOMWARE BEHAVIOUR DETECTOR & ACTIVE DEFENSE");
        title.setStyle("-fx-text-fill: #e0e0e0; -fx-font-size: 18px; -fx-font-weight: bold;");

        HBox metricsRow = new HBox(15);
        metricsRow.setAlignment(Pos.CENTER_LEFT);

        statusLabel = createMetricCard("MONITOR STATUS", "IDLE", "#2196F3");
        scoreMetricLabel = createMetricCard("CURRENT 5s SCORE", "0.0 / 100", "#4CAF50");
        eventsMetricLabel = createMetricCard("EVENTS OBSERVED", "0", "#9C27B0");
        blockedMetricLabel = createMetricCard("ATTACKS BLOCKED", "0", "#F44336");

        metricsRow.getChildren().addAll(statusLabel.getParent(), scoreMetricLabel.getParent(),
                eventsMetricLabel.getParent(), blockedMetricLabel.getParent());

        box.getChildren().addAll(title, metricsRow);
        return box;
    }

    private Label createMetricCard(String title, String initialValue, String accentColor) {
        VBox card = new VBox(4);
        card.setPadding(new Insets(8, 14, 8, 14));
        card.setStyle("-fx-background-color: #2b2b36; -fx-background-radius: 6; -fx-border-color: " + accentColor + "; -fx-border-width: 0 0 0 4;");
        card.setPrefWidth(220);

        Label titleLbl = new Label(title);
        titleLbl.setStyle("-fx-text-fill: #9e9ea7; -fx-font-size: 11px; -fx-font-weight: bold;");

        Label valLbl = new Label(initialValue);
        valLbl.setStyle("-fx-text-fill: #ffffff; -fx-font-size: 16px; -fx-font-weight: bold;");

        card.getChildren().addAll(titleLbl, valLbl);
        return valLbl;
    }

    private TabPane createTabPane() {
        TabPane tabPane = new TabPane();
        tabPane.setTabClosingPolicy(TabPane.TabClosingPolicy.UNAVAILABLE);

        // Tab 1: File Events
        Tab eventsTab = new Tab("Live File Events");
        TableView<EventItem> eventsTable = new TableView<>(eventList);
        setupEventsTable(eventsTable);
        eventsTab.setContent(eventsTable);

        // Tab 2: 5-Second Window Scores
        Tab scoresTab = new Tab("Window Scoring (5s)");
        TableView<ScoreItem> scoresTable = new TableView<>(scoreList);
        setupScoresTable(scoresTable);
        scoresTab.setContent(scoresTable);

        // Tab 3: Blocked Offending Processes
        Tab blockedTab = new Tab("Blocked Processes");
        TableView<BlockedProcessItem> blockedTable = new TableView<>(blockedList);
        setupBlockedTable(blockedTable);
        blockedTab.setContent(blockedTable);

        tabPane.getTabs().addAll(eventsTab, scoresTab, blockedTab);
        return tabPane;
    }

    private void setupEventsTable(TableView<EventItem> table) {
        TableColumn<EventItem, String> colTime = new TableColumn<>("Time");
        colTime.setCellValueFactory(c -> c.getValue().time);
        colTime.setPrefWidth(100);

        TableColumn<EventItem, String> colType = new TableColumn<>("Event Type");
        colType.setCellValueFactory(c -> c.getValue().type);
        colType.setPrefWidth(90);

        TableColumn<EventItem, String> colFile = new TableColumn<>("File Name / Change");
        colFile.setCellValueFactory(c -> c.getValue().fileName);
        colFile.setPrefWidth(380);

        TableColumn<EventItem, String> colSize = new TableColumn<>("Size (Bytes)");
        colSize.setCellValueFactory(c -> c.getValue().fileSize);
        colSize.setPrefWidth(100);

        TableColumn<EventItem, String> colEntropy = new TableColumn<>("Shannon Entropy");
        colEntropy.setCellValueFactory(c -> c.getValue().entropy);
        colEntropy.setPrefWidth(120);

        TableColumn<EventItem, String> colStatus = new TableColumn<>("Entropy Flag");
        colStatus.setCellValueFactory(c -> c.getValue().status);
        colStatus.setPrefWidth(150);

        table.getColumns().addAll(colTime, colType, colFile, colSize, colEntropy, colStatus);
    }

    private void setupScoresTable(TableView<ScoreItem> table) {
        TableColumn<ScoreItem, String> colTime = new TableColumn<>("Time");
        colTime.setCellValueFactory(c -> c.getValue().time);
        colTime.setPrefWidth(100);

        TableColumn<ScoreItem, String> colScore = new TableColumn<>("Score (/100)");
        colScore.setCellValueFactory(c -> c.getValue().score);
        colScore.setPrefWidth(90);

        TableColumn<ScoreItem, String> colRate = new TableColumn<>("Rate (files/s)");
        colRate.setCellValueFactory(c -> c.getValue().rate);
        colRate.setPrefWidth(100);

        TableColumn<ScoreItem, String> colAvgEntropy = new TableColumn<>("Avg Entropy");
        colAvgEntropy.setCellValueFactory(c -> c.getValue().avgEntropy);
        colAvgEntropy.setPrefWidth(100);

        TableColumn<ScoreItem, String> colRenames = new TableColumn<>("Mass Renames");
        colRenames.setCellValueFactory(c -> c.getValue().renames);
        colRenames.setPrefWidth(110);

        TableColumn<ScoreItem, String> colNotes = new TableColumn<>("Ransom Notes");
        colNotes.setCellValueFactory(c -> c.getValue().ransomNotes);
        colNotes.setPrefWidth(100);

        TableColumn<ScoreItem, String> colCanary = new TableColumn<>("Canary");
        colCanary.setCellValueFactory(c -> c.getValue().canary);
        colCanary.setPrefWidth(90);

        TableColumn<ScoreItem, String> colDecision = new TableColumn<>("Decision");
        colDecision.setCellValueFactory(c -> c.getValue().decision);
        colDecision.setPrefWidth(250);

        table.getColumns().addAll(colTime, colScore, colRate, colAvgEntropy, colRenames, colNotes, colCanary, colDecision);
    }

    private void setupBlockedTable(TableView<BlockedProcessItem> table) {
        TableColumn<BlockedProcessItem, String> colTime = new TableColumn<>("Time");
        colTime.setCellValueFactory(c -> c.getValue().time);
        colTime.setPrefWidth(100);

        TableColumn<BlockedProcessItem, String> colPid = new TableColumn<>("PID");
        colPid.setCellValueFactory(c -> c.getValue().pid);
        colPid.setPrefWidth(80);

        TableColumn<BlockedProcessItem, String> colSource = new TableColumn<>("Attribution");
        colSource.setCellValueFactory(c -> c.getValue().source);
        colSource.setPrefWidth(120);

        TableColumn<BlockedProcessItem, String> colName = new TableColumn<>("Process Name");
        colName.setCellValueFactory(c -> c.getValue().name);
        colName.setPrefWidth(140);

        TableColumn<BlockedProcessItem, String> colPath = new TableColumn<>("Executable Path");
        colPath.setCellValueFactory(c -> c.getValue().path);
        colPath.setPrefWidth(260);

        TableColumn<BlockedProcessItem, String> colScore = new TableColumn<>("Trigger Score");
        colScore.setCellValueFactory(c -> c.getValue().score);
        colScore.setPrefWidth(90);

        TableColumn<BlockedProcessItem, String> colAction = new TableColumn<>("Action Taken");
        colAction.setCellValueFactory(c -> c.getValue().action);
        colAction.setPrefWidth(150);

        table.getColumns().addAll(colTime, colPid, colSource, colName, colPath, colScore, colAction);
    }

    private VBox createControlsAndLogArea(Stage stage) {
        VBox bottom = new VBox(8);
        bottom.setPadding(new Insets(10, 0, 0, 0));

        // Folder selection row
        HBox folderRow = new HBox(8);
        folderRow.setAlignment(Pos.CENTER_LEFT);

        Label folderLbl = new Label("Watch Folder:");
        folderLbl.setStyle("-fx-text-fill: #cccccc;");

        folderField = new TextField(currentWatchFolder.toString());
        folderField.setPrefWidth(450);

        Button browseBtn = new Button("Browse...");
        browseBtn.setOnAction(e -> {
            DirectoryChooser dc = new DirectoryChooser();
            dc.setTitle("Select Folder to Watch");
            dc.setInitialDirectory(new File("."));
            File chosen = dc.showDialog(stage);
            if (chosen != null) {
                folderField.setText(chosen.getAbsolutePath());
                updateWatchFolder(chosen.toPath());
            }
        });

        watchToggleButton = new Button("Stop Watcher");
        watchToggleButton.setStyle("-fx-background-color: #d32f2f; -fx-text-fill: white; -fx-font-weight: bold;");
        watchToggleButton.setOnAction(e -> toggleWatcher());

        folderRow.getChildren().addAll(folderLbl, folderField, browseBtn, watchToggleButton);

        // Simulation actions row
        HBox simRow = new HBox(10);
        simRow.setAlignment(Pos.CENTER_LEFT);

        Button deployCanaryBtn = new Button("Deploy Canaries");
        deployCanaryBtn.setOnAction(e -> {
            if (canaryManager != null && currentWatchFolder != null) {
                canaryManager.deployCanaries(Collections.singletonList(currentWatchFolder));
                appendLog("Deployed decoy canaries in " + currentWatchFolder);
            }
        });

        Button runAttackBtn = new Button("Simulate Attack (Sandbox Only)");
        runAttackBtn.setStyle("-fx-background-color: #f57c00; -fx-text-fill: white; -fx-font-weight: bold;");
        runAttackBtn.setOnAction(e -> triggerSimulatedAttack());

        Button runNormalBtn = new Button("Normal File Copy (Benign)");
        runNormalBtn.setOnAction(e -> triggerNormalFileCopy());

        Button clearBtn = new Button("Clear Logs");
        clearBtn.setOnAction(e -> {
            eventList.clear();
            scoreList.clear();
            blockedList.clear();
            logArea.clear();
            eventCount = 0;
            eventsMetricLabel.setText("0");
        });

        simRow.getChildren().addAll(deployCanaryBtn, runAttackBtn, runNormalBtn, clearBtn);

        // Log Console
        logArea = new TextArea();
        logArea.setEditable(false);
        logArea.setPrefRowCount(6);
        logArea.setStyle("-fx-control-inner-background: #121216; -fx-font-family: 'Consolas', monospace; -fx-text-fill: #a9b7c6;");

        bottom.getChildren().addAll(folderRow, simRow, logArea);
        return bottom;
    }

    private void toggleWatcher() {
        try {
            if (folderWatcher.isRunning()) {
                folderWatcher.stop();
                watchToggleButton.setText("Start Watcher");
                watchToggleButton.setStyle("-fx-background-color: #388e3c; -fx-text-fill: white; -fx-font-weight: bold;");
                statusLabel.setText("STOPPED");
                statusLabel.setTextFill(Color.GRAY);
                appendLog("Folder watcher stopped.");
            } else {
                Path target = Paths.get(folderField.getText().trim());
                updateWatchFolder(target);
                folderWatcher.start();
                watchToggleButton.setText("Stop Watcher");
                watchToggleButton.setStyle("-fx-background-color: #d32f2f; -fx-text-fill: white; -fx-font-weight: bold;");
                statusLabel.setText("ACTIVE");
                statusLabel.setTextFill(Color.web("#4CAF50"));
                appendLog("Folder watcher started on: " + target);
            }
        } catch (Exception ex) {
            appendLog("Error toggling watcher: " + ex.getMessage());
        }
    }

    private void updateWatchFolder(Path newFolder) {
        if (folderWatcher != null) {
            folderWatcher.removeFolder(currentWatchFolder);
            this.currentWatchFolder = newFolder.toAbsolutePath().normalize();
            folderWatcher.addFolder(currentWatchFolder);
        }
    }

    private void triggerSimulatedAttack() {
        new Thread(() -> {
            try {
                appendLog(">>> Starting Safe Ransomware Simulation strictly in sandbox: " + sandboxFolder);
                simulator.createDummyFiles(6);
                Thread.sleep(600);
                int encrypted = simulator.simulateAttack(true, 50);
                appendLog(">>> Simulation completed. Encrypted " + encrypted + " files with .locked & dropped ransom note.");
            } catch (Exception ex) {
                appendLog("Simulation error: " + ex.getMessage());
            }
        }, "SimulatorThread").start();
    }

    private void triggerNormalFileCopy() {
        new Thread(() -> {
            try {
                appendLog(">>> Performing normal harmless file writing inside sandbox...");
                for (int i = 1; i <= 3; i++) {
                    Path normalFile = sandboxFolder.resolve("normal_document_" + i + ".txt");
                    simulator.validateSandboxPath(normalFile);
                    String benignContent = "Standard office text document.\nNormal entropy English text for review.\nNumber: " + i;
                    Files.writeString(normalFile, benignContent, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                    Thread.sleep(200);
                }
                appendLog(">>> Normal file copy finished. Entropy remains low (<5).");
            } catch (Exception ex) {
                appendLog("Normal copy error: " + ex.getMessage());
            }
        }, "NormalCopyThread").start();
    }

    private void handleIncomingFileEvent(FileEvent event) {
        // Forward to scoring engine
        ScoreBreakdown breakdown = scoringEngine.processEvent(event);

        Platform.runLater(() -> {
            eventCount++;
            eventsMetricLabel.setText(String.valueOf(eventCount));

            String timeStr = TIME_FMT.format(event.getTimestamp());
            String entStr = event.getEntropy().map(e -> String.format(Locale.ROOT, "%.3f", e)).orElse("N/A");
            String status = "Normal";
            if (event.getEntropy().isPresent() && event.getEntropy().get() > 7.5) {
                status = "HIGH ENTROPY (>7.5)";
            }

            String fileChange = event.getOldPath().map(p -> p.getFileName() + " -> ").orElse("") + event.getFileName();
            EventItem item = new EventItem(timeStr, event.getType().name(), fileChange,
                    String.valueOf(event.getFileSize()), entStr, status);
            eventList.add(0, item);
            if (eventList.size() > 500) {
                eventList.remove(eventList.size() - 1);
            }
        });
    }

    private void handleScoreBreakdown(ScoreBreakdown breakdown) {
        Platform.runLater(() -> {
            double score = breakdown.getTotalScore();
            scoreMetricLabel.setText(String.format(Locale.ROOT, "%.1f / 100", score));
            if (score >= 70) {
                scoreMetricLabel.setTextFill(Color.web("#F44336"));
            } else if (score >= 40) {
                scoreMetricLabel.setTextFill(Color.web("#FF9800"));
            } else {
                scoreMetricLabel.setTextFill(Color.web("#4CAF50"));
            }

            String timeStr = TIME_FMT.format(breakdown.getTimestamp());
            String scoreStr = String.format(Locale.ROOT, "%.1f", score);
            String rateStr = String.format(Locale.ROOT, "%.1f", breakdown.getFilesPerSecond());
            String avgEntStr = String.format(Locale.ROOT, "%.2f", breakdown.getAvgEntropy());
            String renamesStr = String.valueOf(breakdown.getMassRenamesCount());
            String notesStr = String.valueOf(breakdown.getRansomNotesCount());
            String canaryStr = breakdown.isCanaryTouched() ? "BREACHED" : "Safe";
            String decision = breakdown.isAlert() ? "ALERT: " + breakdown.getSummary() : "Normal";

            ScoreItem item = new ScoreItem(timeStr, scoreStr, rateStr, avgEntStr,
                    renamesStr, notesStr, canaryStr, decision);
            scoreList.add(0, item);
            if (scoreList.size() > 200) {
                scoreList.remove(scoreList.size() - 1);
            }

            appendLog(breakdown.formattedLog());
        });
    }

    private void handleProcessBlocked(ProcessActionRecord record) {
        Platform.runLater(() -> {
            blockedCount++;
            blockedMetricLabel.setText(String.valueOf(blockedCount));

            String timeStr = TIME_FMT.format(record.getTimestamp());
            String pidStr = String.valueOf(record.getPid());
            String scoreStr = String.format(Locale.ROOT, "%.1f", record.getAlertScore());

            BlockedProcessItem item = new BlockedProcessItem(
                    timeStr, pidStr, record.getPidSource(), record.getProcessName(), record.getExePath(),
                    scoreStr, record.getAction(), record.isSuccess() ? "SUCCESS" : "FAILED"
            );
            blockedList.add(0, item);

            appendLog("!!! [BLOCKED PROCESS] " + record.formattedLog());
        });
    }

    private void appendLog(String text) {
        Platform.runLater(() -> {
            if (logArea != null) {
                logArea.appendText(text + "\n");
            }
        });
    }

    public static void main(String[] args) {
        launch(args);
    }
}

