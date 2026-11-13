package com.antiransomware.monitor;

@FunctionalInterface
public interface FileEventListener {
    void onFileEvent(FileEvent event);
}

