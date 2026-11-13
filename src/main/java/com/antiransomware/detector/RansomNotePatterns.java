package com.antiransomware.detector;

import java.util.regex.Pattern;

public final class RansomNotePatterns {
    private RansomNotePatterns() {
    }

    private static final Pattern RANSOM_NOTE_PATTERN = Pattern.compile(
            "(?i).*(readme[-_\\s]?decrypt|how[-_\\s]?to[-_\\s]?decrypt|decrypt[-_\\s]?files|" +
            "restore[-_\\s]?files|help[-_\\s]?decrypt|recovery[-_\\s]?instructions|" +
            "ransom[-_\\s]?note|recover[-_\\s]?my[-_\\s]?files|decrypt_your_files|" +
            "your_files_are_encrypted|de-crypt).*");

    private static final Pattern SUSPICIOUS_EXTENSION_PATTERN = Pattern.compile(
            "(?i).*\\.(locked|crypto|crypted|encrypted|enc|ransom|lockbit|blackcat|wannacry|darkside|phobos)$");

    public static boolean isRansomNote(String fileName) {
        if (fileName == null || fileName.isBlank()) {
            return false;
        }
        return RANSOM_NOTE_PATTERN.matcher(fileName).matches();
    }

    public static boolean hasSuspiciousExtension(String fileName) {
        if (fileName == null || fileName.isBlank()) {
            return false;
        }
        return SUSPICIOUS_EXTENSION_PATTERN.matcher(fileName).matches();
    }
}

