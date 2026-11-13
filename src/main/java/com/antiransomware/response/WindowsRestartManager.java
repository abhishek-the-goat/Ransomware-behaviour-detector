package com.antiransomware.response;

import com.sun.jna.Native;
import com.sun.jna.Platform;
import com.sun.jna.Structure;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.WinBase.FILETIME;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.win32.StdCallLibrary;
import com.sun.jna.win32.W32APIOptions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.*;

/**
 * Windows Restart Manager API via JNA.
 * Identifies the process(es) holding active handles or locks to a specific file.
 */
public class WindowsRestartManager {
    private static final Logger logger = LoggerFactory.getLogger(WindowsRestartManager.class);

    private static final int CCH_RM_MAX_APP_NAME = 255;
    private static final int CCH_RM_MAX_SVC_NAME = 63;
    private static final int ERROR_SUCCESS = 0;
    private static final int ERROR_MORE_DATA = 234;

    public interface Rstrtmgr extends StdCallLibrary {
        Rstrtmgr INSTANCE = Platform.isWindows()
                ? Native.load("rstrtmgr", Rstrtmgr.class, W32APIOptions.UNICODE_OPTIONS)
                : null;

        @Structure.FieldOrder({"dwProcessId", "ProcessStartTime"})
        class RM_UNIQUE_PROCESS extends Structure {
            public int dwProcessId;
            public FILETIME ProcessStartTime;
        }

        @Structure.FieldOrder({
                "Process", "strAppName", "strServiceShortName",
                "ApplicationType", "AppStatus", "TSSessionId", "bRestartable"
        })
        class RM_PROCESS_INFO extends Structure {
            public RM_UNIQUE_PROCESS Process;
            public char[] strAppName = new char[CCH_RM_MAX_APP_NAME + 1];
            public char[] strServiceShortName = new char[CCH_RM_MAX_SVC_NAME + 1];
            public int ApplicationType;
            public int AppStatus;
            public int TSSessionId;
            public int bRestartable;
        }

        int RmStartSession(IntByReference pSessionHandle, int dwSessionFlags, char[] strSessionKey);
        int RmRegisterResources(int dwSessionHandle, int nFiles, WString[] rgsFileNames,
                                int nApplications, RM_UNIQUE_PROCESS[] rgApplications,
                                int nServices, WString[] rgsServiceNames);
        int RmGetList(int dwSessionHandle, IntByReference pnProcInfoNeeded, IntByReference pnProcInfo,
                      RM_PROCESS_INFO[] rgAffectedApps, IntByReference lpdwRebootReasons);
        int RmEndSession(int dwSessionHandle);
    }

    public static List<Long> findProcessesLockingFile(Path file) {
        if (!Platform.isWindows() || Rstrtmgr.INSTANCE == null || file == null) {
            return Collections.emptyList();
        }

        List<Long> pids = new ArrayList<>();
        IntByReference sessionHandle = new IntByReference();
        char[] sessionKey = new char[33]; // CCH_RM_SESSION_KEY + 1

        int res = Rstrtmgr.INSTANCE.RmStartSession(sessionHandle, 0, sessionKey);
        if (res != ERROR_SUCCESS) {
            logger.debug("RmStartSession failed with code {}", res);
            return pids;
        }

        try {
            WString[] files = new WString[]{new WString(file.toAbsolutePath().toString())};
            res = Rstrtmgr.INSTANCE.RmRegisterResources(sessionHandle.getValue(), 1, files, 0, null, 0, null);
            if (res != ERROR_SUCCESS) {
                logger.debug("RmRegisterResources failed with code {}", res);
                return pids;
            }

            IntByReference procInfoNeeded = new IntByReference(0);
            IntByReference procInfoCount = new IntByReference(0);
            IntByReference rebootReasons = new IntByReference(0);

            res = Rstrtmgr.INSTANCE.RmGetList(sessionHandle.getValue(), procInfoNeeded, procInfoCount, null, rebootReasons);
            if (res == ERROR_MORE_DATA || procInfoNeeded.getValue() > 0) {
                int count = procInfoNeeded.getValue();
                Rstrtmgr.RM_PROCESS_INFO[] infos = (Rstrtmgr.RM_PROCESS_INFO[]) new Rstrtmgr.RM_PROCESS_INFO().toArray(count);
                procInfoCount.setValue(count);

                res = Rstrtmgr.INSTANCE.RmGetList(sessionHandle.getValue(), procInfoNeeded, procInfoCount, infos, rebootReasons);
                if (res == ERROR_SUCCESS) {
                    for (int i = 0; i < procInfoCount.getValue(); i++) {
                        long pid = infos[i].Process.dwProcessId;
                        if (pid > 0 && pid != ProcessHandle.current().pid()) {
                            pids.add(pid);
                        }
                    }
                }
            }
        } catch (Exception e) {
            logger.debug("Restart manager lookup error", e);
        } finally {
            Rstrtmgr.INSTANCE.RmEndSession(sessionHandle.getValue());
        }

        return pids;
    }
}

