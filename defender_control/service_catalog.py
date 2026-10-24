"""Service and registry catalog used by the disable/enable routines.

The values below reproduce the documented behaviour of the original Sordum
"Defender Control" v2.1 (points 4-8 of the official repair guide) and the
registry keys that Defender-control tools are known to touch.
"""

# ---------------------------------------------------------------------------
# Services that belong to the Windows Defender stack.
# Each entry: (service_name, original_start_value)
#    Start types: 0 = boot, 1 = system, 2 = auto, 3 = demand/manual, 4 = disabled
# ---------------------------------------------------------------------------
DEFENDER_SERVICES: tuple[tuple[str, int], ...] = (
    ("WdNisSvc", 3),              # Windows Defender Network Inspection Service
    ("WdNisDrv", 3),              # Network Inspection Driver
    ("WdFilter", 0),              # Minifilter Driver (boot)
    ("WdBoot", 0),                # Boot Driver / ELAM
    ("WdDevFlt", 3),              # Device Guard/Defender Device Filter Driver
    ("SecurityHealthService", 3), # Windows Security Health Service
    ("Sense", 3),                 # Windows Defender Advanced Threat Protection
    ("MDDlpSvc", 3),              # Data Loss Prevention Service (Win10 1809+)
    ("MsSecFlt", 0),              # Microsoft Security Events Component Filter Driver
    ("MsSecCore", 0),             # Microsoft Security Core Component Driver
    ("MsSecWfp", 3),              # Microsoft Security WFP Callout Driver
    ("SgrmAgent", 3),             # System Guard Runtime Monitor Agent
    ("SgrmBroker", 2),            # System Guard Runtime Monitor Broker
)

# The service v2.1 explicitly cares about stopping first-hand. This mirrors the
# "Wscsvc -> WinDefend + ini-listed services" order from the original tool.
SECURITY_CENTER_SERVICE = "wscsvc"
PRIMARY_SERVICES: tuple[tuple[str, int], ...] = (
    ("WinDefend", 2),   # Windows Defender Antivirus Service (auto)
    ("Wscsvc", 2),      # Security Center (auto)
)


# ---------------------------------------------------------------------------
# Registry paths used by the disable routines.
# ---------------------------------------------------------------------------
REG_POLICY_DEFENDER = r"SOFTWARE\Policies\Microsoft\Windows Defender"
REG_POLICY_MRT = r"SOFTWARE\Policies\Microsoft\MRT"
REG_POLICY_ANTIMALWARE = r"SOFTWARE\Policies\Microsoft\Microsoft Antimalware"
REG_DEFENDER = r"SOFTWARE\Microsoft\Windows Defender"
REG_DEFENDER_RTP = r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
REG_DEFENDER_MPENGINE = r"SOFTWARE\Microsoft\Windows Defender\MpEngine"
REG_IFEO = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
REG_STARTUP_APPROVED = (
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
)
REG_RUN = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"


# ---------------------------------------------------------------------------
# Group-policy DWORDs written when disabling (and deleted when enabling).
# ---------------------------------------------------------------------------
POLICY_DISABLE_VALUES: dict[str, dict[str, int]] = {
    REG_POLICY_DEFENDER: {
        "DisableAntiSpyware": 1,
        "DisableRoutinelyTakingAction": 1,
        "ServiceKeepAlive": 0,
        "AllowFastServiceStartup": 0,
        "RandomizeScheduleTaskTimes": 0,
        "PUAProtection": 0,
    },
    REG_POLICY_DEFENDER + r"\MpEngine": {
        "MpEnablePus": 0,
        "MpCloudBlockLevel": 0,
        "MpBafsExtendedTimeout": 50,
        "EnableFileHashComputation": 0,
    },
    REG_POLICY_DEFENDER + r"\Spynet": {
        "DisableBlockAtFirstSeen": 1,
        "SpynetReporting": 0,
        "SubmitSamplesConsent": 2,
        "LocalSettingOverrideSpynetReporting": 0,
    },
    REG_POLICY_DEFENDER + r"\Real-Time Protection": {
        "DisableBehaviorMonitoring": 1,
        "DisableIOAVProtection": 1,
        "DisableOnAccessProtection": 1,
        "DisableRealtimeMonitoring": 1,
        "DisableIntrusionPreventionSystem": 1,
        "DisableScanOnRealtimeEnable": 1,
    },
    REG_POLICY_DEFENDER + r"\NIS": {
        "DisableProtocolRecognition": 1,
    },
    REG_POLICY_DEFENDER + r"\Scan": {
        "DisableHeuristics": 1,
        "DisableArchiveScanning": 1,
        "DisableEmailScanning": 1,
        "DisableRemovableDriveScanning": 1,
        "DisablePackedExeScanning": 1,
        "DisableScanningNetworkFiles": 1,
        "DisableRestorePoint": 1,
    },
    REG_POLICY_DEFENDER + r"\Signature Updates": {
        "DisableScheduledSignatureUpdate": 1,
    },
    REG_POLICY_MRT: {
        "DontReportInfectionInformation": 1,
        "DontOfferThroughWUAU": 1,
    },
}

# Keys under SOFTWARE\...\Windows Defender that we delete/restore.
DIRECT_DISABLE_VALUES: dict[str, dict[str, int]] = {
    REG_DEFENDER: {
        "DisableAntiSpyware": 1,
        "PUAProtection": 0,
    },
    REG_DEFENDER_RTP: {
        "DisableRealtimeMonitoring": 1,
    },
    REG_DEFENDER_MPENGINE: {
        "MpCloudBlockLevel": 0,
    },
}

POLICY_PATHS_TO_DELETE: tuple[str, ...] = (
    REG_POLICY_DEFENDER + r"\Real-Time Protection",
    REG_POLICY_DEFENDER + r"\Spynet",
    REG_POLICY_DEFENDER + r"\MpEngine",
    REG_POLICY_DEFENDER + r"\NIS",
    REG_POLICY_DEFENDER + r"\Scan",
    REG_POLICY_DEFENDER + r"\Signature Updates",
    REG_POLICY_MRT,
    REG_POLICY_ANTIMALWARE,
)

# ---------------------------------------------------------------------------
# IFEO blocks: executable name -> debugger command used to neutralise it.
# ---------------------------------------------------------------------------
IFEO_BLOCKS: dict[str, str] = {
    "msmpeng.exe": "%SystemRoot%\\System32\\systray.exe",
    "msseces.exe": "%SystemRoot%\\System32\\systray.exe",
    "SecurityHealthSystray.exe": "%SystemRoot%\\System32\\systray.exe",
}

# Start-up entries that must be neutralised / restored.
STARTUP_BLOCKED_ENTRIES: tuple[str, ...] = (
    "SecurityHealth",
)

# Defender-related process names that are killed when disabling.
DEFENDER_PROCESSES: tuple[str, ...] = (
    "MsMpEng.exe",
    "NisSrv.exe",
    "MpCmdRun.exe",
    "SecurityHealthService.exe",
    "SecurityHealthHost.exe",
    "MpDefenderCoreService.exe",
    "MpCopyAccelerator.exe",
    "ConfigSecurityPolicy.exe",
    "SgrmBroker.exe",
    "SgrmLpac.exe",
)