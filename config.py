"""
Parent-Child Process Configuration Module
Contains Windows process definitions, suspicious patterns, and configuration constants
"""
import re

WINDOWS_ROOT = "c:\\windows"

CACHE_FILE = "vt_cache.json"

VTSCANX_URL = "https://vtscanx.cyberlearn360.com"

VTSCANX_API_KEY = ""
VT_SCAN_THRESHOLD = 10

profiles = [
    "WinXPSP1x64", "WinXPSP2x64", "WinXPSP2x86", "WinXPSP3x86",  # Windows XP (2001-2008)
    "Win2003SP0x86", "Win2003SP1x64", "Win2003SP1x86", "Win2003SP2x64", "Win2003SP2x86",  # Windows Server 2003 (2003-2007)
    "VistaSP0x86", "VistaSP0x64", "VistaSP1x86", "VistaSP1x64", "VistaSP2x86", "VistaSP2x64",  # Windows Vista (2007-2009)
    "Win2008SP1x86", "Win2008SP1x64", "Win2008SP2x86", "Win2008SP2x64",  # Windows Server 2008 (2008-2011)
    "Win7SP0x86", "Win7SP0x64", "Win7SP1x86", "Win7SP1x64", "Win7SP1x86_23418", "Win7SP1x64_23418",  # Windows 7 (2009-2015)
    "Win2008R2SP0x64", "Win2008R2SP1x64", "Win2008R2SP1x64_23418",  # Windows Server 2008 R2 (2009-2015)
    "Win8SP0x86", "Win8SP0x64", "Win8SP1x86", "Win8SP1x64", "Win8SP1x64_18340",  # Windows 8 (2012-2016)
    "Win2012x64", "Win2012R2x64", "Win2012R2x64_18340",  # Windows Server 2012 (2012-2018)
    "Win81U1x86", "Win81U1x64",  # Windows 8.1 Update 1 (2013-2016)
    "Win10x86", "Win10x64", "Win10x86_10586", "Win10x64_10586", "Win10x86_14393", "Win10x64_14393", "Win10x64_19041" ,  # Windows 10 (2015+)
    "Win2016x64_14393"  # Windows Server 2016 (2016+)
]

windows_processes = {
    "System": {
        "parent": "",
        "children": ["smss.exe"],
        "can_be_orphan": True,
        "instances" : 1,
        "path" : False
    },
    "smss.exe": {
        "parent": ["System", "smss.exe"],
        "children": ["csrss.exe", "wininit.exe"], 
        "can_be_orphan": False,
        "instances": {"minimum": 1},
        "path": r"C:\Windows\System32\smss.exe"
    },
    "csrss.exe": {
        "parent": ["smss.exe", ],
        "children": [],
        "can_be_orphan": True,
        "instances": {"Win2003SP2x86" : {"default" : 1}, "VistaSP0x86" : {"minimum" : 2}},
        "path" : r"C:\Windows\System32\csrss.exe"
    },
    "wininit.exe": {
        "parent": ["smss.exe",],
        "children": ["services.exe", "lsass.exe", "lsaiso.exe"],
        "can_be_orphan": True,
        "instances": {"Win2003SP2x86" : {"default" : 0}, "VistaSP0x86" : {"default" : 1}},
        "path" : r"C:\Windows\System32\wininit.exe"
    },
    "winlogon.exe": {
        "parent": ["smss.exe",],
        "children": ["services.exe", "lsass.exe", "lsaiso.exe"],
        "can_be_orphan": True,
        "instances": {"minimum": 1},
        "path" : r"C:\Windows\System32\winlogon.exe"
    },
    "lsaiso.exe": {
        "parent": ["wininit.exe",],
        "children": [],
        "can_be_orphan": False,
        "instances" : {"maximum": 1},
        "path" : r"C:\Windows\System32\lsaiso.exe"
    },
    "lsass.exe": {
        # {"Win2003SP2x86" : "winlogon.exe", "VistaSP0x86" : "wininit.exe"}
        "parent": ["winlogon.exe", "wininit.exe"],
        "children": [],
        "can_be_orphan": False,
        "instances" : 1,
        "path" : r"C:\Windows\System32\lsass.exe"
    },
    "services.exe": {
        "parent": ["winlogon.exe", "wininit.exe"],
        "children": ["svchost.exe"],
        "can_be_orphan": False,
        "instances" : 1,
        "path" : r"C:\Windows\System32\services.exe"
    },
    "svchost.exe": {
        "parent": ["services.exe",],
        "children": ["RuntimeBroker.exe", "taskhostw.exe"],
        "can_be_orphan": False,
        "instances" : -1,
        "path" : r"C:\Windows\System32\svchost.exe"
    },
    "RuntimeBroker.exe": {
        "parent": ["svchost.exe",],
        "children": ["RuntimeBroker.exe", "taskhostw.exe"],
        "can_be_orphan": False,
        "instances" : -1,
        "path" : r"C:\Windows\System32\RuntimeBroker.exe"
    },
    "taskhostw.exe": {
        "parent": ["svchost.exe",],
        "children": ["RuntimeBroker.exe", "taskhostw.exe"],
        "can_be_orphan": False,
        "instances" : -1,
        "path" : r"C:\Windows\System32\taskhostw.exe"
    },
    "explorer.exe": {
        "parent": ["userinit.exe",],
        "children": [],
        "can_be_orphan": True,
        "instances" : -1,
        "path" : r"C:\Windows\explorer.exe"
    },
    "userinit.exe": {
        "parent": ["winlogon.exe",],
        "children": ["explorer.exe"],
        "can_be_orphan": True,
        "instances" : -1,
        "path" : r"C:\Windows\userinit.exe"
    },
    "taskhost.exe":{
        "path" : r"C:\Windows\System32\taskhost.exe",
        "instances" : -1,
    },
}

SUSPICIOUS_PATHS = [
    "C:\\Users\\", 
    "C:\\Temp\\", 
    "C:\\Windows\\Temp\\", 
    "C:\\Windows\\Tasks\\", 
    "C:\\Windows\\System32\\Tasks\\", 
    "C:\\ProgramData\\",
    "AppData\\Local\\Temp\\",
    "C:\\a.os\\", 
    "D:\\a.os\\",  
]

SUSPICIOUS_MUTEXES = [
    "Global\\", "Local\\", "Session\\", "Mutex_", "Sync_", "AdobeARM", "cryptbase",
    "Rundll32_Mutex", "shell32_Mutex", "Malware_Mutex",
    "a.os_mutex" 
]

SUSPICIOUS_EVENTS = [
    "Global\\StartEvent", "Global\\StopEvent", "Global\\MalwareEvent", "MalwareTrigger",
    "a.os_event" 
]

SUSPICIOUS_PIPES = [
    "\\Device\\NamedPipe\\", "Pipe\\MalwarePipe", "Pipe\\EvilPipe", "Pipe\\ShellPipe",
    "Pipe\\a.os_pipe"
]

CATEGORY_PRIORITIES = {
    "MinInstance": 10,
    "MaxInstance": 10,
    "AbnormalInstances": 10,
    "IncorrectParent": 10,
    "Svchost_K": 10,
    "DLLInjected": 10,
    "DLLNotinorder": 10,
    "HollowedProcess": 9,
    "MissingParent": 8,
    "PathMismatch": 8,
    "DLLIllegitimatePath": 8,
    "RWX_MemoryPermissions": 8,
    "ProcessNameSimilartoLegitimate": 7,
    "TerminatedNetwork": 7,
    "TerminatedSocket": 6,
    "HiddenProcess": 6,
    "SuspiciousCommandPattern": 5,
    "DLLMissingFromList": 4,
    "SuspiciousMutex": 3,
    "LongProcessName": 2,
    "Base64Detected": 2,
    "NoValidPath": 2,
    "SuspiciousFile": 2,
    "SuspiciousEvent": 2,
    "NumericProcessName": 1,
    "SpecialCharacters": 1,
    "SuspiciousPipe": 1,
    "C2_IP": 0
}

def normalize_path(path):
    if not path or not isinstance(path, basestring):
        return ""

    path = path.replace("\\??\\", "")
    path = re.sub(r"(?i)^\\systemroot\\", WINDOWS_ROOT + "\\\\", path)
    path = re.sub(r"(?i)^%systemroot%", WINDOWS_ROOT, path)

    path = path.replace("/", "\\")
    path = re.sub(r"\\\\+", r"\\", path)

    path = path.strip().lower()

    if re.match(r"^[a-z]:[^\\]", path):
        path = path[:2] + "\\" + path[2:]

    return path