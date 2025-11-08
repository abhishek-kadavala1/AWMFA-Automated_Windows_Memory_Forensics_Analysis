"""
Name, Parent, Instance, and Path Verification Module
Validates process names, parent-child relationships, instance counts, and execution paths
"""
from config import windows_processes, profiles, normalize_path
import re
from difflib import get_close_matches
import base64
import string

def is_suspicious_name(process_name):
    reasons = []
    is_suspicious = False

    if not process_name:
        return False, []

    if process_name.lower() not in (p.lower() for p in windows_processes):
        close_matches = get_close_matches(process_name, windows_processes, n=1, cutoff=0.9)
        
        if close_matches:
            closest_match = close_matches[0]
            reasons.append({
                'reason': "Suspicious Name Modification: Looks similar to '{}'".format(closest_match),
                'category': 'ProcessNameSimilartoLegitimate'
            
            })

            is_suspicious = True

        if len(process_name) > 25:
            reasons.append({
                'reason': "Excessive length (greater than 25 characters)",
                'category': 'LongProcessName'
            })

            is_suspicious = True

        if sum(int(char.isalpha()) for char in process_name) <= sum(int(char.isdigit()) for char in process_name):
            reasons.append({
                'reason': "High proportion of numeric characters (more than 50%)",
                'category': 'NumericProcessName'
            })
            is_suspicious = True

        if not all(c.isalnum() or c == '.' for c in process_name):
            reasons.append({
                'reason': "Special characters found in name",
                'category': 'SpecialCharacters'
            })
            is_suspicious = True

        return is_suspicious, reasons
    return False, []

def check_instance_count(process_name, actual_count, profile):
    if process_name in windows_processes:
        reasons = []
        if "instances" in windows_processes[process_name]:
            instances = windows_processes[process_name]["instances"]
        else:
             return False, []
        if instances == -1:
            return False, []
        
        if isinstance(instances, dict):
            if "minimum" in instances:
                if actual_count < instances["minimum"]:
                    reasons.append({'reason': "Minimum {} instances required and found {}".format(instances["minimum"], actual_count),
                    'category' : "MinInstance"
                    })
                    return True, reasons
                return False, []
            if "maximum" in instances:
                if actual_count > instances["maximum"]:
                    reasons.append({'reason': "Maximum {} instances required and found {}".format(instances["maximum"], actual_count),
                    'category' : "MaxInstance"
                    })
                    return True, reasons
                return False, []

            profile_index = profiles.index(profile) if profile in profiles else -1
            instance_index_early = profiles.index("Win2003SP2x86") if profile in profiles else -1
            instance_index_after = profiles.index("VistaSP0x86") if profile in profiles else -1

            if profile_index ==  -1 or instance_index_early == -1 or instance_index_after == -1:
                return False, []
            if profile_index <= instance_index_early: 
                if "default" in instances["Win2003SP2x86"] and actual_count != instances["Win2003SP2x86"]["default"]:
                        reasons.append({'reason': "Unusual number of instances detected: Expected {}, Found {}".format(instances["Win2003SP2x86"]["default"], actual_count),'category':' AbnormalInstances'})
                        return True, reasons
                if "minimum" in instances["Win2003SP2x86"] and actual_count < instances["Win2003SP2x86"]["minimum"]:
                        reasons.append({'reason': "Minimum {} instances required and found {}".format(instances["Win2003SP2x86"]["minimum"], actual_count),'category' : "MinInstance"})
                        return True, reasons
                if "maximum" in instances["Win2003SP2x86"] and actual_count > instances["Win2003SP2x86"]["maximum"]:
                        reasons.append({'reason': "Maximum {} instances required and found {}".format(instances["Win2003SP2x86"]["maximum"], actual_count),'category' : "MaxInstance"})
                        return True, reasons
            elif profile_index >= instance_index_after:
                if "default" in instances["VistaSP0x86"] and actual_count != instances["VistaSP0x86"]["default"]:
                        reasons.append({'reason': "Unusual number of instances detected: Expected {}, Found {}".format(instances["VistaSP0x86"]["default"], actual_count),'category':' AbnormalInstances'})
                        return True, reasons
                if "minimum" in instances["VistaSP0x86"] and actual_count < instances["VistaSP0x86"]["minimum"]:
                        reasons.append({'reason': "Minimum {} instances required and found {}".format(instances["VistaSP0x86"]["minimum"], actual_count),'category' : "MinInstance"})
                        return True, reasons
                if "maximum" in instances["VistaSP0x86"] and actual_count > instances["VistaSP0x86"]["maximum"]:
                        reasons.append({'reason': "Maximum {} instances required and found {}".format(instances["VistaSP0x86"]["maximum"], actual_count),'category' : "MaxInstance"})   
                        return True, reasons   
        else:
            expected_count = windows_processes[process_name]["instances"]
            if actual_count != expected_count:
                reasons.append({'reason': "Unusual number of instances detected: Expected {}, Found {}".format(expected_count, actual_count),
                'category':' AbnormalInstances'
                })
                return True, reasons
    return False, []

def check_parent(process_name, parent_name):
    if process_name in windows_processes and "parent" in windows_processes[process_name]:
        if windows_processes[process_name]["can_be_orphan"] and parent_name == 'Unknown':
            return False, []
        elif not windows_processes[process_name]["can_be_orphan"] and parent_name == 'Unknown':
            return True, [{'reason': "This process must have a parent.",'category' : "MissingParent"}]
        else:
            if "parent" in windows_processes[process_name] and parent_name in windows_processes[process_name]["parent"]:
                return False, []
            else:
                return True, [{'reason': "The parent of process '{}' should be '{}' but is '{}'.".format(process_name, " or ".join(windows_processes[process_name]["parent"]), parent_name),'category' : "IncorrectParent"}]
    return False, []

def check_svchost_k_param(cmd_path):
    match = re.search(r'svchost\.exe\s+-k\s+(\S+)', cmd_path, re.IGNORECASE)
    return True if match else False

def normalize_and_compare(path1, path2):
    return normalize_path(path1) == normalize_path(path2)

def normalize_windows_processes(processes):
    return {key.lower(): value for key, value in processes.iteritems()}

windows_processes = normalize_windows_processes(windows_processes)


def is_mostly_printable(s, threshold=0.9):
    printable = set(string.printable)
    return sum(c in printable for c in s) / max(len(s), 1) >= threshold

def check_base64_encoded_data(cmdline):
    base64_pattern = re.compile(r'([A-Za-z0-9+/]{30,}={0,2})')
    matches = base64_pattern.findall(cmdline)
    reasons = []

    for match in matches:
        try:
            padded = match + "==="[:(4 - len(match) % 4)]
            decoded = base64.b64decode(padded).decode('utf-8', errors='ignore').strip()

            if (
                decoded and
                len(decoded) >= 10 and
                any(c.isalnum() for c in decoded) and
                is_mostly_printable(decoded)
            ):
                reasons.append({'reason': 'Base64 encoded data detected in commandline "{}" and decoded: {}'.format(cmdline, decoded),
                'category' : 'Base64Detected'
                })
        except Exception:
            continue

    return reasons

def check_cmdline(cmdline):
    suspicious_patterns = [
        r'(?<!\w)powershell(?!\w).*(-nop|-w hidden|-encodedCommand)',
        r'(?<!\w)cmd(?!\w).*/c\s+(del|erase|format|shutdown)',
        r'(?<!\w)wmic(?!\w).*(process call create|os get)',
        r'(?<!\w)certutil(?!\w).*(-urlcache|decode)',
        r'(?<!\w)rundll32(?!\w)',
        r'(?<!\w)regsvr32(?!\w)',
        r'(?<!\w)bitsadmin(?!\w)',
        r'(?<!\w)bcdedit(?!\w)',
        r'(?<!\w)schtasks(?!\w)',
        r'(?<!\w)at(?!\w)',
        r'(?<!\w)sc(?!\w)',
        r'(?<!\w)net\s+user(?!\w)',
        r'(?<!\w)tasklist(?!\w)',
        r'(?<!\w)taskkill(?!\w)',
        r'(?<!\w)netsh(?!\w)',
        r'(?<!\w)mimikatz(?!\w)',
        r'(?<!\w)nc(?!\w)',
        r'(?<!\w)curl(?!\w)',
        r'(?<!\w)wget(?!\w)',
        r'(?<!\w)ftp(?!\w)',
        r'(?<!\w)tftp(?!\w)',
        r'(?<!\w)reg(?!\w).*(add|update|delete|query)',
    ]

    benign_commands = [
        "powershell -file script.ps1",
        "cmd /c dir",
        "wmic os get caption",
        "curl -o file.txt http://example.com/file.txt",
        "wget -O file.txt http://example.com/file.txt",
    ]

    reasons = []
    cmdline_lower = cmdline.lower()

    base64_reasons = check_base64_encoded_data(cmdline)
    if base64_reasons:
        reasons.extend(base64_reasons)

    if cmdline_lower in benign_commands:
        if reasons:
            return True, reasons
        else:
            return False, []

    for pattern in suspicious_patterns:
        if re.search(pattern, cmdline_lower, re.IGNORECASE):
            reasons.append({'reason': "Suspicious pattern detected: {}".format(pattern), 'category' : 'SuspiciousCommandPattern'})

    is_suspicious = len(reasons) > 0
    return is_suspicious, reasons if is_suspicious else []

def check_path(process_name, dll_path, cmd_path, peb_path, vad_path):
    reasons = []
    is_suspicious = False
    
    final_path = cmd_path or dll_path or peb_path or vad_path
    
    if not final_path:
        is_suspicious = True
        reasons.append({'reason': "No valid path found (missing: CMD line path, DLL list path, PEB path, and VAD path).",
        'category':'NoValidPath'
        })
        
        return is_suspicious, reasons
    
    if process_name.lower() == "svchost.exe" and not check_svchost_k_param(cmd_path):
        is_suspicious = True
        reasons.append({'reason': "svchost.exe should have -k parameter.", 'category':'Svchost_K'})
    
    process_name_lower = process_name.lower()
    if process_name_lower in windows_processes and windows_processes[process_name_lower]["path"]:
        expected_path = windows_processes[process_name_lower]["path"].lower()
        if not normalize_and_compare(expected_path, dll_path):
            is_suspicious = True
            reasons.append({'reason': "{} must have the path {} but it has {}".format(
                process_name, expected_path, normalize_path(dll_path)),'category': 'PathMismatch'})

    if vad_path is not None:
        if vad_path != "NA" and vad_path != process_name and vad_path != peb_path:
            is_suspicious = True
            reasons.append({'reason': "{} process path is in PEB {} but in VAD {}".format(
                process_name, normalize_path(peb_path), normalize_path(vad_path)),
                'category' : 'HollowedProcess'
                })
    if cmd_path: 
        is_suspicious, cmdline_reasons = check_cmdline(cmd_path)
        if is_suspicious:
            reasons.extend(cmdline_reasons)
    return is_suspicious, reasons