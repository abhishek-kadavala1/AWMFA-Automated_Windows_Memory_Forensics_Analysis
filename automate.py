# -*- coding: utf-8 -*-
"""
Windows Memory Forensics Automation Framework
Main automation script for comprehensive memory dump analysis using Volatility
"""
import subprocess
import sys
import argparse
import os
import StringIO
import io
import threading
import json
from tabulate import tabulate
import pandas as pd
import re
import hashlib
import requests
import ntpath
from datetime import datetime
from NPIP_Verify import is_suspicious_name, check_instance_count, check_parent, check_path
from DNH_Verify import *
from config import profiles, CACHE_FILE, VTSCANX_URL, VTSCANX_API_KEY, VT_SCAN_THRESHOLD, CATEGORY_PRIORITIES
from volatility import conf, registry, commands
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfbase.pdfmetrics import stringWidth
from xml.sax.saxutils import escape
from jinja2 import Environment, FileSystemLoader
import cgi 

reload(sys)
sys.setdefaultencoding('utf-8')
env = Environment(loader=FileSystemLoader('.'))
template = env.get_template('report.html')

plugins = ["pslist", "pstree", "psscan", "psxview", "cmdline", "dlllist", "hollowfind", "handles", "ldrmodules", "networkscan", "ssdt", "modules", "modscan", "malfind"]
results = {}
suspicious_processes = {}
suggested_profiles = []
profile=""
memory_file = None
plugin_list = None

scan_procdump = False
scan_dlldump = False
scan_suspicious_only = False
scan_suspicious_dll_only = False

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def ensure_directory_exists(path):
    if not os.path.exists(path):
        os.makedirs(path)

def run_plugin(memory_file, profile, plugin, results):
    """Run a Volatility plugin and store the output in a dictionary. Retry with other suggested profiles if results are empty.
       If all profiles fail, store the blank result at the end.
    """
    final_output_data = None
    final_profile_used = profile

    def execute_plugin(p):
        cmd = "python2.7 vol.py -f {} --profile={} {}".format(memory_file, p, plugin)
        if plugin == "procdump" or plugin == "dlldump":
            memfile_base = os.path.splitext(os.path.basename(memory_file))[0]
            dump_dir = os.path.join("dump", memfile_base)
            
            ensure_directory_exists(dump_dir)
            cmd += " -D {}".format(dump_dir)

        if plugin not in ['pstree', 'hollowfind']:
            cmd += " --output=json"
        
        print("Running command: {}\n".format(cmd))
        
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        output, error = process.communicate()
        if process.returncode != 0:
            primary_error = error.strip().split('\n')[0]
            print("[!] Error running {}: {}".format(plugin, primary_error))
            return None, p

        if error:
            error_lines = error.strip().split("\n")
            filtered_errors = [line for line in error_lines if "Volatility Foundation" not in line and line.strip() != ""]
            if filtered_errors:
                print("Warnings/Info from {}:\n".format(plugin) + "\n".join(filtered_errors))
                
        error_lines = error.strip().split("\n")
        filtered_errors = [line for line in error_lines if "Volatility Foundation" not in line]
        if filtered_errors:
            print("Warnings/Info:\n" + "\n".join(filtered_errors))

        if plugin in ['pstree', 'hollowfind']:
            return output, p
        else:
            output = output[output.index('{'):]
            try:
                parsed = json.loads(output)
                if parsed.get("rows", []):
                    return parsed, p
                else:
                    print("[!] No data found with profile: {}".format(p))
                    return parsed, p
            except json.JSONDecodeError:
                print("[-] Failed to parse JSON for plugin: {}".format(plugin))
                return None, p

    output_data, used_profile = execute_plugin(profile)
    final_output_data = output_data
    final_profile_used = used_profile

    if (output_data is None or (isinstance(output_data, dict) and not output_data.get("rows"))) and suggested_profiles:
        for alt_profile in suggested_profiles:
            if alt_profile == profile:
                continue
            print("[*] Trying alternative profile: {}".format(alt_profile))
            output_data, used_profile = execute_plugin(alt_profile)
            if output_data and (not isinstance(output_data, dict) or output_data.get("rows")):
                final_output_data = output_data
                final_profile_used = used_profile
                break
            elif output_data is not None:
                final_output_data = output_data
                final_profile_used = used_profile

    if final_output_data is not None:
        results[plugin] = final_output_data
        print("[+] {} completed using profile: {}".format(plugin, final_profile_used))
    else:
        results[plugin] = None
        print("[-] Plugin '{}' returned no valid output with any profile.".format(plugin))

def extract_hollowfind_paths(hollowfind_output):
    if not hollowfind_output:
        return pd.DataFrame([])
    process_paths = []
    
    process_blocks = hollowfind_output.strip().split("Hollowed Process Information:")
    
    for block in process_blocks[1:]:
        pid_match = re.search(r"PID:\s*(\d+)", block)
        vad_match = re.search(r"Process Path\(VAD\):\s*(.+)", block)
        peb_match = re.search(r"Process Path\(PEB\):\s*(.+)", block)

        pid = pid_match.group(1) if pid_match else None
        vad_path = vad_match.group(1).strip() if vad_match else "NA"
        peb_path = peb_match.group(1).strip() if peb_match else "NA"
        
        if pid:
            process_paths.append({
                "PID": pid,
                "VAD Path": vad_path,
                "PEB Path": peb_path
            })

    return pd.DataFrame(process_paths)

def get_priority(category):
    return CATEGORY_PRIORITIES.get(category, 1)

def NPIP_check():
    try:
        psscan_df = pd.DataFrame(results["psscan"]["rows"], columns=["Offset(P)", "Process Name", "PID", "PPID", "PDB", "Time Created", "Time Exited"])
    except:
        psscan_df = pd.DataFrame(results["pslist"]["rows"], columns=["Offset(V)", "Process Name", "PID", "PPID", "Thds", "Hnds", "Sess", "Wow64", "Time Created", "Time Exited"])
    dlllist_df = pd.DataFrame(results["dlllist"]["rows"], columns=["Pid", "Base", "Size", "LoadCount", "LoadTime", "Path"])

    dlllist_df = dlllist_df.dropna(subset=["Path"])
    exe_paths = dlllist_df[dlllist_df["Path"].str.lower().str.endswith(".exe")]
    exe_paths = exe_paths[["Pid", "Path"]].drop_duplicates()

    exe_paths.rename(columns={"Pid": "PID", "Path": "Executable Path"}, inplace=True)

    dlllist_path = psscan_df.merge(exe_paths, on="PID", how="inner")
    cmdline_path = pd.DataFrame(results["cmdline"]["rows"], columns=["Process", "PID", "CommandLine"])
    handles = pd.DataFrame(results["handles"]["rows"], columns=["Offset(V)", "Pid", "Handle", "Access", "Type", "Details"])
    # malfind_df = pd.DataFrame(results["malfind"]["rows"], columns=results["malfind"]["columns"])
    try:
        if "hollowfind" in results and results["hollowfind"]:
            hollowfind_path = extract_hollowfind_paths(results["hollowfind"])
        else:
            hollowfind_path = pd.DataFrame([])
    except Exception as e:
        hollowfind_path = pd.DataFrame([])

    process_counts = psscan_df["Process Name"].value_counts().to_dict()
    pid_to_name = dict(zip(psscan_df["PID"], psscan_df["Process Name"]))
    for _, row in psscan_df.iterrows():
        process_name = row["Process Name"]
        pid = row["PID"]
        # Get expected instance count (default 1 if not found in known processes)
        actual_count = process_counts[process_name]

        # Initialize a dictionary to hold reasons for the current process
        reasons_dict = {}

        # Check for suspicious name modifications
        is_suspicious, reasons = is_suspicious_name(process_name)

        if is_suspicious:
            reasons_dict["name_reasons"] = reasons

        # Check for unusual instance count
        is_instance_suspicious, reasons = check_instance_count(process_name, actual_count, profile)
        
        if is_instance_suspicious:
            reasons_dict["instance_reasons"] = reasons
        
        parent_name = pid_to_name.get(row["PPID"], "Unknown")
        is_reason_suspicious, reasons = check_parent(process_name, parent_name)

        if is_reason_suspicious:
            reasons_dict["parent_reasons"] = reasons

        pid_specific_dll = dlllist_path[dlllist_path["PID"] == pid]["Executable Path"].values
        pid_specific_cmd = cmdline_path[cmdline_path["PID"] == pid]["CommandLine"].values
        pid_specific_peb = (
            hollowfind_path[hollowfind_path["PID"] == pid]["PEB Path"].values 
            if "hollowfind" in results and not hollowfind_path.empty 
            else []
        )

        pid_specific_vad = (
            hollowfind_path[hollowfind_path["PID"] == pid]["VAD Path"].values 
            if "hollowfind" in results and not hollowfind_path.empty 
            else []
        )

        if row["Process Name"] != "System" and row["Time Exited"].strip() == "":
            is_path_suspicious, reasons = check_path(
                process_name,
                pid_specific_dll[0] if len(pid_specific_dll) > 0 else None, 
                pid_specific_cmd[0] if len(pid_specific_cmd) > 0 else None, 
                pid_specific_peb[0] if len(pid_specific_peb) > 0 else None, 
                pid_specific_vad[0] if len(pid_specific_vad) > 0 else None
            )

            if is_path_suspicious:
                reasons_dict["path_reasons"] = reasons

        process_dll_path = pid_specific_dll[0] if len(pid_specific_dll) > 0 else None
        if process_dll_path != None and pid != 4:
            is_dll_suspicious, reasons = check_dll(process_dll_path, dlllist_df[dlllist_df["Pid"] == pid]["Path"].tolist())

            if is_dll_suspicious:
                reasons_dict["dll_reasons"] = reasons

        is_handles_suspicious, reasons = check_handles(handles[handles["Pid"] == pid])
        
        if is_handles_suspicious:
            reasons_dict["handles_reasons"] = reasons

        # If there are any reasons collected, store them in the suspicious_processes dictionary
        if reasons_dict:
            add_reasons(pid, process_name, reasons_dict)

def add_reasons(pid, process_name, new_reasons):
    global suspicious_processes
    if pid not in suspicious_processes:
        suspicious_processes[pid] = {
            "process_name": process_name,
            "reasons": {}
        }
    for key, reason in new_reasons.iteritems():
        # Ensure vtscanx_reasons is always in the correct format (list of dicts)
        if key == "vtscanx_reasons":
            if isinstance(reason, (str, unicode)):
                # If it's a string, convert it to the proper format
                # Try to extract score for proper categorization
                score_match = re.search(r'score:\s*(\d+)', reason)
                score = int(score_match.group(1))
                reason = [{'category': score, 'reason': reason}]
            elif not isinstance(reason, list):
                # If it's neither string nor list, convert to proper format
                reason = [{'category': 'VTScanX', 'reason': str(reason)}]
            # Ensure each item in the list has both 'category' and 'reason' keys
            elif isinstance(reason, list):
                for item in reason:
                    if isinstance(item, dict):
                        if 'category' not in item:
                            item['category'] = 'VTScanX'
                        if 'reason' not in item:
                            item['reason'] = str(item)
        
        if key in suspicious_processes[pid]["reasons"]:
            if isinstance(suspicious_processes[pid]["reasons"][key], list):
                if isinstance(reason, list):
                    suspicious_processes[pid]["reasons"][key].extend(reason)
                else:
                    suspicious_processes[pid]["reasons"][key].append(reason)
            else:
                suspicious_processes[pid]["reasons"][key] = reason
        else:
            suspicious_processes[pid]["reasons"][key] = reason

def get_process_name(pid):
    try:
        psscan_df = pd.DataFrame(results["psscan"]["rows"], columns=["Offset(P)", "Process Name", "PID", "PPID", "PDB", "Time Created", "Time Exited"])
    except:
        psscan_df = pd.DataFrame(results["pslist"]["rows"], columns=results["pslist"]["Offset(V)", "Process Name", "PID", "PPID", "Thds", "Hnds", "Sess", "Wow64", "Time Created", "Time Exited"])
    row = psscan_df[psscan_df["PID"] == pid]
    return row.iloc[0]["Process Name"] if not row.empty else "Unknown"

def analyze_hidden_network_artifacts():
    if profiles.index(profile) >= 9:
        connections_df = pd.DataFrame(results["netscan"]["rows"], columns=results["netscan"]["columns"])
        for i in range(len(connections_df)):
            row = connections_df.iloc[i]
            pid = row["PID"]
            if int(pid) in suspicious_processes:
                foreign_addr = row["ForeignAddr"]
                process_name = row["Owner"]

                if foreign_addr and not foreign_addr.startswith("0.0.0.0") and not foreign_addr.startswith("*") and not foreign_addr.startswith(":::"):
                    add_reasons(pid, process_name, {
                        "netscan_reasons": [{'reason': "Possible C2 communication: {}".format(foreign_addr), 'category': 'C2_IP'}]
                    })

    else:
        connections_df = pd.DataFrame(results["connections"]["rows"], columns=results["connections"]["columns"])
        connscan_df = pd.DataFrame(results["connscan"]["rows"], columns=results["connscan"]["columns"])
        sockets_df = pd.DataFrame(results["sockets"]["rows"], columns=results["sockets"]["columns"])
        sockscan_df = pd.DataFrame(results["sockscan"]["rows"], columns=results["sockscan"]["columns"])

        conn_keys = ["LocalAddress", "RemoteAddress", "PID"]
        conn_reasons = find_hidden_entries(connections_df, connscan_df, conn_keys)

        for pid, reasons in conn_reasons.iteritems():
            if int(pid) in suspicious_processes:
                process_name = get_process_name(pid)
                new_reasons = {
                    "connections": reasons
                }
                add_reasons(pid, process_name, new_reasons)

        sock_keys = ["PID", "Port", "Proto", "Protocol", "Address"]
        sock_reasons = find_hidden_entries(sockets_df, sockscan_df, sock_keys)

        for pid, reasons in sock_reasons.iteritems():
            process_name = get_process_name(pid)
            if int(pid) in suspicious_processes:
                add_reasons(pid, process_name, {
                    "sockets": reasons
                })

    return suspicious_processes

def analyse_ldrmodules_malfind():
    try:
        psscan_df = pd.DataFrame(results["psscan"]["rows"], columns=["Offset(P)", "Process Name", "PID", "PPID", "PDB", "Time Created", "Time Exited"])
    except:
        psscan_df = pd.DataFrame(results["pslist"]["rows"], columns=results["pslist"]["Offset(V)", "Process Name", "PID", "PPID", "Thds", "Hnds", "Sess", "Wow64", "Time Created", "Time Exited"])
    ldrmodules = pd.DataFrame(results["ldrmodules"]["rows"],
                              columns=["Pid", "Process", "Base", "InLoad", "InInit", "InMem", "MappedPath"])
    malfind_df = pd.DataFrame(results["malfind"]["rows"], columns=results["malfind"]["columns"])

    for _, row in psscan_df.iterrows():
        process_name = row["Process Name"]
        pid = row["PID"] 
        if int(pid) in suspicious_processes:
            new_reasons = {}

            is_ldrmodules_suspicious, reasons = check_ldrmodules(ldrmodules[ldrmodules["Pid"] == pid])
            if is_ldrmodules_suspicious:
                new_reasons["ldrmodules_reasons"] = reasons

            if not malfind_df[malfind_df["Pid"] == pid].empty:
                new_reasons["malfind_reasons"] = [{'reason':"Invalid memory protection permission: PAGE_EXECUTE_READWRITE",'category':'RWX_MemoryPermissions'}]

            add_reasons(pid, process_name, new_reasons)

def load_vt_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_vt_cache(cache):
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache, f)
    except Exception as e:
        print("Error saving cache: {}".format(str(e)))

already_scanned_hashes = set()

def vtscanx_scan_file(file_path):
    """
    Submit file hash to the VTScanX API and return scan results if suspicious.
    Uses local cache to avoid redundant queries.
    """
    global already_scanned_hashes
    SERVER_IP_SCAN_URL = "{}/check_hash".format(VTSCANX_URL)
    headers = {"Authorization": "Bearer {}".format(VTSCANX_API_KEY)}
    sha256_hash = calculate_sha256(file_path)

    if sha256_hash in already_scanned_hashes:
        return None

    already_scanned_hashes.add(sha256_hash)

    vt_cache = load_vt_cache()
    if sha256_hash in vt_cache:
        return vt_cache[sha256_hash] or None  # Return cached result or None

    try:
        response = requests.post(SERVER_IP_SCAN_URL, json={"hash_value": sha256_hash}, headers=headers)
        if response.status_code == 200:
            data = response.json()
            score = data.get("score", 0)
            category = (data.get("threat_category") or "").strip()
            label = (data.get("threat_label") or "").strip()
            threat_name = (data.get("threat_name") or "").strip()
            if score > VT_SCAN_THRESHOLD:
                parts = ["score: {}".format(score)]
                if category:
                    parts.append("Popular Threat Category: {}".format(category))
                if label:
                    parts.append("suggested_threat_label: {}".format(label))
                if threat_name:
                    parts.append("popular_threat_name: {}".format(threat_name))
                reason_str = ", ".join(parts)
                reason = [{'reason': reason_str, 'category': score}]
                vt_cache[sha256_hash] = reason
                save_vt_cache(vt_cache)
                return reason
            else:
                # Not suspicious
                vt_cache[sha256_hash] = None
                save_vt_cache(vt_cache)

    except requests.RequestException as e:
        print("Error during hash submission: {}".format(str(e)))

    return None

def extract_pid_from_filename(filename, source_type):
    """
    Extract PID based on file type (exe or dll)
    """
    if source_type == "exe":
        match = re.search(r'\.(\d+)\.exe$', filename)
        if match:
            return int(match.group(1))
    elif source_type == "dll":
        # Example: module.880.ea13030.10000000.dll → extract second part
        parts = filename.split('.')
        if len(parts) >= 3:
            try:
                return int(parts[1])  # This is the correct PID for the process owning the DLL
            except ValueError:
                pass
    return None


def scan_dump_table(table_name, valid_extensions, source_type, filter_pids=None):
    dump_df = pd.DataFrame(results[table_name]["rows"], columns=results[table_name]["columns"])
    dump_dir = os.path.join(".", "dump", os.path.splitext(os.path.basename(memory_file))[0])

    for _, row in dump_df.iterrows():
        process_name = row["Name"]
        result = row["Result"]

        if result.startswith("OK:"):
            file_name = result.split(":", 1)[1].strip()
            file_path = os.path.join(dump_dir, file_name)

            if file_name.lower().endswith(valid_extensions):
                pid = extract_pid_from_filename(file_name, source_type)

                if (filter_pids is None or pid in filter_pids) and os.path.exists(file_path):
                    vt_reasons = vtscanx_scan_file(file_path)
                    if vt_reasons:
                        # If source is DLL, prepend label to each reason
                        if source_type == "dll":
                            dll_path = row.get("Module Name") or row.get("Module") or file_name
                            dll_real_name = os.path.basename(dll_path)
                            if dll_real_name.lower() == process_name.lower():
                                continue
                            label = "Suspicious DLL: {}".format(dll_real_name)

                            for item in vt_reasons:
                                item["reason"] = "{} | {}".format(label, item["reason"])

                        # Add correctly as list of dicts
                        add_reasons(pid, process_name, {"vtscanx_reasons": vt_reasons})

def vtscanx_scan():
    if scan_procdump:
        print("\n[+] Scanning all process dumps...")
        scan_dump_table("procdump", (".exe", ), "exe")

    if scan_dlldump:
        print("\n[+] Scanning all DLL dumps...")
        scan_dump_table("dlldump", (".dll", ), "dll")

    if scan_suspicious_only:
        print("\n[+] Scanning only suspicious process dumps...")
        pids = suspicious_processes.keys()
        scan_dump_table("procdump", (".exe", ), "exe", pids)

    if scan_suspicious_dll_only:
        print("\n[+] Scanning only suspicious DLLs...")
        pids = suspicious_processes.keys()
        scan_dump_table("dlldump", (".dll", ), "dll", pids)

def analyze_ssdt_hooks():
    """
    Analyzes SSDT data from results to find hooks from non-standard owners.
    
    Args:
        results (dict): The dictionary containing raw plugin output.
        
    Returns:
        list: A list of dictionaries, where each dictionary represents a hooked function.
              Returns an empty list if no hooks are found or data is missing.
    """
    APIHooking_df = pd.DataFrame(results["ssdt"]["rows"], columns=results["ssdt"]["columns"])
    allowed_owners = ['ntoskrnl.exe', 'win32k.sys']
    
    hooked_functions = []

    for index, row in APIHooking_df.iterrows():
        owner = row.get('Owner')
        # Filter out hooks from allowed owners
        if owner and owner not in allowed_owners:
            # Append a dictionary for easier use in the template
            hooked_functions.append({
                'function_name': row.get('Function'),
                'owner': owner,
                'entry': row.get('Entry'),
                'address': "0x{:X}".format(row.get('Addr', 0)) # Format address as hex
            })

    return hooked_functions



def print_ssdt_hooks_report(hooked_functions):
    """
    Prints a formatted report of SSDT hooks to the console.
    
    Args:
        hooked_functions (list): The list of hooked function dictionaries from analyze_ssdt_hooks.
    """
    RED = "\033[91m"
    RESET = "\033[0m"
    print("\n[+] SSDT Hooking Report")
    print("=" * 50)
    hooked_functions = analyze_ssdt_hooks()
    for hook in hooked_functions:
        print("Function Name: {}{}{}".format(RED, hook['function_name'], RESET))
        print("Entry Number: {}".format(hook['entry']))
        print("Address: {}".format(hook['address']))
        print("Hooked By: {}".format(hook['owner']))
        print("-" * 50)

def ssdt_hooks():
    """
    Analyzes and prints a report for suspicious SSDT hooks.
    This function acts as a wrapper for the analysis and printing logic.
    """
    # First, analyze the SSDT data to find hooks
    hooked_functions = analyze_ssdt_hooks()
    
    # Then, print the formatted report to the console
    print_ssdt_hooks_report(hooked_functions)


# def suspicious_modules():
#     RED = "\033[91m"     # Red color for module name
#     YELLOW = "\033[93m"  # Yellow color for hidden status
#     RESET = "\033[0m"    # Reset color

#     # Load DataFrames
#     modules_df = pd.DataFrame(results["modules"]["rows"], columns=results["modules"]["columns"])
#     modscan_df = pd.DataFrame(results["modscan"]["rows"], columns=results["modscan"]["columns"])

#     # Convert Base columns to int (assumes already int or convertible)
#     def safe_int(val):
#         try:
#             return int(val)
#         except:
#             return None

#     modules_df['Base'] = modules_df['Base'].apply(safe_int)
#     modscan_df['Base'] = modscan_df['Base'].apply(safe_int)

#     # Suspicious path detection
#     def is_suspicious(path):
#         if not path or "\\" not in path:
#             return False
#         normalized_path = path.replace("\\", "\\\\").lower()
#         safe_paths = [
#             r"\\systemroot\\system32\\",
#             r"c:\\windows\\system32\\",
#             r"\\windows\\system32\\"
#         ]
#         for safe in safe_paths:
#             if normalized_path.startswith(safe):
#                 return False
#         return True

#     # Mark suspicious modules from modules list
#     modules_df['is_suspicious'] = modules_df['File'].apply(is_suspicious)
#     suspicious_df = modules_df[modules_df['is_suspicious'] == True].copy()
#     suspicious_df['Status'] = ''
#     suspicious_df['Reason'] = 'Suspicious path'

#     # Detect hidden modules (bases in modscan but NOT in modules)
#     known_bases = set(modules_df['Base'].dropna())
#     hidden_df = modscan_df[~modscan_df['Base'].isin(known_bases)].copy()
#     hidden_df['Status'] = 'Hidden'

#     # Reset index before applying functions to avoid pandas error
#     hidden_df = hidden_df.reset_index(drop=True)

#     if not hidden_df.empty:
#         hidden_df['is_suspicious'] = hidden_df['File'].apply(is_suspicious)

#         def reason_label(row):
#             if row['Status'] == 'Hidden' and row['is_suspicious']:
#                 return 'Hidden + Suspicious path'
#             elif row['Status'] == 'Hidden':
#                 return 'Hidden'
#             elif row.get('is_suspicious', False):
#                 return 'Suspicious path'
#             else:
#                 return ''

#         hidden_df['Reason'] = hidden_df.apply(reason_label, axis=1)
#     else:
#         hidden_df['is_suspicious'] = []
#         hidden_df['Reason'] = []

#     # Fill missing cols in hidden_df for consistent concat
#     for col in ['Name', 'File', 'Size']:
#         if col not in hidden_df.columns:
#             hidden_df[col] = 'Unknown'
#         hidden_df[col] = hidden_df[col].fillna('Unknown')

#     # Ensure suspicious_df has all needed columns
#     for col in ['Name', 'File', 'Base', 'Size', 'Status', 'Reason']:
#         if col not in suspicious_df.columns:
#             suspicious_df[col] = 'Unknown'

#     # Combine both DataFrames
#     combined_df = pd.concat([suspicious_df, hidden_df], ignore_index=True, sort=True)
#     print "\n[+] Suspicious Modules:"
#     print "=" * 60
#     if combined_df.empty:
#         print "No suspicious or hidden modules detected."
#     else:
#         for idx, row in combined_df.iterrows():
#             name_str = RED + str(row['Name']) + RESET
#             if row['Status'] == 'Hidden':
#                 name_str += " " + YELLOW + "[Hidden]" + RESET

#             print "Module Name: " + name_str
#             print "File Path  : " + row['File'].encode('utf-8')

#             try:
#                 base_val = int(row['Base'])
#                 print "Base Addr  : 0x%X" % base_val
#             except:
#                 print "Base Addr  : Unknown"

#             print "Size       : " + str(row['Size'])
#             print "Reason     : " + str(row['Reason'])
#             print "-" * 50

def analyze_suspicious_modules():
    """
    Analyzes modules and modscan data to find suspicious and hidden kernel modules.
    
    Args:
        results (dict): The dictionary containing raw plugin output.
        
    Returns:
        list: A list of dictionaries, where each dictionary represents a suspicious module.
    """
    # Safety check for missing plugin data
    if "modules" not in results or "modscan" not in results:
        return []

    modules_df = pd.DataFrame(results["modules"]["rows"], columns=results["modules"]["columns"])
    modscan_df = pd.DataFrame(results["modscan"]["rows"], columns=results["modscan"]["columns"])

    # --- Data Preparation and Analysis ---
    def safe_int(val):
        try: return int(val)
        except: return None
    
    modules_df['Base'] = modules_df['Base'].apply(safe_int)
    modscan_df['Base'] = modscan_df['Base'].apply(safe_int)

    def is_suspicious_path(path):
        if not isinstance(path, basestring) or "\\" not in path: return False
        normalized_path = path.replace("\\", "\\\\").lower()
        safe_paths = [r"\\systemroot\\system32\\", r"c:\\windows\\system32\\", r"\\windows\\system32\\"]
        return not any(normalized_path.startswith(safe) for safe in safe_paths)

    suspicious_df = modules_df[modules_df['File'].apply(is_suspicious_path)].copy()
    suspicious_df['Reason'] = 'Suspicious path'
    
    known_bases = set(modules_df['Base'].dropna())
    hidden_df = modscan_df[~modscan_df['Base'].isin(known_bases)].copy()
    
    if not hidden_df.empty:
        hidden_df['is_suspicious_path'] = hidden_df['File'].apply(is_suspicious_path)
        def determine_reason(row):
            is_hidden = True # All modules in this df are hidden
            is_suspicious = row['is_suspicious_path']
            if is_hidden and is_suspicious: return 'Hidden + Suspicious path'
            return 'Hidden'
        hidden_df['Reason'] = hidden_df.apply(determine_reason, axis=1)
    
    combined_df = pd.concat([suspicious_df, hidden_df], ignore_index=True, sort=False).fillna('Unknown')
    
    # --- Format final output list ---
    final_modules_list = []
    if not combined_df.empty:
        for idx, row in combined_df.iterrows():
            is_hidden = 'Hidden' in str(row.get('Reason'))
            try: base_addr = "0x{:X}".format(int(row.get('Base')))
            except: base_addr = "Unknown"
            
            final_modules_list.append({
                'name': row.get('Name'),
                'path': row.get('File'),
                'base_addr': base_addr,
                'size': row.get('Size'),
                'reason': row.get('Reason'),
                'is_hidden': is_hidden
            })
            
    return final_modules_list

def print_suspicious_modules_report():
    """
    Prints a formatted report of suspicious modules to the console.
    
    Args:
        suspicious_modules (list): The list of module dictionaries from the analyze function.
    """
    RED = "\033[91m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"
    print("\n[+] Suspicious Modules Report")
    print("=" * 60)
    
    suspicious_modules = analyze_suspicious_modules()

    for module in suspicious_modules:
        name_str = RED + module['name'] + RESET
        if module['is_hidden']:
            name_str += " " + YELLOW + "[Hidden]" + RESET
            
        print("Module Name: " + name_str)
        print("File Path  : " + module['path'].encode('utf-8'))
        print("Base Addr  : " + module['base_addr'])
        print("Size       : " + str(module['size']))
        print("Reason     : " + module['reason'])
        print("-" * 50)


def suspicious_modules():
    """
    Analyzes and prints a report for suspicious kernel modules.
    This is a wrapper function for the analysis and printing logic.
    """
    print_suspicious_modules_report()


def print_suspicious_process():
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    RESET = "\033[0m"

    def highlight_score(reason_text):
        try:
            reason_text = str(reason_text)
            match = re.search(r"(score:\s*)(\d+)", reason_text)
            if match:
                score_val = int(match.group(2))
                if score_val > 50:
                    color = RED
                elif score_val > 20:
                    color = YELLOW
                else:
                    color = CYAN
                colored_score = "{}{}{}".format(match.group(1), color + match.group(2), RESET)
                return reason_text.replace(match.group(0), colored_score)
        except:
            pass
        return reason_text

    print "\n[+] Suspicious Processes Report"
    print "=" * 80

    if not suspicious_processes:
        print "No suspicious processes detected."
        return

    # --- Calculate Scores for Summary Table ---
    process_scores = []
    for pid, details in suspicious_processes.iteritems():
        process_name = details.get("process_name", "Unknown")
        reasons_dict = details.get("reasons", {})

        total_score = 0
        for reason_key, reason_list in reasons_dict.iteritems():
            for reason_item in reason_list:
                if isinstance(reason_item, dict):
                    cat = reason_item.get('category')
                    try:
                        total_score += int(cat)
                    except (TypeError, ValueError):
                        total_score += CATEGORY_PRIORITIES.get(cat, 0)

        process_scores.append((total_score, pid, process_name))

    # --- Sort by score descending ---
    process_scores.sort(reverse=True)

    # --- Print Summary Table ---
    # --- Print Summary Table (Improved) ---
    print "\n" + "=" * 80
    print " " * 28 + "Suspicious Process Summary"
    print "=" * 80
    print "| {:<3} | {:<25} | {:<10} | {:<17} |".format("No.", "Process Name", "PID", "Suspicious Score")
    print "-" * 80

    for idx, (score, pid, name) in enumerate(process_scores, start=1):
        print "| {:<3} | {:<25} | {:<10} | {:<17} |".format(idx, name, pid, score)

    print "=" * 80


    # --- Detailed Per-Process Report ---
    for _, pid, process_name in process_scores:
        details = suspicious_processes[pid]
        reasons_dict = details.get("reasons", {})

        if "hidden_process" in reasons_dict:
            print "Process Name: {}{}{} {}[Hidden]{}".format(RED, process_name, RESET, YELLOW, RESET)
        else:
            print "Process Name: {}{}{}".format(RED, process_name, RESET)

        print "PID: {}".format(pid)
        print "Reasons:"

        other_reasons = []
        ldr_reasons = []

        for reason_key, reason_list in reasons_dict.iteritems():
            if reason_key == "ldrmodules_reasons":
                ldr_reasons.extend(reason_list)
            elif reason_key == "hidden_process":
                continue
            else:
                other_reasons.extend(reason_list)

        def print_reason_list(reason_list):
            for reason_item in reason_list:
                if isinstance(reason_item, dict) and 'reason' in reason_item:
                    reason_text = reason_item['reason']
                else:
                    reason_text = str(reason_item)
                print "     - {}".format(highlight_score(reason_text))

        print_reason_list(other_reasons)
        print_reason_list(ldr_reasons)

        print "-" * 50

def print_hidden_processes(psxview_data):
    """Identify and print hidden processes using psxview data."""
    global suspicious_processes
    hidden_processes = []
    
    for row in psxview_data:
        # row format: [Offset, Name, PID, pslist, psscan, thrdproc, pspcid, csrss, session, deskthrd, ExitTime]
        offset = row[0]
        name = row[1]
        pid = row[2]
        in_pslist = row[3]  # "True" or "False" as string
        in_psscan = row[4]  # "True" or "False" as string
        exit_time = row[10] if len(row) > 10 else ""
        
        # Process is hidden if it's in psscan but not in pslist
        if in_psscan == "True" and in_pslist == "False":
            reasons_dict = {"hidden_process": [{'category': 'HiddenProcess', 'reason': "Hidden"}]}
            add_reasons(pid, name, reasons_dict)
            
            # Format for display: [Offset, Name, PID, Status]
            hidden_processes.append([
                hex(offset) if isinstance(offset, (int, long)) else offset,
                name,
                pid,
                "Hidden",
                exit_time if exit_time and exit_time != "" else "Still Running"
            ])
    
    if hidden_processes:
        headers = ["Offset(P)", "Name", "PID", "Status", "Exit Time"]
        print(tabulate(hidden_processes, headers=headers, tablefmt="rst"))
    else:
        print("No hidden processes found.")

        
def is_plugin_exist(plugin_name):
    global plugin_list
    plugin_name = plugin_name.lower()  # Normalize input

    if plugin_list is not None:
        # Compare after converting list items to lowercase
        if plugin_name in [p.lower() for p in plugin_list]:
            return True
        return False

    config = conf.ConfObject()
    registry.PluginImporter()
    registry.register_global_options(config, commands.Command)
    plugin_classes = registry.get_plugin_classes(commands.Command, lower=True)
    plugin_list = plugin_classes.keys()

    # Compare with lowercase keys
    if plugin_name in [p.lower() for p in plugin_list]:
        return True
    return False

def strip_ansi(text):
    ansi_escape = re.compile(r'\x1b\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]')
    return ansi_escape.sub('', text)

def generate_txt_report(report_name, report_dir, include_plugins=None, include_all=False):
    output_buffer = StringIO.StringIO()
    output_buffer.write("======= Volatility Automated Report =======\n")
    output_buffer.write("Memory File: {}\n".format(memory_file))
    output_buffer.write("Profile Used: {}\n".format(profile))
    output_buffer.write("===========================================\n\n")

    output_buffer.write("General Info:\n")
    output_buffer.write("- Generated on: {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    output_buffer.write("\n\n")

    # Capture and write print_suspicious_process output
    original_stdout = sys.stdout
    temp_output = StringIO.StringIO()
    sys.stdout = temp_output
    try:
        print_suspicious_process()
    finally:
        sys.stdout = original_stdout
        output_buffer.write(strip_ansi(temp_output.getvalue()) + "\n")

    # Capture and write ssdt_hooks output
    temp_output = StringIO.StringIO()
    sys.stdout = temp_output
    try:
        ssdt_hooks()
    finally:
        sys.stdout = original_stdout
        output_buffer.write(strip_ansi(temp_output.getvalue()) + "\n")

    # Capture and write suspicious_modules output
    temp_output = StringIO.StringIO()
    sys.stdout = temp_output
    try:
        print_suspicious_modules_report()
    finally:
        sys.stdout = original_stdout
        output_buffer.write(strip_ansi(temp_output.getvalue()) + "\n")

    if include_all is True and include_plugins is not None:
        selected_plugins = plugins[:]
        
        for p in include_plugins:
            if is_plugin_exist(p) and p not in selected_plugins:
                run_plugin(memory_file, profile, p, results)
                selected_plugins.append(p)

    elif include_all is True:
        selected_plugins = plugins[:]

    else:
        selected_plugins = [p for p in (include_plugins or []) if is_plugin_exist(p)]

    for plugin in selected_plugins:
        data = results.get(plugin)
        if not data:
            continue

        output_buffer.write("===== Plugin: {} =====\n".format(plugin))
        if plugin in ['pstree', 'hollowfind']:
            output_buffer.write(data + "\n\n")
        elif isinstance(data, dict):
            headers = data.get("columns", [])
            rows = data.get("rows", [])
            if rows:
                output_buffer.write(tabulate(rows, headers=headers, tablefmt="grid") + "\n\n")
            else:
                output_buffer.write("No data available\n\n")
        else:
            output_buffer.write(str(data) + "\n\n")

    # Save the report
    try:
        file_path = os.path.join(report_dir, "{}.txt".format(report_name))
        with open(file_path, "w") as f:
            f.write(output_buffer.getvalue())
        print("[+] TXT report saved to: {}".format(file_path))
    except Exception as e:
        print("[-] Failed to save TXT report: {}".format(e))

def _calculate_process_scores(suspicious_data):
    """
    Calculates total and VT-specific scores for each suspicious process and sorts them.

    Args:
        suspicious_data (dict): The global suspicious_processes dictionary.

    Returns:
        list: A list of dictionaries, sorted by score, each containing
              pid, name, score, and vt_score.
    """
    process_scores = []
    for pid, details in suspicious_data.iteritems():
        process_name = details.get("process_name", "Unknown")
        reasons_dict = details.get("reasons", {})

        total_score = 0
        vt_score = 'N/A'  # Default value if no VT scan reason exists

        for reason_key, reason_list in reasons_dict.iteritems():
            if not isinstance(reason_list, list):
                reason_list = [reason_list]  # Ensure it's always a list

            for reason_item in reason_list:
                if isinstance(reason_item, dict):
                    category = reason_item.get('category')
                    
                    # Handle VTScanX scores, which are directly used as the score value
                    if reason_key == 'vtscanx_reasons':
                        try:
                            current_vt_score = int(category)
                            total_score += current_vt_score
                            # Keep the highest VT score found for the process as its primary vt_score
                            if vt_score == 'N/A' or current_vt_score > vt_score:
                                vt_score = current_vt_score
                        except (ValueError, TypeError):
                            # Fallback for non-integer categories
                            total_score += get_priority(category)
                    else:
                        # Use the priority mapping for all other categories
                        total_score += get_priority(category)

        process_scores.append({
            'pid': pid,
            'name': process_name,
            'score': total_score,
            'vt_score': vt_score
        })

    # Sort the processes by total score in descending order for the report
    process_scores.sort(key=lambda x: x['score'], reverse=True)
    return process_scores


def _generate_suspicious_process_pdf_elements(suspicious_data, styles):
    """
    Generates ReportLab Flowables where the summary table itself contains
    the hyperlinks, removing the separate link list.
    """
    elements = []
    if not suspicious_data:
        elements.append(Paragraph("<b>Suspicious Process Analysis</b>", styles['Heading2']))
        elements.append(Paragraph("No suspicious processes detected.", styles['Normal']))
        elements.append(Spacer(1, 0.2 * inch))
        return elements

    scores_data = _calculate_process_scores(suspicious_data)

    elements.append(Paragraph("<b>Suspicious Process Analysis</b>", styles['Heading2']))
    elements.append(Paragraph("<u>Process Risk Summary (Click Name for Details)</u>", styles['Heading3']))
    
    # --- THIS IS THE MODIFIED LINE ---
    table_headers = ['PID', 'Process Name', 'Suspicious Score', 'VirusTotal']
    # --- END OF MODIFICATION ---

    table_rows = [table_headers]
    link_in_cell_style = ParagraphStyle('link_in_cell', parent=styles['Normal'], textColor=colors.blue)

    for item in scores_data:
        pid = item['pid']
        process_name = escape(str(item['name']))
        link_text = u'<link href="#pid_{}">{}</link>'.format(pid, process_name)
        process_name_paragraph = Paragraph(link_text, link_in_cell_style)
        
        row_data = [
            str(item['pid']),
            process_name_paragraph,
            str(item['score']),
            str(item['vt_score']) # This data comes from the 'vt_score' key
        ]
        table_rows.append(row_data)

    col_widths = [0.8 * inch, 2.7 * inch, 1.5 * inch, 1.5 * inch]
    summary_table = Table(table_rows, colWidths=col_widths)
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    elements.append(summary_table)
    elements.append(Spacer(1, 0.2 * inch))

    # Detailed sections logic follows...
    elements.append(Paragraph("<u>Process Details</u>", styles['Heading3']))
    bullet_style = ParagraphStyle('bullet_style', parent=styles['Normal'], leftIndent=20)
    
    for item in scores_data:
        pid = item['pid']
        details = suspicious_data[pid]
        process_name = item['name']
        is_hidden = "hidden_process" in details.get("reasons", {})
        header_text = u'<a name="pid_{}"/><b>Process: {} (PID: {})</b>'.format(pid, escape(process_name), pid)
        if is_hidden:
            header_text += u' <font color="orange"><i>[Hidden]</i></font>'
        elements.append(Paragraph(header_text, styles['h4']))
        
        reasons = details.get("reasons", {})
        if not reasons:
            elements.append(Paragraph(" - No specific reasons found.", bullet_style))
        else:
            all_reasons_text = []
            for reason_key, reason_list in reasons.items():
                if reason_key == "hidden_process": continue
                if not isinstance(reason_list, list): reason_list = [reason_list]
                for reason_item in reason_list:
                    if isinstance(reason_item, dict):
                        all_reasons_text.append(reason_item.get('reason', ''))
                    else:
                        all_reasons_text.append(str(reason_item))
            for reason in sorted(all_reasons_text):
                # Highlighting logic for PDF
                highlighted_reason_text = u""
                try:
                    reason_text = strip_ansi(unicode(reason))
                    match = re.search(r"(score:\s*)(\d+)", reason_text)
                    if match:
                        score_val = int(match.group(2))
                        color = "blue"
                        if score_val > 50: color = "red"
                        elif score_val > 20: color = "orange"
                        pre_match = escape(reason_text[:match.start()])
                        colored_score_html = u'{}<font color="{}"><b>{}</b></font>'.format(escape(match.group(1)), color, match.group(2))
                        post_match = escape(reason_text[match.end():])
                        highlighted_reason_text = pre_match + colored_score_html + post_match
                    else:
                        highlighted_reason_text = escape(reason_text)
                except Exception:
                    highlighted_reason_text = escape(strip_ansi(unicode(reason)))
                reason_para = Paragraph(u"- {}".format(highlighted_reason_text), bullet_style)
                elements.append(reason_para)
        elements.append(Spacer(1, 0.1 * inch))

    elements.append(Spacer(1, 0.2 * inch))
    return elements



def generate_pdf_report(report_name, report_dir, include_plugins=None, include_all=False):

    file_path = os.path.join(report_dir, "%s.pdf" % report_name)
    doc = SimpleDocTemplate(file_path,pagesize=A4,rightMargin=20,leftMargin=20,topMargin=20,bottomMargin=20)

    styles = getSampleStyleSheet()
    elements = []

    # Report Header
    elements.append(Paragraph("Volatility Automated Report", styles['Title']))
    elements.append(Spacer(1, 0.2 * inch))

    # Meta Info
    file_hash = calculate_sha256(memory_file)
    info = [
        "Memory File: %s" % memory_file,
        "SHA256 Hash: %s" % file_hash,
        "Profile Used: %s" % profile,
        "Generated On: %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    ]
    for line in info:
        elements.append(Paragraph(escape(line), styles['Normal']))
    elements.append(Spacer(1, 0.2 * inch))

    # *** MODIFICATION STARTS HERE ***

    # Call the new helper to generate interactive PDF elements for suspicious processes
    suspicious_pdf_elements = _generate_suspicious_process_pdf_elements(suspicious_processes, styles)
    elements.extend(suspicious_pdf_elements)

    # Capture output for the other analysis sections
    for title, func in [
        # ("Suspicious Process Analysis", print_suspicious_process), # This is now handled above
        ("SSDT Hook Analysis", ssdt_hooks),
        ("Suspicious Modules", suspicious_modules)
    ]:
        temp_output = StringIO.StringIO()
        sys.stdout = temp_output
        try:
            func()
        finally:
            sys.stdout = sys.__stdout__
        cleaned_output = strip_ansi(temp_output.getvalue())
        elements.append(Paragraph("<b>%s</b>" % title, styles['Heading2']))
        # Use a Code style for monospaced font
        code_style = ParagraphStyle('code_style', parent=styles['Normal'], fontName='Courier', fontSize=8, leading=10)
        for line in cleaned_output.splitlines():
            # Escape HTML special characters to prevent rendering issues
            escaped_line = escape(line)
            elements.append(Paragraph(escaped_line, code_style))
        elements.append(Spacer(1, 0.2 * inch))

    # *** MODIFICATION ENDS HERE ***

    if include_all is True and include_plugins is not None:
        selected_plugins = plugins[:]
        for p in include_plugins:
            if is_plugin_exist(p) and p not in selected_plugins:
                run_plugin(memory_file, profile, p, results)
                selected_plugins.append(p)

    elif include_all is True:
        selected_plugins = plugins[:]

    elif include_plugins is not None:
        selected_plugins = []
        for p in include_plugins:
            if p not in results.keys() and is_plugin_exist(p):
                run_plugin(memory_file, profile, p, results)
            selected_plugins.append(p)

    else:
        selected_plugins = []

    for plugin in selected_plugins:
        data = results.get(plugin)
        if not data:
            continue

        elements.append(Paragraph("<b>Plugin: %s</b>" % plugin, styles['Heading2']))

        if plugin in ['pstree', 'hollowfind']:
            code_style = ParagraphStyle('code_style', parent=styles['Normal'], fontName='Courier', fontSize=8, leading=10)
            for line in strip_ansi(data).splitlines():
                escaped_line = escape(line)
                elements.append(Paragraph(escaped_line, code_style))
        elif isinstance(data, dict):
            headers = data.get("columns", [])
            rows = data.get("rows", [])
            if headers and rows:
                table = create_dynamic_table(headers, rows, doc)
                elements.append(table)
            else:
                elements.append(Paragraph("No data available", styles['Normal']))
        else:
            code_style = ParagraphStyle('code_style', parent=styles['Normal'], fontName='Courier', fontSize=8, leading=10)
            for line in strip_ansi(str(data)).splitlines():
                escaped_line = escape(line)
                elements.append(Paragraph(escaped_line, code_style))

        elements.append(Spacer(1, 0.2 * inch))

    # Final save
    try:
        doc.build(elements)
        print("[+] PDF report saved to: %s" % file_path)
    except Exception as e:
        print("[-] Failed to save PDF report: %s" % str(e))

def _parse_address(addr_str):
    """Helper to safely parse IP:Port strings."""
    if not isinstance(addr_str, basestring) or ':' not in addr_str:
        return addr_str, 'N/A'
    parts = addr_str.rsplit(':', 1)
    return parts[0], parts[1]

def format_suspicious_data(raw_data):
    """
    Analyzes raw suspicious process data in a single pass, correctly parsing all
    process and DLL details from any relevant reason category. Python 2.7 compatible.

    This version correctly handles:
    - DLLInjected (multi-line)
    - DLLIllegitimatePath (single-line)
    - DLLMissingFromList (and extracts the missing-from details)
    - Windows-style paths on any host operating system.

    Returns:
        A tuple of (formatted_processes, suspicious_dlls, category_scores).
    """
    formatted_processes = []
    suspicious_dlls = []
    suspicious_files = []
    netscan_data = []
    connections_data = []
    sockets_data = []
    category_scores = {}

    if profiles.index(profile) >= 9 and results.get("netscan"):
        columns = results["netscan"]["columns"]
        for row_values in results["netscan"]["rows"]:
            row = dict(zip(columns, row_values)) # Create a dictionary for easy access
            local_ip, local_port = _parse_address(row.get("LocalAddr", ""))
            foreign_ip, foreign_port = _parse_address(row.get("ForeignAddr", ""))
            netscan_data.append({
                'protocol': row.get("Proto", "N/A"), 'local_ip': local_ip, 'local_port': local_port,
                'foreign_ip': foreign_ip, 'foreign_port': foreign_port, 'state': row.get("State", " "),
                'pid': row.get("PID", "N/A"), 'process_name': row.get("Owner", "Unknown")
            })
    else: # Logic for pre-Win7 (XP, etc.)
        if results.get("connections"):
            columns = results["connections"]["columns"]
            for row_values in results["connections"]["rows"]:
                row = dict(zip(columns, row_values)) # <--- FIX: Create dict from list
                local_ip, local_port = _parse_address(row.get("LocalAddress", ""))
                foreign_ip, foreign_port = _parse_address(row.get("RemoteAddress", ""))
                connections_data.append({'local_ip': local_ip, 'local_port': local_port, 'foreign_ip': foreign_ip, 'foreign_port': foreign_port, 'pid': row.get("PID", "N/A"), 'process_name': get_process_name(row.get("PID")), 'is_hidden': False })
        if results.get("connscan"):
            columns = results["connscan"]["columns"]
            for row_values in results["connscan"]["rows"]:
                row = dict(zip(columns, row_values)) # <--- FIX: Create dict from list
                local_ip, local_port = _parse_address(row.get("LocalAddress", ""))
                foreign_ip, foreign_port = _parse_address(row.get("RemoteAddress", ""))
                connections_data.append({'local_ip': local_ip, 'local_port': local_port, 'foreign_ip': foreign_ip, 'foreign_port': foreign_port, 'pid': row.get("PID", "N/A"), 'process_name': get_process_name(row.get("PID")), 'is_hidden': True })

        # Process sockets and sockscan
        if results.get("sockets"):
            columns = results["sockets"]["columns"]
            for row_values in results["sockets"]["rows"]:
                row = dict(zip(columns, row_values)) # <--- FIX: Create dict from list
                sockets_data.append({ 'protocol': row.get("Protocol", "N/A"), 'address': row.get("Address", "N/A"), 'port': row.get("Port", "N/A"), 'pid': row.get("PID", "N/A"), 'process_name': get_process_name(row.get("PID")), 'is_hidden': False })
        if results.get("sockscan"):
            columns = results["sockscan"]["columns"]
            for row_values in results["sockscan"]["rows"]:
                row = dict(zip(columns, row_values)) # <--- FIX: Create dict from list
                sockets_data.append({ 'protocol': row.get("Protocol", "N/A"), 'address': row.get("Address", "N/A"), 'port': row.get("Port", "N/A"), 'pid': row.get("PID", "N/A"), 'process_name': get_process_name(row.get("PID")), 'is_hidden': True })
    
    for pid, pdata in raw_data.items():
        process_details = {
            'pid': pid,
            'process_name': pdata.get('process_name', 'Unknown'),
            'score': 0,
            'vt_score': 'N/A',
            'reasons': [],
            'is_hidden': 'hidden_process' in pdata.get('reasons', {})
        }

        total_score = 0
        vt_score = None

        for reason_key, reason_list in pdata.get('reasons', {}).items():
            for reason in reason_list:
                if not isinstance(reason, dict):
                    continue

                category = reason.get('category')
                reason_text = reason.get('reason', '')
                formatted_reason = reason_text
                if reason_key == 'vtscanx_reasons':
                    try:
                        vt_score = int(category)
                        total_score += vt_score
                    except (ValueError, TypeError):
                        pass
                else:
                    cat_score = get_priority(category)
                    total_score += cat_score
                    if cat_score > 0 and category:
                        category_scores[category] = category_scores.get(category, 0) + cat_score
                
                if category == 'DLLInjected' and '\n' in reason_text:
                    lines = reason_text.splitlines()
                    header = lines[0]
                    dll_paths = [line.strip() for line in reason_text.splitlines()[1:] if line.strip()]
                    html_list = u'<ol class="injected-dll-list">'
                    for path in dll_paths:
                        suspicious_dlls.append({
                            # --- FIX APPLIED HERE ---
                            'name': ntpath.basename(path) if path else 'Unknown DLL',
                            'path': path,
                            'reason': 'Injected DLL',
                            'process_name': process_details['process_name'],
                            'pid': pid,
                            'vt_score': 'N/A'
                        })
                        html_list += u'<li>{}</li>'.format(path)
                    html_list += u'</ol>'
                    formatted_reason = header + html_list
                
                elif category == 'DLLIllegitimatePath':
                    path = reason_text.split('illegitimate path:')[-1].strip()
                    suspicious_dlls.append({
                        # --- FIX APPLIED HERE ---
                        'name': ntpath.basename(path) if path else 'Unknown DLL',
                        'path': path,
                        'reason': 'Loaded from suspicious path',
                        'process_name': process_details['process_name'],
                        'pid': pid,
                        'vt_score': 'N/A'
                    })

                elif category == 'DLLMissingFromList':
                    path = reason_text.split('Path:')[-1].strip()
                    missing_from_match = re.search(r'\[(.*?)\]', reason_text)
                    custom_reason = "Missing from [{}]".format(missing_from_match.group(1)) if missing_from_match else "Missing from PEB order"
                    
                    suspicious_dlls.append({
                        # --- FIX APPLIED HERE ---
                        'name': ntpath.basename(path) if path else 'Unknown DLL',
                        'path': path,
                        'reason': custom_reason,
                        'process_name': process_details['process_name'],
                        'pid': pid,
                        'vt_score': 'N/A'
                    })

                elif category == 'SuspiciousFile':
                    path = reason_text.split('Accessed suspicious file:')[-1].strip()
                    suspicious_files.append({
                        'name': ntpath.basename(path) if path else 'Unknown File',
                        'path': path,
                        'pid': pid,
                        'process_name': process_details['process_name'],
                        'offset': reason.get('offset')
                    })
    

                elif reason_key == 'vtscanx_reasons':
                    score_match = re.search(r'score: (\d+)', reason_text)
                    if score_match:
                        score_num = int(score_match.group(1))
                        score_text = score_match.group(0) # e.g., "score: 67"
                        
                        # Determine risk level for coloring
                        risk_class = 'low'
                        if score_num >= 60: risk_class = 'high'
                        elif score_num >= 30: risk_class = 'medium'
                        
                        # Create the colored span for just the number
                        colored_score = u'score: <span class="score-{}">{}</span>'.format(risk_class, score_num)
                        
                        # Replace the original "score: XX" text with the new HTML version
                        formatted_reason = reason_text.replace(score_text, colored_score, 1)

                process_details['reasons'].append(formatted_reason)

        process_details['score'] = total_score
        if vt_score is not None:
            process_details['vt_score'] = vt_score
        
        formatted_processes.append(process_details)

    network_data = {
        'connections': connections_data,
        'sockets': sockets_data,
        'networks': netscan_data
    }

    return formatted_processes, suspicious_dlls, suspicious_files, network_data, category_scores

def get_risk_level(vt_score, score):
    # Normalize: handle Nones or 'N/A'
    vt = vt_score if isinstance(vt_score, int) else 0
    sc = (score if isinstance(score, int) else 0) - vt

    # Classify each independently
    def classify(val):
        if val >= 60:
            return 'high'
        elif val >= 30:
            return 'medium'
        else:
            return 'low'

    vt_risk = classify(vt)
    score_risk = classify(sc)

    # Combine smartly:
    if vt_risk == 'high' or score_risk == 'high':
        return 'high'
    elif vt_risk == 'medium' or score_risk == 'medium':
        return 'medium'
    else:
        return 'low'

def generate_html_report(report_name, report_dir, include_plugins=None, include_all=None):
    file_hash = calculate_sha256(memory_file)
    included_plugins =[]
    if include_all:
        included_plugins = list(plugins)
    if include_plugins:
        for p in include_plugins:
            if p not in plugins:
                run_plugin(memory_file, profile, p, results)
            if p not in included_plugins:
                included_plugins.append(p)
    suspicious_list, suspicious_dlls_list, suspicious_files_list, network_data, category_scores = format_suspicious_data(suspicious_processes)

    high_risk = len([p for p in suspicious_list if get_risk_level(p.get('vt_score'), p.get('score')) == 'high'])
    medium_risk = len([p for p in suspicious_list if get_risk_level(p.get('vt_score'), p.get('score')) == 'medium'])
    low_risk = len([p for p in suspicious_list if get_risk_level(p.get('vt_score'), p.get('score')) == 'low'])

    
    data = {
        'title': memory_file + ' report',
        'profile': profile,
        'memory_file': memory_file,
        'file_hash': file_hash,
        'generation_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'suspicious_processes': suspicious_list,
        'suspicious_dlls': suspicious_dlls_list,
        'suspicious_files': suspicious_files_list,
        'network_data': network_data,
        'high_risk_count': high_risk,
        'medium_risk_count': medium_risk,
        'category_scores': category_scores,
        'low_risk_count': low_risk,
        'other_plugins': included_plugins,
        'ssdt_hooks': analyze_ssdt_hooks(),
        'suspicious_modules': analyze_suspicious_modules(),
        'results': results
    }
    output = template.render(data)
    report_path = os.path.join(report_dir, report_name + '.html')
    with open(report_path, 'w') as f:
        f.write(output.encode('utf-8'))
    print(report_path)

def get_profile(memory_file):
    """Run imageinfo to get suggested profiles."""
    print("\nRunning imageinfo to suggest a profile...\n")
    global suggested_profiles
    suggested_profiles = []

    process = subprocess.Popen("python2.7 vol.py -f '{}' imageinfo".format(memory_file), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

    for line in iter(process.stdout.readline, ''):
        print line,
        if "Suggested Profile(s)" in line:
            profile_line = line.split(":", 1)[-1].strip()
            
            # Clean profiles: remove anything in parentheses and strip whitespace
            raw_profiles = profile_line.split(',')
            for profile in raw_profiles:
                clean_profile = re.sub(r"\s*\(.*?\)", "", profile).strip()
                if clean_profile:
                    suggested_profiles.append(clean_profile)

    process.stdout.close()
    process.wait()

    return suggested_profiles if suggested_profiles else None

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Volatility Automation Script - Analyzes memory dumps for suspicious processes."
    )
    parser.add_argument("-f", "--file", required=True, help="Path to the memory dump file")
    parser.add_argument("-p", "--profile", help="Volatility profile to use (optional)")
    parser.add_argument("--scan-procdump", action="store_true", help="Scan dumped processes with VTScanX")
    parser.add_argument("--scan-dlldump", action="store_true", help="Scan dumped DLLs with VTScanX")
    parser.add_argument("--scan-suspicious-proc", action="store_true", help="Scan only suspicious processes with VTScanX")
    parser.add_argument("--scan-suspicious-dll", action="store_true", help="Scan only suspicious DLLs with VTScanX")
    parser.add_argument("--generate-txt", action="store_true", help="Generate report in TXT format")
    parser.add_argument("--generate-html", action="store_true", help="Generate report in HTML format")
    parser.add_argument("--generate-pdf", action="store_true", help="Generate report in PDF format")
    parser.add_argument("--report-name", type=str, default="memory_report", help="Name of the report file without extension")
    parser.add_argument("--report-dir", type=str, default="reports", help="Directory to save the report")
    parser.add_argument("--include-plugins", nargs="+", help="List of plugin names to include in report.")
    parser.add_argument("--all-include-plugins", action="store_true", help="To include all plugins")

    return parser.parse_args()

def main():
    print("Welcome to the Volatility Automation Script")
    global profile, memory_file, plugins, scan_procdump, scan_dlldump, scan_suspicious_only, scan_suspicious_dll_only

    args = parse_arguments()

    if len(sys.argv) < 3 or sys.argv[1] != '-f':
        print("Usage: python2 update.py -f <memory_dump_file>")
        sys.exit(1)

    memory_file = args.file

    if not os.path.exists(memory_file):
        print("Error: Memory file does not exist:", memory_file)
        return

    if args.profile:
        profile = args.profile.strip()
    else:
        suggested_profiles = get_profile(memory_file)
        if suggested_profiles:
            use_suggested = raw_input("\nUse suggested profile '{}'? [Enter=yes, type 'no' for manual]: ".format(suggested_profiles[0])).strip().lower()
            profile = suggested_profiles[0] if use_suggested in ['', 'yes', 'y'] else raw_input("Enter the profile to use: ").strip()
            # profile = suggested_profiles[0]
        else:
            print("No suggested profiles found.")
            profile = raw_input("Enter the profile to use: ").strip()

    if profile not in profiles:
        print("\n[!] Error: The profile '{}' is not valid.".format(profile))
        print("[*] Available profiles are:")
        for p in profiles:
            print("  -", p)
        sys.exit(1)

    scan_procdump = args.scan_procdump
    scan_dlldump = args.scan_dlldump
    scan_suspicious_only = args.scan_suspicious_proc
    scan_suspicious_dll_only = args.scan_suspicious_dll

    print("\nUsing profile: {}\n".format(profile))

    if args.scan_procdump or args.scan_suspicious_proc:
        plugins.append("procdump")
    
    if args.scan_dlldump or args.scan_suspicious_dll:
        plugins.append("dlldump")

    threads = []
    for plugin in plugins:
        if plugin == "networkscan" and profiles.index(profile) >= 9:
            thread = threading.Thread(target=run_plugin, args=(memory_file, profile, "netscan", results))
        elif plugin == "networkscan":
            for net_plugin in ["connections", "connscan", "sockets", "sockscan"]:
                thread = threading.Thread(target=run_plugin, args=(memory_file, profile, net_plugin, results))
                thread.start()
                threads.append(thread)
            continue
        else:
            thread = threading.Thread(target=run_plugin, args=(memory_file, profile, plugin, results))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()  

    NPIP_check()
    analyze_hidden_network_artifacts()
    if VTSCANX_API_KEY:
        vtscanx_scan()
    analyse_ldrmodules_malfind()
    include_plugins = args.include_plugins if args.include_plugins else []
    include_all = args.all_include_plugins
    report_name = args.report_name
    report_dir = args.report_dir
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)
    print_hidden_processes(results["psxview"]["rows"])
    # print_hidden_processes(results["pslist"]["rows"], results["psscan"]["rows"])
    if args.generate_txt:
        # Decide which plugins to include in report
        generate_txt_report(report_name, report_dir, include_plugins, include_all)
    elif args.generate_html:
        generate_html_report(report_name, report_dir, include_plugins, include_all)
    elif args.generate_pdf:
        generate_pdf_report(report_name, report_dir, include_plugins, include_all)
    else:
        for plugin in plugins[:4]:
            print("\n==============================")
            print("Running {}...".format(plugin))
            print("==============================\n")
            data = results.get(plugin, None)
            if data and plugin not in ['pstree', 'hollowfind']:
                print(tabulate(data["rows"], headers=data["columns"], tablefmt="rst"))
            elif plugin in ['pstree', 'hollowfind']:
                print(data)
            else:
                print("No output received for {}".format(plugin))

        print("\n[+] Checking for hidden processes...")
        # print_hidden_processes(results["pslist"]["rows"], results["psscan"]["rows"])
        print_suspicious_process()
        ssdt_hooks()
        suspicious_modules()
if __name__ == "__main__":
    main()
