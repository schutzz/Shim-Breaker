#!/usr/bin/env python3
import sys
import struct
import datetime
import re
import argparse
import csv
import os

# -----------------------------------------------------------------------------
# Shim-Breaker
# "Break the Hive, Seize the Evidence."
#
# A structure-agnostic ShimCache extractor for corrupted/fragmented hives.
# Created by a barbarian forensic analyst.
# -----------------------------------------------------------------------------

def parse_filetime(ft_bytes):
    """
    Convert Windows FILETIME (8 bytes) to a readable UTC datetime string.
    Returns 'N/A' or 'Invalid Time' if conversion fails.
    """
    try:
        (ft_int,) = struct.unpack('<Q', ft_bytes)
        if ft_int == 0:
            return "N/A"
        
        # Windows FILETIME is 100ns intervals since January 1, 1601 (UTC)
        dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft_int / 10)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return f"Invalid Time ({ft_bytes.hex()})"

def is_likely_path(s):
    """
    Heuristic validation to check if a decoded string looks like a file path.
    Used to filter out garbage data carved from raw binaries.
    """
    if not s: return False
    
    # Check for common invalid chars in paths
    invalid_chars = '<>|"?*'
    if any(c in s for c in invalid_chars):
        return False

    s_lower = s.lower()
    
    # 1. Standard Path: contains "\"
    if "\\" in s: return True
    
    # 2. Executable: contains ".exe" (case insensitive)
    if ".exe" in s_lower: return True
    
    # 3. UWP Package: contains "." (e.g., Microsoft.GamingApp) AND is long enough
    if "." in s and len(s) > 10: 
        return True
        
    return False

def brute_force_shimcache(filepath, output_csv=None):
    print(f"[*] Targeting: {filepath}")
    print("[*] Mode: BERSERK (Ignoring Hive Structure)")
    
    results = []

    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except IOError as e:
        print(f"[!] Error opening file: {e}")
        return

    # 1. 10ts Header Search
    print("[*] Scanning for '10ts' signatures...")
    regex = re.compile(b'\x31\x30\x74\x73....[\x00-\x88][\x00-\x13]\x00\x00', re.DOTALL)

    for match in regex.finditer(data):
        offset = match.start()
        
        try:
            sig, unk, count = struct.unpack('<4sII', data[offset:offset+12])
        except:
            continue

        if count == 0:
            continue

        print(f"[+] Found Shimcache Header at 0x{offset:X} | Entries: {count}")
        
        current_pos = offset + 12
        parsed_count = 0
        
        # Heuristic: Skip to first valid-looking entry
        while current_pos < offset + 512:
            if current_pos + 4 >= len(data): break
            
            try:
                path_len = struct.unpack('<H', data[current_pos:current_pos+2])[0]
                if 4 <= path_len < 1024:
                    try:
                        candidate_str = data[current_pos+2 : current_pos+2+path_len].decode('utf-16le')
                        if is_likely_path(candidate_str):
                            break
                    except:
                        pass
            except:
                pass
            current_pos += 1

        # Extraction Loop
        while parsed_count < count and current_pos < len(data):
            try:
                # Skip '10ts' signature if present (start of entry)
                if data[current_pos:current_pos+4] == b'10ts':
                    current_pos += 4
                
                if current_pos + 2 > len(data): break
                path_size = struct.unpack('<H', data[current_pos:current_pos+2])[0]
                
                if path_size == 0 or path_size > 4096:
                    current_pos += 1
                    continue
                
                # Path String
                path_str_raw = data[current_pos+2 : current_pos+2+path_size]
                try:
                    path_str = path_str_raw.decode('utf-16le').replace('\0', '').strip()
                except:
                    path_str = "<Decode Error>"
                
                # Timestamp
                ts_offset = current_pos + 2 + path_size
                if ts_offset + 8 > len(data): break
                
                ts_bytes = data[ts_offset : ts_offset+8]
                ts_str = parse_filetime(ts_bytes)
                
                # Store result
                entry_data = {
                    "Offset": f"0x{current_pos:08X}",
                    "Size": path_size,
                    "ModifiedTime": ts_str,
                    "Path": path_str
                }
                results.append(entry_data)
                
                # Heuristic Jump to Next Entry
                scan_ptr = ts_offset + 8
                found_next = False
                
                for i in range(256): 
                    if scan_ptr + 4 > len(data): break
                    
                    # Check for '10ts' signature
                    if data[scan_ptr:scan_ptr+4] == b'10ts':
                        current_pos = scan_ptr
                        found_next = True
                        break

                    # Check for valid path size + path content
                    try:
                        possible_size = struct.unpack('<H', data[scan_ptr:scan_ptr+2])[0]
                        if 4 <= possible_size < 1024:
                            check_str = data[scan_ptr+2 : scan_ptr+2+possible_size].decode('utf-16le')
                            if is_likely_path(check_str):
                                current_pos = scan_ptr
                                found_next = True
                                break
                    except:
                        pass
                    
                    scan_ptr += 1
                
                if not found_next:
                    current_pos = ts_offset + 8
                
                parsed_count += 1
                
            except Exception as e:
                current_pos += 1
                continue

    # Output
    print("-" * 80)
    print(f"{'Offset':<10} | {'Size':<6} | {'Modified Time (UTC)':<22} | {'Path'}")
    print("-" * 80)
    for r in results:
        try:
            print(f"{r['Offset']:<10} | {r['Size']:<6} | {r['ModifiedTime']:<22} | {r['Path'][:80]}")
        except UnicodeEncodeError:
            # Safe print for environments that don't support certain characters
            safe_path = r['Path'][:80].encode('utf-8', 'replace').decode('utf-8')
            print(f"{r['Offset']:<10} | {r['Size']:<6} | {r['ModifiedTime']:<22} | {safe_path}")
            
    print("-" * 80)
    print(f"[*] Total Entries Found: {len(results)}")

    if output_csv:
        try:
            with open(output_csv, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.DictWriter(f, fieldnames=["Offset", "Size", "ModifiedTime", "Path"])
                writer.writeheader()
                writer.writerows(results)
            print(f"[+] CSV saved to: {output_csv}")
        except IOError as e:
            print(f"[!] Error saving CSV: {e}")

if __name__ == "__main__":
    banner = """
  ____  _     _             ____                  _             
 / ___|| |__ (_)_ __ ___   | __ ) _ __ ___  _ __| | _____ _ __ 
 \___ \| '_ \| | '_ ` _ \  |  _ \| '__/ _ \| '__| |/ / _ \ '__|
  ___) | | | | | | | | | | | |_) | | |  __/ |  |   <  __/ |   
 |____/|_| |_|_|_| |_| |_| |____/|_|  \___|_|  |_|\_\___|_|   
    
    Structure-Agnostic ShimCache Extractor
    """
    print(banner)

    parser = argparse.ArgumentParser(
        description="Extract ShimCache from corrupted hives or raw data by carving '10ts' signatures.",
        epilog="WARNING: This tool ignores hive structures. Use for data recovery/carving only."
    )
    
    parser.add_argument("filepath", help="Path to SYSTEM hive, memory dump, or raw binary file")
    parser.add_argument("-o", "--output", help="Path to save results as CSV", default=None)
    
    args = parser.parse_args()
    
    if not os.path.exists(args.filepath):
        print(f"[!] Target file not found: {args.filepath}")
        sys.exit(1)
        
    brute_force_shimcache(args.filepath, args.output)
