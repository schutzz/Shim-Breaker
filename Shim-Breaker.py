import sys
import struct
import datetime
import re
import argparse
import csv
import os

def parse_filetime(ft_bytes):
    """
    Windows FILETIME (8 bytes) -> datetime string
    """
    (ft_int,) = struct.unpack('<Q', ft_bytes)
    if ft_int == 0:
        return "N/A"
    
    try:
        dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft_int / 10)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return f"Invalid Time ({hex(ft_int)})"

def is_likely_path(s):
    if not s: return False
    
    # Check for common invalid chars in paths
    invalid_chars = '<>|"?*'
    if any(c in s for c in invalid_chars):
        return False

    # Logic Update:
    # 1. Standard Path: contains "\"
    # 2. Executable: contains ".exe" (case insensitive)
    # 3. UWP Package: contains "." (e.g., Microsoft.GamingApp) AND is long enough
    
    s_lower = s.lower()
    if "\\" in s: return True
    if ".exe" in s_lower: return True
    
    # UWP判定の追加: ドットを含み、かつある程度の長さがある
    if "." in s and len(s) > 10: 
        return True
        
    return False

def brute_force_shimcache(filepath, output_csv=None):
    print(f"[*] Targeting: {filepath}")
    print("[*] Mode: FORCEFUL EXTRACTION (Ignoring Hive Structure)")
    
    results = []

    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except IOError as e:
        print(f"[!] Error opening file: {e}")
        return

    # 1. 10ts Header Search
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
        # Search for a valid path length followed by a valid path string
        while current_pos < offset + 512: # Increased search range
            if current_pos + 4 >= len(data): break
            
            # Check if this looks like a path size
            try:
                path_len = struct.unpack('<H', data[current_pos:current_pos+2])[0]
                if 4 <= path_len < 1024:
                    # Check if followed by valid UTF-16 string
                    try:
                        candidate_str = data[current_pos+2 : current_pos+2+path_len].decode('utf-16le')
                        if is_likely_path(candidate_str):
                            # Found it!
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
                
                # Path Size
                if current_pos + 2 > len(data): break
                path_size = struct.unpack('<H', data[current_pos:current_pos+2])[0]
                
                if path_size == 0 or path_size > 4096:
                    # Invalid size, try to resync
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
                # Scan forward for the next valid structure
                scan_ptr = ts_offset + 8
                found_next = False
                
                # Scan limit
                for i in range(256): 
                    if scan_ptr + 4 > len(data): break
                    
                    # 1. Check for '10ts' signature
                    if data[scan_ptr:scan_ptr+4] == b'10ts':
                        current_pos = scan_ptr # Found next entry signature
                        found_next = True
                        break

                    # 2. Check for valid path size + path content directly
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
                    # If we can't find the next entry, we might be done or lost
                    # But let's try to continue scanning from where we left off just in case
                    current_pos = ts_offset + 8
                
                parsed_count += 1
                
            except Exception as e:
                # print(f"  [!] Parse error at 0x{current_pos:X}: {e}")
                current_pos += 1
                continue

    # Output
    print("-" * 80)
    print(f"{'Offset':<10} | {'Size':<6} | {'Modified Time (UTC)':<22} | {'Path'}")
    print("-" * 80)
    for r in results:
        print(f"{r['Offset']:<10} | {r['Size']:<6} | {r['ModifiedTime']:<22} | {r['Path'][:80]}")
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
    parser = argparse.ArgumentParser(description="ShimCache Brute Force Extractor")
    parser.add_argument("filepath", help="Path to SYSTEM hive or raw binary file")
    parser.add_argument("-o", "--output", help="Path to save CSV output")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.filepath):
        print(f"[!] File not found: {args.filepath}")
        sys.exit(1)
        
    brute_force_shimcache(args.filepath, args.output)