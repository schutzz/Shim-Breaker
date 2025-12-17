# 🔨 Shim-Breaker

> **"Break the Hive, Seize the Evidence."**

**Shim-Breaker** is a ruthless, structure-agnostic extractor for Windows ShimCache (AppCompatCache). 
It does not care about Registry Hive headers, bin structures, or cell indexes. It simply carves the raw binary to find what remains.

![Python](https://img.shields.io/badge/Python-3.x-blue.svg) ![License](https://img.shields.io/badge/License-MIT-green.svg) ![Forensics](https://img.shields.io/badge/Category-DFIR-red.svg)

## 💀 The Problem

Standard forensic tools (like Zimmerman's *AppCompatCacheParser* or Volatility plugins) are excellent, but they are "civilized". They rely on a healthy Registry Hive structure (`hbin`, cells, indexes).

But in the real world of Incident Response:
* **Hives get corrupted.** (BSOD, power failure, anti-forensics)
* **Headers get wiped.**
* **You only have a raw memory dump or a carved chunk of disk.**

When the structure is broken, civilized tools fail. **That's when you need a Breaker.**

## 🛠️ How It Works

Shim-Breaker ignores the file system logic completely.

1.  **Brute-Force Scanning**: It hunts down the `10ts` (0x73743031) signature used in Windows 10/11 ShimCache headers directly within the raw binary stream.
2.  **Heuristic Parsing**: Once a header is found, it blindly attempts to parse the following bytes as variable-length entries, applying strict validation logic to separate valid file paths from garbage data.
3.  **Physical Extraction**: It pulls out the File Path, Modified Timestamp ($Standard_Info), and Execution Flags.

**It acts as a "Last Resort" weapon when all other parsers return 0 entries.**

## 📦 Usage

No complex dependencies. Just Python standard libraries.

```bash
# Basic usage against a SYSTEM hive file
python shim_breaker.py C:\Evidence\SYSTEM --output result.csv

# Run against a raw memory dump or unallocated space chunk
python shim_breaker.py D:\dumps\memory.dmp -o evidence.csv
