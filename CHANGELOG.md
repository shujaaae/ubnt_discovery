# Ubiquiti Device Discovery Tool - Change Log

**Author:** shujaa ahmed issa · **License:** MIT

## v1.0.0 (2026-03-17)

### New: Python-based Discovery Tool
The original Java tool (`ubnt-discovery-v2.5.1.jar`) no longer works on modern Java versions (Java 9+) due to illegal class field names (`ClassFormatError`). A full Python replacement was built from scratch.

### Files Added
- **`ubnt_discovery.py`** — Main application (Python 3 + tkinter, no external dependencies)
- **`ubnt-discovery-py.bat`** — Windows launcher (double-click to run)

### Features
- **UBNT Discovery Protocol**: Sends UDP broadcast packets (V1 + V2) on port 10001 and parses TLV-encoded responses from Ubiquiti devices
- **Desktop GUI** (tkinter):
  - Device table with columns: Product Name, IP Address, Hardware Address, System Name, SSID, Firmware, Uptime
  - Scan button with countdown timer (4-second scan window)
  - Sortable columns (click headers to sort; IP addresses sort numerically)
  - Live search/filter across all columns
  - Double-click a device to view full details dialog
  - Right-click context menu: Copy IP, Copy MAC, Open Web UI
  - Clear button to reset results
- **Multi-interface support**: Broadcasts on all local network interfaces
- **Cross-platform**: Works on Windows, Linux, and macOS

### Requirements
- Python 3.x (with tkinter — included by default in most Python installations)
- No external packages needed

### How to Run
```
python ubnt_discovery.py
```
Or double-click `ubnt-discovery-py.bat` on Windows.
