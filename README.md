# Ubiquiti Device Discovery Tool (Python Edition)

A modern, cross-platform **Python** replacement for the legacy Java-based
**UBNT Discovery Tool**. It discovers Ubiquiti devices on your local network by
sending UDP broadcast packets on port `10001` and parsing the TLV-encoded
responses — all in a clean tkinter desktop GUI, with **no external
dependencies**.

> The original Java tool (`ubnt-discovery-v2.5.1.jar`) no longer runs on modern
> Java (9+) because of a `ClassFormatError` caused by illegal class field names.
> This project rebuilds it from scratch in Python 3.

**Author:** shujaa ahmed issa · **License:** MIT

---

## ✨ Features

- **UBNT Discovery Protocol** — sends V1 + V2 UDP broadcast packets on port 10001
  and parses the TLV responses from Ubiquiti devices.
- **Desktop GUI (tkinter):**
  - Device table: Product Name, IP Address, Hardware (MAC) Address, System Name,
    SSID, Firmware, Uptime.
  - Scan button with a 4-second countdown timer.
  - Sortable columns (IP addresses sort numerically).
  - Live search / filter across all columns.
  - Double-click a device for a full details dialog.
  - Right-click menu: Copy IP, Copy MAC, Open Web UI.
  - Clear button to reset results.
- **Multi-interface support** — broadcasts on every local network interface.
- **Cross-platform** — Windows, Linux, and macOS.

---

## 📋 Requirements

- **Python 3.x** with **tkinter** (bundled with most Python installations).
- No third-party packages required.

---

## 🚀 Run from source

```bash
python ubnt_discovery.py
```

On **Windows** you can also just double-click `ubnt-discovery-py.bat`.

---

## 🛠️ Build a standalone Windows .exe

The build artifacts (`build/`, `dist/`, `*.exe`) are intentionally **not**
committed. Build them yourself with [PyInstaller](https://pyinstaller.org/):

```bash
pip install pyinstaller
python build_exe.py
```

This produces `dist/UBNT-Discovery.exe` (single-file, windowed). The
`UBNT-Discovery.spec` file holds the PyInstaller configuration.

### Optional: build a Windows installer

An [Inno Setup](https://jrsoftware.org/isinfo.php) script (`installer.iss`) is
included. After building the `.exe`, compile `installer.iss` with Inno Setup to
produce `UBNT-Discovery-Setup-1.0.0.exe`.

---

## 🤝 Contributing

Issues and pull requests are welcome — the goal is for anyone to use, modify, and
improve the tool. The entire application lives in a single, dependency-free file
(`ubnt_discovery.py`), so it's easy to read and hack on.

---

## 📄 License

Released under the [MIT License](LICENSE) — © 2026 **shujaa ahmed issa**.
