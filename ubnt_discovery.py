"""
Ubiquiti Device Discovery Tool
A Python replacement for the legacy Java-based UBNT Discovery Tool.
Discovers Ubiquiti devices on the local network via UDP broadcast on port 10001.

Author:  shujaa ahmed issa
License: MIT
Repo:    https://github.com/shujaaae/ubnt_discovery
"""

__author__ = "shujaa ahmed issa"
__license__ = "MIT"
__version__ = "1.0.0"

import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import threading
import time
import tkinter as tk
from tkinter import ttk
import webbrowser

# ─── Constants ────────────────────────────────────────────────────────────────

UBNT_PORT = 10001
DISCOVERY_V1 = b'\x01\x00\x00\x00'
DISCOVERY_V2 = b'\x02\x00\x00\x00'
BROADCAST_ADDR = '255.255.255.255'
SCAN_TIMEOUT = 4
PING_TIMEOUT_MS = 1000
CONFIG_FILE = os.path.join(os.path.expanduser('~'), '.ubnt_discovery_config.json')

# TLV Field Type IDs
FIELD_HW_ADDR     = 0x01
FIELD_IP_INFO     = 0x02
FIELD_FW_VERSION  = 0x03
FIELD_RADIO_NAME  = 0x05
FIELD_HOSTNAME    = 0x0B
FIELD_MODEL_SHORT = 0x0C
FIELD_ESSID       = 0x0D
FIELD_UPTIME      = 0x0E
FIELD_MODEL_LONG  = 0x14
FIELD_SYSTEM_ID   = 0x17


# ─── TLV Parser ──────────────────────────────────────────────────────────────

def format_mac(data):
    return ':'.join(f'{b:02X}' for b in data)


def format_uptime(seconds):
    days = seconds // 86400
    remaining = seconds % 86400
    hours = remaining // 3600
    remaining %= 3600
    minutes = remaining // 60
    secs = remaining % 60
    if days > 0:
        return f'{days}d {hours:02d}:{minutes:02d}:{secs:02d}'
    return f'{hours:02d}:{minutes:02d}:{secs:02d}'


def parse_discovery_response(data):
    """Parse a UBNT discovery TLV response packet into a device dict."""
    device = {
        'mac': '', 'ip': '', 'ips': [], 'macs': [], 'interfaces': [],
        'firmware': '', 'hostname': '',
        'model_short': '', 'model_long': '', 'essid': '',
        'uptime_seconds': 0, 'uptime_str': '', 'radio_name': '',
        'system_id': 0,
    }

    if len(data) < 4:
        return None

    offset = 4  # skip header
    while offset + 3 <= len(data):
        try:
            field_type = data[offset]
            field_len = struct.unpack('>H', data[offset + 1:offset + 3])[0]
            field_data = data[offset + 3:offset + 3 + field_len]
            offset += 3 + field_len

            if len(field_data) < field_len:
                break

            if field_type == FIELD_HW_ADDR and len(field_data) >= 6:
                device['mac'] = format_mac(field_data[:6])

            elif field_type == FIELD_IP_INFO and len(field_data) >= 10:
                iface_mac = format_mac(field_data[:6])
                iface_ip = socket.inet_ntoa(field_data[6:10])
                if not device['mac']:
                    device['mac'] = iface_mac
                # keep first IP as the "primary" for ping / web UI
                if not device['ip']:
                    device['ip'] = iface_ip
                if iface_ip not in device['ips']:
                    device['ips'].append(iface_ip)
                if iface_mac not in device['macs']:
                    device['macs'].append(iface_mac)
                device['interfaces'].append((iface_mac, iface_ip))

            elif field_type == FIELD_FW_VERSION:
                device['firmware'] = field_data.decode('utf-8', errors='replace').strip('\x00')

            elif field_type == FIELD_RADIO_NAME:
                device['radio_name'] = field_data.decode('utf-8', errors='replace').strip('\x00')

            elif field_type == FIELD_HOSTNAME:
                device['hostname'] = field_data.decode('utf-8', errors='replace').strip('\x00')

            elif field_type == FIELD_MODEL_SHORT:
                device['model_short'] = field_data.decode('utf-8', errors='replace').strip('\x00')

            elif field_type == FIELD_ESSID:
                device['essid'] = field_data.decode('utf-8', errors='replace').strip('\x00')

            elif field_type == FIELD_UPTIME and len(field_data) >= 4:
                device['uptime_seconds'] = struct.unpack('>I', field_data[:4])[0]
                device['uptime_str'] = format_uptime(device['uptime_seconds'])

            elif field_type == FIELD_MODEL_LONG:
                device['model_long'] = field_data.decode('utf-8', errors='replace').strip('\x00')

            elif field_type == FIELD_SYSTEM_ID and len(field_data) >= 2:
                device['system_id'] = struct.unpack('>H', field_data[:2])[0]

        except Exception:
            offset += 1
            continue

    return device


# ─── Network Discovery ───────────────────────────────────────────────────────

def get_local_ips():
    """Get all local IPv4 addresses for broadcasting on each interface."""
    ips = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except Exception:
        pass
    ips.discard('127.0.0.1')
    if not ips:
        ips.add('0.0.0.0')
    return list(ips)


def parse_target_range(target_str):
    """Parse IP or CIDR string into list of target IPs.
    Returns (list_of_ips | None, error_string | None)."""
    target_str = target_str.strip()
    if not target_str:
        return None, None
    try:
        if '/' in target_str:
            network = ipaddress.IPv4Network(target_str, strict=False)
            hosts = list(network.hosts())
            if len(hosts) > 4094:
                return None, f'Range too large ({len(hosts)} hosts). Max /20.'
            return [str(h) for h in hosts], None
        else:
            addr = ipaddress.IPv4Address(target_str)
            return [str(addr)], None
    except ValueError as e:
        return None, str(e)


def discover_devices(timeout=SCAN_TIMEOUT, on_device=None, stop_event=None,
                     interfaces=None, targets=None):
    """
    Send UBNT discovery broadcasts and collect responses.
    on_device: optional callback(device_dict) called for each discovered device.
    stop_event: optional threading.Event to cancel scan early.
    interfaces: list of local IPs to bind to (None = all).
    targets: list of destination IPs for unicast (None = broadcast).
    Returns dict of {mac: device_dict}.
    """
    devices = {}
    local_ips = interfaces if interfaces else get_local_ips()
    destinations = targets if targets else [BROADCAST_ADDR]

    # Create one socket per interface to avoid rebind issues
    socks = []
    for local_ip in local_ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(0.5)
            s.bind((local_ip, 0))
            socks.append(s)
        except Exception:
            pass

    # Fallback: unbound socket if no interface could be bound
    if not socks:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(0.5)
        socks.append(s)

    try:
        # Send discovery packets from each socket to each destination
        for s in socks:
            for dest_ip in destinations:
                for packet in (DISCOVERY_V1, DISCOVERY_V2):
                    try:
                        s.sendto(packet, (dest_ip, UBNT_PORT))
                    except Exception:
                        pass

        # Listen for responses on all sockets
        end_time = time.time() + timeout
        while time.time() < end_time:
            if stop_event and stop_event.is_set():
                break
            for s in socks:
                try:
                    data, addr = s.recvfrom(65535)
                    device = parse_discovery_response(data)
                    if device and device['mac']:
                        existing = devices.get(device['mac'])
                        if existing:
                            # merge IP/MAC lists from this response into the existing record
                            for ip in device.get('ips', []):
                                if ip not in existing['ips']:
                                    existing['ips'].append(ip)
                            for m in device.get('macs', []):
                                if m not in existing['macs']:
                                    existing['macs'].append(m)
                            for pair in device.get('interfaces', []):
                                if pair not in existing['interfaces']:
                                    existing['interfaces'].append(pair)
                            if not existing.get('ip') and device.get('ip'):
                                existing['ip'] = device['ip']
                            # fill in any text fields that were empty
                            for k in ('firmware', 'hostname', 'model_short',
                                      'model_long', 'essid', 'radio_name',
                                      'uptime_str'):
                                if not existing.get(k) and device.get(k):
                                    existing[k] = device[k]
                            if not existing.get('uptime_seconds') and device.get('uptime_seconds'):
                                existing['uptime_seconds'] = device['uptime_seconds']
                            if not existing.get('system_id') and device.get('system_id'):
                                existing['system_id'] = device['system_id']
                        else:
                            devices[device['mac']] = device
                        if on_device:
                            on_device(devices[device['mac']])
                except socket.timeout:
                    continue
                except Exception:
                    continue
    finally:
        for s in socks:
            s.close()

    return devices


# ─── GUI Application ─────────────────────────────────────────────────────────

COLUMNS = [
    ('product',  'Product Name',    180),
    ('ip',       'IP Address(es)',  220),
    ('mac',      'Hardware Address', 150),
    ('hostname', 'System Name',     120),
    ('essid',    'SSID',            100),
    ('firmware', 'Firmware',        140),
    ('uptime',   'Uptime',          110),
    ('ping',     'Ping',             80),
]


def ping_ip(ip, timeout_ms=PING_TIMEOUT_MS):
    """Ping an IP address once. Returns latency string (e.g. '12ms') or 'Timeout'."""
    try:
        if os.name == 'nt':
            cmd = ['ping', '-n', '1', '-w', str(timeout_ms), ip]
            creation_flags = subprocess.CREATE_NO_WINDOW
        else:
            cmd = ['ping', '-c', '1', '-W', str(timeout_ms // 1000 or 1), ip]
            creation_flags = 0

        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout_ms / 1000 + 2,
            creationflags=creation_flags,
        )
        if result.returncode == 0:
            match = re.search(r'time[<=](\d+)\s*ms', result.stdout, re.IGNORECASE)
            if match:
                return f'{match.group(1)}ms'
            return '<1ms'
        return 'Timeout'
    except Exception:
        return 'Timeout'


class DiscoveryApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Ubiquiti Device Discovery')
        self.geometry('960x540')
        self.minsize(800, 400)

        self._devices = {}
        self._scan_thread = None
        self._stop_event = threading.Event()
        self._countdown = 0
        self._sort_col = None
        self._sort_reverse = False
        self._all_items = []  # for filtering

        self._build_ui()
        self._apply_theme()
        self._load_config()
        self.protocol('WM_DELETE_WINDOW', self._on_close)

    def _build_ui(self):
        # ── Toolbar Row 1 ──
        toolbar1 = ttk.Frame(self, padding=(5, 5, 5, 0))
        toolbar1.pack(fill=tk.X)

        self._scan_btn = ttk.Button(toolbar1, text='Scan', command=self._start_scan, width=12)
        self._scan_btn.pack(side=tk.LEFT, padx=(0, 4))

        self._clear_btn = ttk.Button(toolbar1, text='Clear', command=self._clear_table, width=8)
        self._clear_btn.pack(side=tk.LEFT, padx=(0, 12))

        ttk.Label(toolbar1, text='Search:').pack(side=tk.LEFT, padx=(0, 4))
        self._search_var = tk.StringVar()
        self._search_var.trace_add('write', lambda *_: self._filter_devices())
        search_entry = ttk.Entry(toolbar1, textvariable=self._search_var, width=25)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # ── Toolbar Row 2 (Network Options) ──
        toolbar2 = ttk.Frame(self, padding=(5, 2, 5, 2))
        toolbar2.pack(fill=tk.X)

        ttk.Label(toolbar2, text='Interface:').pack(side=tk.LEFT, padx=(0, 4))
        self._iface_var = tk.StringVar(value='All Interfaces')
        self._iface_combo = ttk.Combobox(toolbar2, textvariable=self._iface_var,
                                         state='readonly', width=18)
        self._refresh_interfaces()
        self._iface_combo.pack(side=tk.LEFT, padx=(0, 12))

        ttk.Label(toolbar2, text='Target:').pack(side=tk.LEFT, padx=(0, 4))
        self._target_var = tk.StringVar()
        target_entry = ttk.Entry(toolbar2, textvariable=self._target_var, width=22)
        target_entry.pack(side=tk.LEFT, padx=(0, 4))
        ttk.Label(toolbar2, text='(IP or CIDR, e.g. 192.168.1.0/24)',
                  foreground='gray').pack(side=tk.LEFT)

        # ── Treeview ──
        tree_frame = ttk.Frame(self)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 0))

        col_ids = [c[0] for c in COLUMNS]
        self._tree = ttk.Treeview(tree_frame, columns=col_ids, show='headings', selectmode='browse')

        for col_id, col_name, col_width in COLUMNS:
            self._tree.heading(col_id, text=col_name,
                               command=lambda c=col_id: self._sort_column(c))
            self._tree.column(col_id, width=col_width, minwidth=60)

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self._tree.yview)
        self._tree.configure(yscrollcommand=scrollbar.set)
        self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self._tree.bind('<Double-1>', self._show_details)
        self._tree.bind('<Button-3>', self._show_context_menu)

        # ── Context Menu ──
        self._context_menu = tk.Menu(self, tearoff=0)
        self._context_menu.add_command(label='Copy IP', command=self._copy_ip)
        self._context_menu.add_command(label='Copy MAC', command=self._copy_mac)
        self._context_menu.add_separator()
        self._context_menu.add_command(label='Open Web UI', command=self._open_web_ui)

        # ── Status Bar ──
        status_frame = ttk.Frame(self, padding=(5, 3))
        status_frame.pack(fill=tk.X)

        self._count_label = ttk.Label(status_frame, text='Total: 0 devices')
        self._count_label.pack(side=tk.LEFT)

        self._status_label = ttk.Label(status_frame, text='Ready')
        self._status_label.pack(side=tk.RIGHT)

    def _apply_theme(self):
        style = ttk.Style(self)
        available = style.theme_names()
        for preferred in ('vista', 'clam', 'winnative', 'default'):
            if preferred in available:
                style.theme_use(preferred)
                break

        style.configure('Treeview', rowheight=24)
        self._tree.tag_configure('even', background='#F5F5F5')
        self._tree.tag_configure('odd', background='#FFFFFF')

    def _refresh_interfaces(self):
        ips = get_local_ips()
        self._iface_combo['values'] = ['All Interfaces'] + ips
        self._iface_var.set('All Interfaces')

    # ── Scan ──────────────────────────────────────────────────────────────

    def _start_scan(self):
        if self._scan_thread and self._scan_thread.is_alive():
            return

        # Parse interface selection
        iface = self._iface_var.get()
        if iface == 'All Interfaces':
            self._scan_interfaces = None
        else:
            self._scan_interfaces = [iface]

        # Parse target range
        target_str = self._target_var.get().strip()
        self._scan_targets = None
        if target_str:
            targets, error = parse_target_range(target_str)
            if error:
                self._status_label.configure(text=f'Invalid target: {error}')
                return
            self._scan_targets = targets

        self._scan_btn.configure(state='disabled')
        self._stop_event.clear()
        self._countdown = SCAN_TIMEOUT
        self._status_label.configure(text=f'Scanning ({self._countdown}s)...')

        self._scan_thread = threading.Thread(target=self._scan_worker, daemon=True)
        self._scan_thread.start()
        self._tick_countdown()

    def _scan_worker(self):
        try:
            devices = discover_devices(
                timeout=SCAN_TIMEOUT,
                stop_event=self._stop_event,
                interfaces=self._scan_interfaces,
                targets=self._scan_targets,
            )
            self.after(0, self._on_scan_complete, devices)
        except Exception as e:
            self.after(0, self._on_scan_error, str(e))

    def _tick_countdown(self):
        if self._scan_thread and self._scan_thread.is_alive():
            self._countdown -= 1
            if self._countdown >= 0:
                self._scan_btn.configure(text=f'Scanning ({self._countdown}s)')
                self._status_label.configure(text=f'Scanning ({self._countdown}s)...')
            self.after(1000, self._tick_countdown)

    def _on_scan_complete(self, devices):
        self._devices.update(devices)
        self._populate_table()
        self._scan_btn.configure(state='normal', text='Scan')
        self._status_label.configure(text=f'Scan complete — {len(self._devices)} device(s) found. Pinging...')
        self._start_ping_workers()

    def _on_scan_error(self, error_msg):
        self._scan_btn.configure(state='normal', text='Scan')
        self._status_label.configure(text=f'Error: {error_msg}')

    # ── Ping ─────────────────────────────────────────────────────────────

    def _start_ping_workers(self):
        devices_to_ping = [(mac, dev['ip']) for mac, dev in self._devices.items()
                           if dev.get('ip')]
        if not devices_to_ping:
            return

        def ping_worker(mac, ip):
            result = ping_ip(ip)
            self.after(0, self._update_ping_result, mac, result)

        for mac, ip in devices_to_ping:
            t = threading.Thread(target=ping_worker, args=(mac, ip), daemon=True)
            t.start()

    def _update_ping_result(self, mac, ping_result):
        if mac in self._devices:
            self._devices[mac]['ping'] = ping_result

        # Update treeview item if visible
        if self._tree.exists(mac):
            current = list(self._tree.item(mac, 'values'))
            current[-1] = ping_result
            self._tree.item(mac, values=tuple(current))

        # Update _all_items for filter consistency
        for i, (item_mac, values) in enumerate(self._all_items):
            if item_mac == mac:
                values_list = list(values)
                values_list[-1] = ping_result
                self._all_items[i] = (item_mac, tuple(values_list))
                break

        # Check if all pings are done
        all_done = all(dev.get('ping', '...') != '...'
                       for dev in self._devices.values() if dev.get('ip'))
        if all_done:
            self._status_label.configure(
                text=f'Scan complete — {len(self._devices)} device(s) found')

    # ── Table ─────────────────────────────────────────────────────────────

    def _device_to_row(self, dev):
        ips = dev.get('ips') or ([dev['ip']] if dev.get('ip') else [])
        macs = dev.get('macs') or ([dev['mac']] if dev.get('mac') else [])
        return (
            dev.get('model_long') or dev.get('model_short') or '',
            ', '.join(ips),
            ', '.join(macs) if len(macs) > 1 else (macs[0] if macs else ''),
            dev.get('hostname', ''),
            dev.get('essid', ''),
            dev.get('firmware', ''),
            dev.get('uptime_str', ''),
            dev.get('ping', '...'),
        )

    def _populate_table(self):
        self._tree.delete(*self._tree.get_children())
        self._all_items = []

        for i, (mac, dev) in enumerate(self._devices.items()):
            values = self._device_to_row(dev)
            tag = 'even' if i % 2 == 0 else 'odd'
            item_id = self._tree.insert('', tk.END, iid=mac, values=values, tags=(tag,))
            self._all_items.append((mac, values))

        self._count_label.configure(text=f'Total: {len(self._devices)} devices')
        self._filter_devices()

    def _clear_table(self):
        self._devices.clear()
        self._all_items.clear()
        self._tree.delete(*self._tree.get_children())
        self._count_label.configure(text='Total: 0 devices')
        self._status_label.configure(text='Cleared')

    # ── Sort ──────────────────────────────────────────────────────────────

    def _sort_column(self, col):
        if self._sort_col == col:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_col = col
            self._sort_reverse = False

        col_index = [c[0] for c in COLUMNS].index(col)
        items = [(self._tree.set(iid, col), iid) for iid in self._tree.get_children()]

        if col == 'ip':
            def ip_key(val):
                try:
                    return socket.inet_aton(val[0])
                except Exception:
                    return b'\xff\xff\xff\xff'
            items.sort(key=ip_key, reverse=self._sort_reverse)
        elif col == 'ping':
            def ping_key(val):
                text = val[0]
                if text and text not in ('...', 'Timeout'):
                    try:
                        return int(text.replace('ms', '').replace('<', ''))
                    except ValueError:
                        return 99999
                return 99999 if text == 'Timeout' else 100000
            items.sort(key=ping_key, reverse=self._sort_reverse)
        else:
            items.sort(key=lambda x: x[0].lower(), reverse=self._sort_reverse)

        for idx, (_, iid) in enumerate(items):
            self._tree.move(iid, '', idx)
            tag = 'even' if idx % 2 == 0 else 'odd'
            self._tree.item(iid, tags=(tag,))

        # Update heading to show sort indicator
        for c_id, c_name, _ in COLUMNS:
            indicator = ''
            if c_id == col:
                indicator = ' ▼' if self._sort_reverse else ' ▲'
            self._tree.heading(c_id, text=c_name + indicator)

    # ── Filter ────────────────────────────────────────────────────────────

    def _filter_devices(self):
        query = self._search_var.get().strip().lower()
        self._tree.delete(*self._tree.get_children())

        visible = 0
        for i, (mac, values) in enumerate(self._all_items):
            if query and not any(query in v.lower() for v in values):
                continue
            tag = 'even' if visible % 2 == 0 else 'odd'
            self._tree.insert('', tk.END, iid=mac, values=values, tags=(tag,))
            visible += 1

        self._count_label.configure(text=f'Total: {visible} devices')

    # ── Details Dialog ────────────────────────────────────────────────────

    def _get_selected_device(self):
        sel = self._tree.selection()
        if not sel:
            return None
        mac = sel[0]
        return self._devices.get(mac)

    def _show_details(self, event=None):
        dev = self._get_selected_device()
        if not dev:
            return

        dlg = tk.Toplevel(self)
        dlg.title('Device Details')
        dlg.geometry('480x420')
        dlg.resizable(False, False)
        dlg.transient(self)
        dlg.grab_set()

        frame = ttk.Frame(dlg, padding=15)
        frame.pack(fill=tk.BOTH, expand=True)

        interfaces = dev.get('interfaces') or []
        if interfaces:
            iface_text = '\n'.join(f'{ip}  ({mac})' for mac, ip in interfaces)
        else:
            iface_text = f"{dev.get('ip', '')}  ({dev.get('mac', '')})"

        fields = [
            ('Product Name', dev.get('model_long') or dev.get('model_short', '')),
            ('Interfaces', iface_text),
            ('System Name', dev.get('hostname', '')),
            ('Firmware', dev.get('firmware', '')),
            ('SSID', dev.get('essid', '')),
            ('Radio Name', dev.get('radio_name', '')),
            ('Uptime', dev.get('uptime_str', '')),
            ('System ID', hex(dev.get('system_id', 0)) if dev.get('system_id') else ''),
            ('Ping', dev.get('ping', '')),
        ]

        for row, (label, value) in enumerate(fields):
            ttk.Label(frame, text=label + ':', font=('Segoe UI', 9, 'bold')).grid(
                row=row, column=0, sticky=tk.W, pady=2, padx=(0, 10))
            ttk.Label(frame, text=value, font=('Segoe UI', 9)).grid(
                row=row, column=1, sticky=tk.W, pady=2)

        ttk.Button(frame, text='Close', command=dlg.destroy, width=10).grid(
            row=len(fields), column=0, columnspan=2, pady=(15, 0))

    # ── Context Menu ──────────────────────────────────────────────────────

    def _show_context_menu(self, event):
        iid = self._tree.identify_row(event.y)
        if iid:
            self._tree.selection_set(iid)
            self._context_menu.tk_popup(event.x_root, event.y_root)

    def _copy_ip(self):
        dev = self._get_selected_device()
        if dev and dev.get('ip'):
            self.clipboard_clear()
            self.clipboard_append(dev['ip'])

    def _copy_mac(self):
        dev = self._get_selected_device()
        if dev and dev.get('mac'):
            self.clipboard_clear()
            self.clipboard_append(dev['mac'])

    def _open_web_ui(self):
        dev = self._get_selected_device()
        if dev and dev.get('ip'):
            webbrowser.open(f'https://{dev["ip"]}')


    # ── Config Persistence ─────────────────────────────────────────────────

    def _load_config(self):
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
            geo = config.get('geometry')
            if geo:
                self.geometry(geo)
        except Exception:
            pass

    def _save_config(self):
        config = {}
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
        except Exception:
            pass
        config['geometry'] = self.geometry()
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception:
            pass

    def _on_close(self):
        self._save_config()
        self.destroy()


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == '__main__':
    app = DiscoveryApp()
    app.mainloop()
