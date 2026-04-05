"""
NetScan Pro — Advanced Network Port Scanner
Author : dhanish0711  (https://github.com/dhanish0711)
License: MIT
"""

import socket
import threading
import time
import queue
import sys
import csv
import json
import ipaddress
from datetime import datetime
from tkinter import ttk, messagebox, filedialog
import tkinter as tk

# ─────────────────────────────────────────────────────────────
#  Service / Risk database
# ─────────────────────────────────────────────────────────────
SERVICE_DB = {
    # port: (name, risk, description)
    20:    ('FTP-Data',     'medium', 'FTP data transfer — unencrypted'),
    21:    ('FTP',          'high',   'File Transfer Protocol — credentials sent in plaintext'),
    22:    ('SSH',          'low',    'Secure Shell — encrypted remote access'),
    23:    ('Telnet',       'critical','Telnet — unencrypted, legacy remote access'),
    25:    ('SMTP',         'medium', 'Mail transfer — often open relay risk'),
    53:    ('DNS',          'medium', 'Domain Name System'),
    67:    ('DHCP',         'low',    'DHCP server'),
    68:    ('DHCP',         'low',    'DHCP client'),
    69:    ('TFTP',         'high',   'Trivial FTP — no authentication'),
    80:    ('HTTP',         'medium', 'Unencrypted web server'),
    110:   ('POP3',         'medium', 'Email retrieval — unencrypted'),
    119:   ('NNTP',         'low',    'Network News Transfer'),
    123:   ('NTP',          'low',    'Network Time Protocol'),
    135:   ('MS-RPC',       'high',   'Microsoft RPC — common attack vector'),
    137:   ('NetBIOS-NS',   'high',   'NetBIOS Name Service'),
    138:   ('NetBIOS-DGM',  'high',   'NetBIOS Datagram'),
    139:   ('NetBIOS-SSN',  'high',   'NetBIOS Session — often exploitable'),
    143:   ('IMAP',         'medium', 'Email access — unencrypted'),
    161:   ('SNMP',         'high',   'Network management — community strings exposed'),
    389:   ('LDAP',         'medium', 'Directory services — unencrypted'),
    443:   ('HTTPS',        'low',    'Encrypted web server'),
    445:   ('SMB',          'critical','Server Message Block — EternalBlue/ransomware vector'),
    465:   ('SMTPS',        'low',    'Encrypted SMTP'),
    514:   ('Syslog',       'medium', 'System log — may expose sensitive info'),
    587:   ('SMTP-TLS',     'low',    'Encrypted mail submission'),
    636:   ('LDAPS',        'low',    'Encrypted LDAP'),
    993:   ('IMAPS',        'low',    'Encrypted IMAP'),
    995:   ('POP3S',        'low',    'Encrypted POP3'),
    1433:  ('MSSQL',        'critical','Microsoft SQL Server — common target'),
    1521:  ('Oracle-DB',    'critical','Oracle Database'),
    1723:  ('PPTP',         'high',   'VPN — known weak encryption'),
    2049:  ('NFS',          'high',   'Network File System — often misconfigured'),
    2181:  ('Zookeeper',    'high',   'Zookeeper — often exposed without auth'),
    3306:  ('MySQL',        'critical','MySQL database server'),
    3389:  ('RDP',          'critical','Remote Desktop — BlueKeep & brute-force target'),
    4444:  ('Metasploit',   'critical','Metasploit default listener'),
    5432:  ('PostgreSQL',   'critical','PostgreSQL database server'),
    5900:  ('VNC',          'high',   'Remote desktop — weak auth by default'),
    5985:  ('WinRM-HTTP',   'high',   'Windows Remote Management (HTTP)'),
    5986:  ('WinRM-HTTPS',  'medium', 'Windows Remote Management (HTTPS)'),
    6379:  ('Redis',        'critical','Redis — often exposed with no auth'),
    6443:  ('Kubernetes',   'high',   'Kubernetes API server'),
    7001:  ('WebLogic',     'critical','Oracle WebLogic — frequent CVEs'),
    8080:  ('HTTP-Alt',     'medium', 'Alternate HTTP — dev/proxy server'),
    8443:  ('HTTPS-Alt',    'medium', 'Alternate HTTPS'),
    8888:  ('Jupyter',      'high',   'Jupyter Notebook — code execution if exposed'),
    9200:  ('Elasticsearch','critical','Elasticsearch — often unauthenticated'),
    9300:  ('ES-Transport', 'high',   'Elasticsearch transport'),
    27017: ('MongoDB',      'critical','MongoDB — often unauthenticated'),
    27018: ('MongoDB-Alt',  'high',   'MongoDB shard server'),
}

RISK_ORDER  = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
RISK_COLORS = {
    'critical': ('#FFF1F2', '#BE123C'),
    'high':     ('#FFF7ED', '#C2410C'),
    'medium':   ('#FEFCE8', '#A16207'),
    'low':      ('#F0FDF4', '#15803D'),
    'info':     ('#F8FAFC', '#475569'),
}

PORT_PRESETS = {
    "Top 20 Common":       [21,22,23,25,53,80,110,139,143,443,445,
                            1433,3306,3389,5432,5900,6379,8080,8443,27017],
    "Web Ports":           [80,443,8080,8443,8000,8888,3000,4000,5000],
    "Database Ports":      [1433,1521,3306,5432,6379,9200,27017,27018],
    "Well-Known (0–1023)": (0, 1023),
    "Registered (1024–49151)": (1024, 49151),
    "All Ports (0–65535)": (0, 65535),
}

def get_service(port):
    if port in SERVICE_DB:
        name, risk, desc = SERVICE_DB[port]
        return name, risk, desc
    return 'Unknown', 'info', 'No service information available'


# ─────────────────────────────────────────────────────────────
#  Banner Grabber (best-effort)
# ─────────────────────────────────────────────────────────────
def grab_banner(host, port, timeout=1.5):
    """Try to read a service banner. Returns str or empty string."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        # Some services need a nudge
        if port in (80, 8080, 8000, 8443):
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        else:
            s.send(b"\r\n")
        banner = s.recv(1024).decode(errors='replace').strip()
        s.close()
        # Collapse whitespace / take first meaningful line
        lines = [l.strip() for l in banner.splitlines() if l.strip()]
        return lines[0][:120] if lines else ""
    except Exception:
        return ""


# ─────────────────────────────────────────────────────────────
#  Scanner Engine
# ─────────────────────────────────────────────────────────────
class PortScanner:
    def __init__(self, target, start_port, end_port,
                 timeout=0.5, max_workers=500, grab_banners=False):
        self.target       = target
        self.start_port   = start_port
        self.end_port     = end_port
        self.timeout      = timeout
        self.max_workers  = max_workers
        self.grab_banners = grab_banners
        self._stop        = threading.Event()

        self.total_ports  = max(0, end_port - start_port + 1)
        self.scanned_count = 0
        self.open_ports   = []       # list[(port, service, risk, desc, banner)]
        self._lock        = threading.Lock()
        self.result_queue = queue.Queue()
        self._scan_start  = None
        self.ports_per_sec = 0.0

    def stop(self):
        self._stop.set()

    def resolve(self):
        return socket.gethostbyname(self.target)

    def _scan_port(self, port):
        if self._stop.is_set():
            return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            if s.connect_ex((self.target, port)) == 0:
                service, risk, desc = get_service(port)
                banner = ""
                if self.grab_banners:
                    banner = grab_banner(self.target, port, timeout=1.5)
                with self._lock:
                    self.open_ports.append((port, service, risk, desc, banner))
                self.result_queue.put(('open', port, service, risk, desc, banner))
            s.close()
        except Exception:
            pass
        finally:
            with self._lock:
                self.scanned_count += 1
                elapsed = time.time() - self._scan_start if self._scan_start else 1
                self.ports_per_sec = self.scanned_count / max(elapsed, 0.001)
            self.result_queue.put(('progress', self.scanned_count,
                                   self.total_ports, self.ports_per_sec))

    def run(self):
        self._scan_start = time.time()
        sem = threading.Semaphore(self.max_workers)
        threads = []
        for port in range(self.start_port, self.end_port + 1):
            if self._stop.is_set():
                break
            sem.acquire()
            t = threading.Thread(target=self._wrapper, args=(sem, port), daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        self.result_queue.put(('done', None, None, None, None, None))

    def _wrapper(self, sem, port):
        try:
            self._scan_port(port)
        finally:
            sem.release()


# ─────────────────────────────────────────────────────────────
#  GUI
# ─────────────────────────────────────────────────────────────
FONT_MONO = "Courier New"
FONT_UI   = ("Segoe UI"   if sys.platform == "win32"
             else "SF Pro Display" if sys.platform == "darwin"
             else "Ubuntu")

C = {
    'bg':        '#F0F4FA',
    'panel':     '#FFFFFF',
    'border':    '#D1DBE8',
    'accent':    '#1A56DB',
    'accent_h':  '#1648C0',
    'green':     '#057A55',
    'green_bg':  '#ECFDF5',
    'amber':     '#B45309',
    'amber_bg':  '#FFFBEB',
    'red':       '#BE123C',
    'red_bg':    '#FFF1F2',
    'text':      '#1E293B',
    'muted':     '#64748B',
    'sidebar':   '#1E293B',
    'sidebar_h': '#334155',
}


class ToolTip:
    """Simple hover tooltip."""
    def __init__(self, widget, text_fn):
        self.widget  = widget
        self.text_fn = text_fn
        self._tip    = None
        widget.bind("<Enter>", self._show)
        widget.bind("<Leave>", self._hide)

    def _show(self, _e=None):
        text = self.text_fn()
        if not text:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        self._tip = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        tk.Label(tw, text=text, background="#1E293B", foreground="white",
                 font=(FONT_UI, 9), relief="flat", padx=10, pady=6).pack()

    def _hide(self, _e=None):
        if self._tip:
            self._tip.destroy()
            self._tip = None


class ScannerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NetScan Pro")
        self.geometry("980x700")
        self.minsize(860, 580)
        self.configure(bg=C['bg'])

        self.scanner       = None
        self.scanner_thread = None
        self.start_time    = None
        self.poll_ms       = 40
        self.history       = []   # list of completed scan summaries
        self._filter_var   = tk.StringVar()
        self._filter_var.trace_add("write", self._apply_filter)
        self._all_rows     = []   # (iid, port, service, risk, desc, banner) for filtering

        self._apply_styles()
        self._build_ui()
        self.bind("<Return>", lambda _e: self.start_scan())
        self.bind("<Control-f>", lambda _e: self.ent_filter.focus_set())

    # ──────────────────────────────────── STYLES ──
    def _apply_styles(self):
        s = ttk.Style(self)
        s.theme_use("clam")

        s.configure(".", background=C['bg'], foreground=C['text'], font=(FONT_UI, 10))
        s.configure("TFrame",      background=C['bg'])
        s.configure("Inner.TFrame", background=C['panel'])

        s.configure("TLabelframe", background=C['panel'],
                    bordercolor=C['border'], relief="solid")
        s.configure("TLabelframe.Label", background=C['panel'],
                    foreground=C['accent'], font=(FONT_UI, 9, "bold"))

        s.configure("TEntry", fieldbackground=C['panel'],
                    foreground=C['text'], insertcolor=C['text'],
                    bordercolor=C['border'], relief="solid", padding=(6, 5))
        s.map("TEntry", bordercolor=[("focus", C['accent'])])

        # Buttons
        for name, bg, fg, bg_a in [
            ("Primary",   C['accent'],   "white",      C['accent_h']),
            ("Green",     "#065F46",     "white",      "#064E3B"),
            ("Ghost",     C['panel'],    C['accent'],  "#EFF6FF"),
            ("Danger",    "#FEE2E2",     C['red'],     "#FECACA"),
            ("Sidebar",   C['sidebar'],  "white",      C['sidebar_h']),
        ]:
            s.configure(f"{name}.TButton", background=bg, foreground=fg,
                        relief="flat", padding=(14, 7), font=(FONT_UI, 10),
                        borderwidth=0)
            s.map(f"{name}.TButton",
                  background=[("active", bg_a), ("disabled", "#CBD5E1")],
                  foreground=[("disabled", "#94A3B8")])

        s.configure("Accent.Horizontal.TProgressbar",
                    troughcolor=C['border'], background=C['accent'],
                    borderwidth=0, thickness=6)

        s.configure("Treeview", background=C['panel'],
                    fieldbackground=C['panel'], foreground=C['text'],
                    font=(FONT_MONO, 9), rowheight=24, borderwidth=0)
        s.configure("Treeview.Heading", background="#E2E8F0",
                    foreground=C['muted'], font=(FONT_UI, 9, "bold"),
                    relief="flat", padding=(8, 5))
        s.map("Treeview", background=[("selected", "#DBEAFE")],
              foreground=[("selected", C['text'])])

        s.configure("TCheckbutton", background=C['panel'], foreground=C['muted'],
                    font=(FONT_UI, 9))

        s.configure("TCombobox", fieldbackground=C['panel'],
                    selectbackground=C['panel'], selectforeground=C['text'])

    # ──────────────────────────────────── BUILD UI ──
    def _build_ui(self):
        # Outer wrapper: sidebar + main
        wrapper = ttk.Frame(self)
        wrapper.pack(fill="both", expand=True)

        self._build_sidebar(wrapper)

        main = ttk.Frame(wrapper)
        main.pack(side="left", fill="both", expand=True)

        self._build_header(main)
        self._build_input_panel(main)
        self._build_statusbar(main)
        self._build_results(main)
        self._build_footer(main)

    # ── Sidebar ──
    def _build_sidebar(self, parent):
        sb = tk.Frame(parent, bg=C['sidebar'], width=200)
        sb.pack(side="left", fill="y")
        sb.pack_propagate(False)

        tk.Label(sb, text="⚡ NetScan Pro", bg=C['sidebar'], fg="white",
                 font=(FONT_UI, 12, "bold")).pack(pady=(18, 4), padx=16, anchor="w")
        tk.Label(sb, text="Network Port Scanner", bg=C['sidebar'], fg="#94A3B8",
                 font=(FONT_UI, 8)).pack(padx=16, anchor="w")

        ttk.Separator(sb, orient="horizontal").pack(fill="x", padx=16, pady=14)

        # Nav buttons
        nav_items = [
            ("🔍  Scanner",   self._show_scanner),
            ("📋  History",   self._show_history),
            ("ℹ️   About",     self._show_about),
        ]
        self._nav_buttons = []
        for label, cmd in nav_items:
            b = tk.Button(sb, text=label, bg=C['sidebar'], fg="white",
                          activebackground=C['sidebar_h'], activeforeground="white",
                          relief="flat", anchor="w", padx=16, pady=8,
                          font=(FONT_UI, 10), cursor="hand2", command=cmd)
            b.pack(fill="x")
            self._nav_buttons.append(b)

        self._nav_buttons[0].config(bg=C['sidebar_h'])

        ttk.Separator(sb, orient="horizontal").pack(fill="x", padx=16, pady=14)

        # Stats box
        tk.Label(sb, text="LAST SCAN", bg=C['sidebar'], fg="#64748B",
                 font=(FONT_UI, 8, "bold")).pack(padx=16, anchor="w")

        self.lbl_stat_host = tk.Label(sb, text="—", bg=C['sidebar'], fg="#94A3B8",
                                       font=(FONT_MONO, 9), wraplength=160, justify="left")
        self.lbl_stat_host.pack(padx=16, anchor="w", pady=(4, 0))

        self.lbl_stat_open = tk.Label(sb, text="Open ports: —", bg=C['sidebar'],
                                       fg="#94A3B8", font=(FONT_UI, 9))
        self.lbl_stat_open.pack(padx=16, anchor="w", pady=(2, 0))

        self.lbl_stat_time = tk.Label(sb, text="Duration: —", bg=C['sidebar'],
                                       fg="#94A3B8", font=(FONT_UI, 9))
        self.lbl_stat_time.pack(padx=16, anchor="w", pady=(2, 0))

        # Version at bottom
        tk.Label(sb, text="v2.0.0  •  MIT License", bg=C['sidebar'],
                 fg="#334155", font=(FONT_UI, 8)).pack(side="bottom", pady=12)
        tk.Label(sb, text="github.com/dhanish0711", bg=C['sidebar'],
                 fg="#475569", font=(FONT_UI, 8)).pack(side="bottom")

    def _nav_highlight(self, idx):
        for i, b in enumerate(self._nav_buttons):
            b.config(bg=C['sidebar_h'] if i == idx else C['sidebar'])

    # ── Header ──
    def _build_header(self, parent):
        hdr = tk.Frame(parent, bg="#1A56DB", height=46)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        tk.Label(hdr, text="Port Scanner", bg="#1A56DB", fg="white",
                 font=(FONT_UI, 12, "bold")).pack(side="left", padx=18, pady=8)

        self.lbl_clock = tk.Label(hdr, text="", bg="#1A56DB", fg="#BFDBFE",
                                   font=(FONT_UI, 9))
        self.lbl_clock.pack(side="right", padx=18)
        self._tick_clock()

        self.lbl_resolved = tk.Label(hdr, text="", bg="#1A56DB", fg="#93C5FD",
                                      font=(FONT_MONO, 9))
        self.lbl_resolved.pack(side="right", padx=(0, 16))

    def _tick_clock(self):
        self.lbl_clock.config(text=datetime.now().strftime("%d %b %Y  %H:%M:%S"))
        self.after(1000, self._tick_clock)

    # ── Input Panel ──
    def _build_input_panel(self, parent):
        card = ttk.LabelFrame(parent, text="  Scan Configuration", padding=14)
        card.pack(fill="x", padx=14, pady=(12, 6))

        # Row 0: labels
        for col, lbl in enumerate(["Target Host / IP", "Port Preset", "Start Port", "End Port"]):
            tk.Label(card, text=lbl, bg=C['panel'], fg=C['muted'],
                     font=(FONT_UI, 8, "bold")).grid(row=0, column=col*2, sticky="w",
                                                     padx=(0 if col==0 else 12, 0))

        # Row 1: entries
        self.ent_target = ttk.Entry(card, width=26, font=(FONT_MONO, 10))
        self.ent_target.insert(0, "scanme.nmap.org")
        self.ent_target.grid(row=1, column=0, sticky="ew", pady=(3, 0))

        self.var_preset = tk.StringVar(value="Select preset…")
        cb = ttk.Combobox(card, textvariable=self.var_preset,
                          values=list(PORT_PRESETS.keys()), state="readonly", width=20)
        cb.bind("<<ComboboxSelected>>", self._apply_preset)
        cb.grid(row=1, column=2, sticky="ew", padx=(12, 0), pady=(3, 0))

        self.ent_start = ttk.Entry(card, width=8, font=(FONT_MONO, 10))
        self.ent_start.insert(0, "1")
        self.ent_start.grid(row=1, column=4, sticky="ew", padx=(12, 0), pady=(3, 0))

        self.ent_end = ttk.Entry(card, width=8, font=(FONT_MONO, 10))
        self.ent_end.insert(0, "1024")
        self.ent_end.grid(row=1, column=6, sticky="ew", padx=(12, 0), pady=(3, 0))

        # Row 2: options + buttons
        opts = tk.Frame(card, bg=C['panel'])
        opts.grid(row=2, column=0, columnspan=7, sticky="w", pady=(10, 0))

        self.var_banners = tk.BooleanVar(value=False)
        cb_banner = ttk.Checkbutton(opts, text="Grab service banners",
                                    variable=self.var_banners)
        cb_banner.pack(side="left")
        ToolTip(cb_banner, lambda: "Attempts to read banner/header from each open port.\nSlows scan but gives version info.")

        btns = tk.Frame(card, bg=C['panel'])
        btns.grid(row=1, column=8, rowspan=2, padx=(16, 0), sticky="e")

        self.btn_start = ttk.Button(btns, text="▶  Start Scan",
                                    style="Primary.TButton", command=self.start_scan)
        self.btn_start.pack(pady=(0, 5))

        self.btn_stop = ttk.Button(btns, text="■  Stop",
                                   style="Danger.TButton",
                                   command=self.stop_scan, state="disabled")
        self.btn_stop.pack()

        for c in range(9):
            card.grid_columnconfigure(c, weight=1 if c % 2 == 0 else 0)

    def _apply_preset(self, _e=None):
        val = PORT_PRESETS.get(self.var_preset.get())
        if val is None:
            return
        lo, hi = (min(val), max(val)) if isinstance(val, list) else val
        self.ent_start.delete(0, tk.END); self.ent_start.insert(0, str(lo))
        self.ent_end.delete(0, tk.END);   self.ent_end.insert(0, str(hi))

    # ── Status Bar ──
    def _build_statusbar(self, parent):
        bar = tk.Frame(parent, bg=C['bg'])
        bar.pack(fill="x", padx=14, pady=(0, 4))

        self.progress = ttk.Progressbar(bar, orient="horizontal", mode="determinate",
                                        style="Accent.Horizontal.TProgressbar")
        self.progress.pack(fill="x", pady=(0, 5))

        row = tk.Frame(bar, bg=C['bg'])
        row.pack(fill="x")

        self.lbl_dot = tk.Label(row, text="●", bg=C['bg'],
                                fg=C['muted'], font=(FONT_UI, 13))
        self.lbl_dot.pack(side="left")

        self.var_status = tk.StringVar(value="Ready  —  enter a target and press Start")
        tk.Label(row, textvariable=self.var_status, bg=C['bg'],
                 fg=C['text'], font=(FONT_UI, 9, "bold")).pack(side="left", padx=(5, 0))

        self.var_speed = tk.StringVar(value="")
        tk.Label(row, textvariable=self.var_speed, bg=C['bg'],
                 fg=C['muted'], font=(FONT_UI, 9)).pack(side="left", padx=(14, 0))

        self.var_elapsed = tk.StringVar(value="")
        tk.Label(row, textvariable=self.var_elapsed, bg=C['bg'],
                 fg=C['muted'], font=(FONT_UI, 9)).pack(side="right")

        self.var_open_lbl = tk.StringVar(value="")
        tk.Label(row, textvariable=self.var_open_lbl, bg=C['bg'],
                 fg=C['green'], font=(FONT_UI, 9, "bold")).pack(side="right", padx=(0, 14))

    # ── Results Tree ──
    def _build_results(self, parent):
        outer = ttk.LabelFrame(parent, text="  Open Ports", padding=(10, 6))
        outer.pack(fill="both", expand=True, padx=14, pady=(0, 6))

        # Filter bar
        fbar = tk.Frame(outer, bg=C['panel'])
        fbar.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 6))
        tk.Label(fbar, text="🔎", bg=C['panel'], fg=C['muted'],
                 font=(FONT_UI, 11)).pack(side="left")
        self.ent_filter = ttk.Entry(fbar, textvariable=self._filter_var, width=30,
                                    font=(FONT_UI, 9))
        self.ent_filter.pack(side="left", padx=(4, 0))
        tk.Label(fbar, text="Filter by port / service / risk  (Ctrl+F)",
                 bg=C['panel'], fg=C['muted'], font=(FONT_UI, 8)).pack(side="left", padx=8)

        self.lbl_match = tk.Label(fbar, text="", bg=C['panel'], fg=C['muted'],
                                   font=(FONT_UI, 8))
        self.lbl_match.pack(side="right")

        # Treeview
        cols = ("port", "service", "risk", "description", "banner")
        self.tree = ttk.Treeview(outer, columns=cols, show="headings",
                                 selectmode="browse")

        self.tree.heading("port",        text="Port",    command=lambda: self._sort("port", int))
        self.tree.heading("service",     text="Service", command=lambda: self._sort("service", str))
        self.tree.heading("risk",        text="Risk",    command=lambda: self._sort_risk)
        self.tree.heading("description", text="Description")
        self.tree.heading("banner",      text="Banner / Version")

        self.tree.column("port",        width=70,  minwidth=55,  anchor="center")
        self.tree.column("service",     width=120, minwidth=90,  anchor="w")
        self.tree.column("risk",        width=80,  minwidth=65,  anchor="center")
        self.tree.column("description", width=260, minwidth=180, anchor="w")
        self.tree.column("banner",      width=250, minwidth=140, anchor="w")

        # Risk level tags
        for risk, (bg, fg) in RISK_COLORS.items():
            self.tree.tag_configure(risk, background=bg, foreground=fg)

        vsb = ttk.Scrollbar(outer, orient="vertical",   command=self.tree.yview)
        hsb = ttk.Scrollbar(outer, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=1, column=0, sticky="nsew")
        vsb.grid(row=1, column=1, sticky="ns")
        hsb.grid(row=2, column=0, sticky="ew")

        outer.grid_rowconfigure(1, weight=1)
        outer.grid_columnconfigure(0, weight=1)

        # Right-click context menu
        self._ctx = tk.Menu(self, tearoff=0)
        self._ctx.add_command(label="📋  Copy Port",    command=self._copy_port)
        self._ctx.add_command(label="📋  Copy Row",     command=self._copy_row)
        self._ctx.add_separator()
        self._ctx.add_command(label="🌐  Open in Browser", command=self._open_browser)
        self.tree.bind("<Button-3>", self._show_ctx)
        self.tree.bind("<Button-2>", self._show_ctx)   # macOS

        self._sort_reverse = {}

    # ── Footer ──
    def _build_footer(self, parent):
        frm = tk.Frame(parent, bg=C['bg'])
        frm.pack(fill="x", padx=14, pady=(0, 10))

        self.btn_clear = ttk.Button(frm, text="🗑  Clear",
                                    style="Ghost.TButton", command=self.clear_results)
        self.btn_clear.pack(side="left")

        self.btn_csv = ttk.Button(frm, text="⬇  CSV",
                                  style="Ghost.TButton",
                                  command=self.export_csv, state="disabled")
        self.btn_csv.pack(side="right", padx=(6, 0))

        self.btn_txt = ttk.Button(frm, text="⬇  TXT Report",
                                  style="Ghost.TButton",
                                  command=self.export_txt, state="disabled")
        self.btn_txt.pack(side="right", padx=(6, 0))

        self.btn_json = ttk.Button(frm, text="⬇  JSON",
                                   style="Ghost.TButton",
                                   command=self.export_json, state="disabled")
        self.btn_json.pack(side="right", padx=(6, 0))

        tk.Label(frm, text="↵ Start  •  Ctrl+F Filter  •  Right-click row for options",
                 bg=C['bg'], fg=C['muted'], font=(FONT_UI, 8)).pack(side="right", padx=(0, 12))

    # ──────────────────────────────────── PAGES ──
    def _show_scanner(self):
        self._nav_highlight(0)
        # Just bring focus to target entry
        self.ent_target.focus_set()

    def _show_history(self):
        self._nav_highlight(1)
        win = tk.Toplevel(self)
        win.title("Scan History")
        win.geometry("600x400")
        win.configure(bg=C['bg'])

        tk.Label(win, text="Scan History", bg=C['bg'], fg=C['text'],
                 font=(FONT_UI, 13, "bold")).pack(padx=20, pady=(16, 8), anchor="w")

        txt = tk.Text(win, font=(FONT_MONO, 9), bg=C['panel'],
                      fg=C['text'], relief="flat", padx=12, pady=12)
        txt.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        if not self.history:
            txt.insert("1.0", "No scans completed yet.")
        else:
            for i, h in enumerate(reversed(self.history), 1):
                txt.insert("end", f"{'─'*50}\n")
                txt.insert("end", f"  #{i}  {h['target']}  ({h['ip']})\n")
                txt.insert("end", f"  Ports:   {h['start_port']}–{h['end_port']}\n")
                txt.insert("end", f"  Open:    {h['open_count']}\n")
                txt.insert("end", f"  Time:    {h['duration']:.2f}s\n")
                txt.insert("end", f"  Date:    {h['timestamp']}\n")
                if h['open_ports']:
                    txt.insert("end", f"  Results: " + ", ".join(
                        f"{p}({s})" for p, s, *_ in h['open_ports']) + "\n")
                txt.insert("end", "\n")
        txt.configure(state="disabled")

    def _show_about(self):
        self._nav_highlight(2)
        win = tk.Toplevel(self)
        win.title("About NetScan Pro")
        win.geometry("420x320")
        win.configure(bg=C['bg'])
        win.resizable(False, False)

        tk.Label(win, text="⚡ NetScan Pro", bg=C['bg'], fg=C['accent'],
                 font=(FONT_UI, 18, "bold")).pack(pady=(24, 4))
        tk.Label(win, text="v2.0.0 — Advanced Network Port Scanner",
                 bg=C['bg'], fg=C['muted'], font=(FONT_UI, 10)).pack()
        ttk.Separator(win, orient="horizontal").pack(fill="x", padx=30, pady=16)

        info = [
            ("Author",  "dhanish0711"),
            ("GitHub",  "github.com/dhanish0711"),
            ("License", "MIT — free to use and modify"),
            ("Python",  f"{sys.version.split()[0]}"),
            ("Platform",sys.platform),
        ]
        for k, v in info:
            row = tk.Frame(win, bg=C['bg'])
            row.pack(anchor="w", padx=40, pady=2)
            tk.Label(row, text=f"{k}:", bg=C['bg'], fg=C['muted'],
                     font=(FONT_UI, 9, "bold"), width=10, anchor="w").pack(side="left")
            tk.Label(row, text=v, bg=C['bg'], fg=C['text'],
                     font=(FONT_MONO, 9)).pack(side="left")

        tk.Label(win, text="For educational and authorized testing use only.",
                 bg=C['bg'], fg=C['muted'], font=(FONT_UI, 8),
                 wraplength=360).pack(pady=(20, 0))

    # ──────────────────────────────────── SCAN CONTROL ──
    def start_scan(self):
        if self.scanner_thread and self.scanner_thread.is_alive():
            messagebox.showinfo("NetScan Pro", "A scan is already running.")
            return

        target = self.ent_target.get().strip()
        if not target:
            messagebox.showerror("Input Error", "Please enter a target IP or hostname.")
            return

        try:
            sp = int(self.ent_start.get()); ep = int(self.ent_end.get())
        except ValueError:
            messagebox.showerror("Input Error", "Port values must be integers.")
            return

        if not (0 <= sp <= 65535 and 0 <= ep <= 65535 and sp <= ep):
            messagebox.showerror("Input Error", "Port range must be 0–65535 and start ≤ end.")
            return

        self.scanner = PortScanner(target, sp, ep,
                                   timeout=0.5, max_workers=500,
                                   grab_banners=self.var_banners.get())
        try:
            ip = self.scanner.resolve()
            self.lbl_resolved.config(text=f"→  {ip}")
        except Exception as e:
            messagebox.showerror("DNS Error", f"Cannot resolve '{target}'.\n{e}")
            self.scanner = None
            return

        self._clear_tree()
        self._all_rows.clear()
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self._set_export_buttons("disabled")
        self.progress.configure(maximum=1, value=0)
        self.var_open_lbl.set("")
        self.var_speed.set("")

        self._set_dot(C['accent'], "●")
        self.var_status.set(f"Scanning  {target}  ports {sp}–{ep}…")
        self.start_time = time.time()
        self._tick_elapsed()

        self.scanner_thread = threading.Thread(target=self.scanner.run, daemon=True)
        self.scanner_thread.start()
        self.after(self.poll_ms, self._poll)

    def stop_scan(self):
        if self.scanner:
            self.scanner.stop()
            self._set_dot(C['amber'], "●")
            self.var_status.set("Stopping…")

    # ──────────────────────────────────── POLL ──
    def _poll(self):
        if not self.scanner:
            return
        try:
            while True:
                msg = self.scanner.result_queue.get_nowait()
                kind = msg[0]
                if kind == 'open':
                    _, port, service, risk, desc, banner = msg
                    iid = self.tree.insert("", "end",
                                           values=(port, service,
                                                   risk.upper(), desc,
                                                   banner or "—"),
                                           tags=(risk,))
                    self._all_rows.append((iid, port, service, risk, desc, banner))
                    count = len(self.scanner.open_ports)
                    self.var_open_lbl.set(f"● {count} open port{'s' if count!=1 else ''}")

                elif kind == 'progress':
                    _, scanned, total, pps = msg
                    pct = int(scanned / total * 100) if total else 0
                    self.progress.configure(maximum=max(total, 1), value=scanned)
                    self.var_status.set(f"Scanning…  {scanned:,} / {total:,}  ({pct}%)")
                    self.var_speed.set(f"⚡ {pps:,.0f} ports/sec")

                elif kind == 'done':
                    self._scan_done()
                    return
        except queue.Empty:
            pass

        if self.scanner_thread and self.scanner_thread.is_alive():
            self.after(self.poll_ms, self._poll)
        else:
            self._scan_done()

    def _scan_done(self):
        elapsed  = time.time() - self.start_time if self.start_time else 0
        n_open   = len(self.scanner.open_ports) if self.scanner else 0
        target   = self.ent_target.get().strip()

        self.start_time = None
        self.var_elapsed.set(f"Finished in {elapsed:.1f}s")
        self.var_speed.set("")
        self.progress.configure(value=self.progress["maximum"])

        if n_open:
            self._set_dot(C['green'], "✔")
            self.var_status.set(f"Scan complete  —  {n_open} open port{'s' if n_open!=1 else ''} found")
            self._set_export_buttons("normal")
        else:
            self._set_dot(C['muted'], "●")
            self.var_status.set("Scan complete  —  no open ports found")

        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")

        # Update sidebar stats
        try:
            ip = self.scanner.resolve()
        except Exception:
            ip = "?"
        self.lbl_stat_host.config(text=target)
        self.lbl_stat_open.config(text=f"Open ports: {n_open}")
        self.lbl_stat_time.config(text=f"Duration: {elapsed:.2f}s")

        # Save to history
        self.history.append({
            'target':     target,
            'ip':         ip,
            'start_port': self.ent_start.get(),
            'end_port':   self.ent_end.get(),
            'open_count': n_open,
            'open_ports': list(self.scanner.open_ports) if self.scanner else [],
            'duration':   elapsed,
            'timestamp':  datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        })
        self.var_open_lbl.set(f"● {n_open} open port{'s' if n_open!=1 else ''}")

    # ──────────────────────────────────── FILTER / SORT ──
    def _apply_filter(self, *_):
        q = self._filter_var.get().strip().lower()
        for row in self._all_rows:
            iid, port, service, risk, desc, banner = row
            if q == "" or q in str(port) or q in service.lower() or q in risk.lower() or q in desc.lower():
                if not self.tree.exists(iid):
                    self.tree.reattach(iid, "", "end")
            else:
                if self.tree.exists(iid):
                    self.tree.detach(iid)
        visible = sum(1 for r in self._all_rows
                      if self._filter_var.get().strip() == "" or self.tree.exists(r[0]))
        if q:
            self.lbl_match.config(text=f"{visible} match{'es' if visible!=1 else ''}")
        else:
            self.lbl_match.config(text="")

    def _sort(self, col, key_fn):
        rows = [(self.tree.set(i, col), i) for i in self.tree.get_children()]
        rev  = self._sort_reverse.get(col, False)
        try:
            rows.sort(key=lambda x: key_fn(x[0]), reverse=rev)
        except Exception:
            rows.sort(reverse=rev)
        for idx, (_, iid) in enumerate(rows):
            self.tree.move(iid, "", idx)
        self._sort_reverse[col] = not rev

    def _sort_risk(self):
        rows = [(self.tree.set(i, "risk"), i) for i in self.tree.get_children()]
        rev  = self._sort_reverse.get("risk", False)
        rows.sort(key=lambda x: RISK_ORDER.get(x[0].lower(), 99), reverse=rev)
        for idx, (_, iid) in enumerate(rows):
            self.tree.move(iid, "", idx)
        self._sort_reverse["risk"] = not rev

    # ──────────────────────────────────── CONTEXT MENU ──
    def _show_ctx(self, event):
        row = self.tree.identify_row(event.y)
        if row:
            self.tree.selection_set(row)
            self._ctx.tk_popup(event.x_root, event.y_root)

    def _copy_port(self):
        sel = self.tree.selection()
        if sel:
            self.clipboard_clear()
            self.clipboard_append(self.tree.set(sel[0], "port"))

    def _copy_row(self):
        sel = self.tree.selection()
        if sel:
            vals = self.tree.item(sel[0], "values")
            self.clipboard_clear()
            self.clipboard_append("\t".join(str(v) for v in vals))

    def _open_browser(self):
        sel = self.tree.selection()
        if not sel:
            return
        port    = self.tree.set(sel[0], "port")
        target  = self.ent_target.get().strip()
        service = self.tree.set(sel[0], "service").lower()
        scheme  = "https" if "https" in service or port in ("443", "8443") else "http"
        if service in ("http", "https", "http-alt", "https-alt",
                       "jupyter", "weblogic", "kubernetes"):
            import webbrowser
            webbrowser.open(f"{scheme}://{target}:{port}")

    # ──────────────────────────────────── HELPERS ──
    def _set_dot(self, color, char):
        self.lbl_dot.config(fg=color, text=char)

    def _set_export_buttons(self, state):
        self.btn_csv.configure(state=state)
        self.btn_txt.configure(state=state)
        self.btn_json.configure(state=state)

    def _tick_elapsed(self):
        if self.start_time:
            self.var_elapsed.set(f"Elapsed: {time.time()-self.start_time:.1f}s")
            self.after(200, self._tick_elapsed)

    def _clear_tree(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        self._all_rows.clear()

    def clear_results(self):
        self._clear_tree()
        self._filter_var.set("")
        self.lbl_match.config(text="")
        self.progress.configure(value=0, maximum=1)
        self._set_dot(C['muted'], "●")
        self.var_status.set("Ready  —  enter a target and press Start")
        self.var_elapsed.set("")
        self.var_open_lbl.set("")
        self.var_speed.set("")
        self.lbl_resolved.config(text="")
        self._set_export_buttons("disabled")

    # ──────────────────────────────────── EXPORT ──
    def _sorted_ports(self):
        return sorted(self.scanner.open_ports, key=lambda x: x[0]) if self.scanner else []

    def _pick_save(self, ext, ftype):
        return filedialog.asksaveasfilename(
            title=f"Save as {ext.upper()}",
            defaultextension=f".{ext}",
            initialfile=f"netscan_{self.ent_target.get().strip()}_{int(time.time())}.{ext}",
            filetypes=[(ftype, f"*.{ext}"), ("All Files", "*.*")]
        )

    def export_txt(self):
        ports = self._sorted_ports()
        if not ports:
            messagebox.showinfo("Export", "No results to export.")
            return
        path = self._pick_save("txt", "Text Files")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("=" * 60 + "\n")
                f.write("  NetScan Pro — Port Scan Report\n")
                f.write("=" * 60 + "\n")
                f.write(f"  Target   : {self.ent_target.get().strip()}\n")
                f.write(f"  Range    : {self.ent_start.get()}–{self.ent_end.get()}\n")
                f.write(f"  Date     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"  Open     : {len(ports)} port(s)\n")
                f.write("=" * 60 + "\n\n")
                for port, svc, risk, desc, banner in ports:
                    f.write(f"  Port {port:<6}  {svc:<18}  [{risk.upper():<8}]  {desc}\n")
                    if banner:
                        f.write(f"           Banner: {banner}\n")
                f.write("\n" + "=" * 60 + "\n")
            messagebox.showinfo("Saved", f"Report saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def export_csv(self):
        ports = self._sorted_ports()
        if not ports:
            messagebox.showinfo("Export", "No results to export.")
            return
        path = self._pick_save("csv", "CSV Files")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Port", "Service", "Risk", "Description", "Banner", "Timestamp"])
                ts = datetime.now().isoformat()
                for port, svc, risk, desc, banner in ports:
                    w.writerow([port, svc, risk, desc, banner, ts])
            messagebox.showinfo("Saved", f"CSV saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def export_json(self):
        ports = self._sorted_ports()
        if not ports:
            messagebox.showinfo("Export", "No results to export.")
            return
        path = self._pick_save("json", "JSON Files")
        if not path:
            return
        try:
            data = {
                "target":    self.ent_target.get().strip(),
                "range":     {"start": self.ent_start.get(), "end": self.ent_end.get()},
                "scanned_at": datetime.now().isoformat(),
                "open_ports": [
                    {"port": p, "service": s, "risk": r, "description": d, "banner": b}
                    for p, s, r, d, b in ports
                ]
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            messagebox.showinfo("Saved", f"JSON saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))


# ─────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────
def main():
    if sys.platform.startswith("win"):
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(
                ctypes.windll.kernel32.GetStdHandle(-10), 7)
            # Windows DPI awareness for sharp text
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass

    app = ScannerGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
