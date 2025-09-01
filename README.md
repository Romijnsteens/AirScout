# User Guide – Wi-Fi Passive Monitor (ESSID + Band Filter)

---

## Legal & Ethics Notice (Educational Use)

**For educational and authorized testing only.** You are solely responsible for how you use this tool. Intentionally disrupting networks you do not own or lack written permission to test may be illegal in your jurisdiction. Even a single deauthentication frame sent to someone else’s network can be unlawful. Use only with explicit authorization and at your own risk.

---

## 1) Purpose (at a glance)

This application discovers a **target SSID**, lists matching **BSSIDs** by **band (2.4/5/6 GHz)**, and **passively monitors** each BSSID to enumerate **clients** and, if present, **capture WPA handshakes** to **.22000**. Deauthentication buttons are **active working**; active deauths are performed.

---

## 2) System Requirements

* **OS:** Linux with `iw`, `ip`, and `systemd`/`NetworkManager`.
* **Tools:** `airodump-ng` (aircrack-ng suite), `airmon-ng`, `hcxpcapngtool`, `iw`, `ip`, `systemctl`.
* **Privileges:** Run as root (or with equivalent capabilities for capture tools).
* **Wi-Fi adapter:** Must support **monitor mode** and the target **bands**. 6 GHz requires modern chipset/driver/kernel.

---

## 3) First-Time Setup

1. Verify tools are installed: `which airodump-ng`, `which hcxpcapngtool`, etc.
2. Start the app: `python3 your_script.py`.
3. If you see “Run this script as root,” restart with sufficient privileges.

*Tip:* Use **Self-test** (see §12) to quickly validate the environment.

---

## 4) Files & Folders

* `logs/<SAFE_ESSID>/session.log` – rolling session log (rotates after \~5 MB).
* `logs/<SAFE_ESSID>/discovery-01.csv` – latest band discovery output.
* `logs/<SAFE_ESSID>/<ESSID>_mon-01.csv` – per-BSSID monitor CSV.
* `logs/<SAFE_ESSID>/aliases.json` – your human-readable aliases for client MACs.
* `logs/<SAFE_ESSID>/session.json` – session data (BSSIDs, clients, counts).
* `logs/<SAFE_ESSID>/*hs*.22000` – passively captured WPA handshakes.

`<SAFE_ESSID>` is a sanitized filename-safe version of your ESSID.

---

## 5) Main Window Overview

### 5.1 Top Bar (Inputs)

* **Wi-Fi interface**
  Physical device, e.g., `wlan1`.

* **Monitor name**
  Name to use in monitor mode, e.g., `mon0`. The app will switch mode and rename if needed.

* **Band (2.4 / 5 / 6 GHz)**
  Band to scan for the target ESSID. 6 GHz requires recent aircrack-ng and driver support.

* **ESSID**
  Exact SSID to target (case-sensitive).

* **Log level**
  `basic` (minimal), `verbose` (more detail), `debug` (maximum detail).

* **Discovery (s)**
  Duration for the band discovery pass.

* **Per-BSSID scan (s)**
  Passive listen time per BSSID to enumerate clients.

* **Start / STOP**
  Runs or stops the pipeline. STOP terminates processes and **restores** NetworkManager/interface state when applicable.

### 5.2 Discovery Table

Shows all networks seen during discovery (BSSID, channel, band, ESSID).

**Optional Filters** (if enabled in your build):

* Search field filters by partial **BSSID/ESSID**.
* “Hide hidden SSIDs” removes blank/`<hidden>` rows.

### 5.3 Target & BSSID Selection (band-filtered)

Lists BSSIDs that match your **ESSID** **and** the selected **band**, including channel. This identifies the exact APs belonging to your SSID.

### 5.4 Per-BSSID Monitoring

* **Status line** – phase, current BSSID, and remaining time.
* **Progress bar** – indeterminate during discovery; countdown during per-BSSID scans.
* **Clients (current BSSID)** – live client MACs; displayed with **aliases** when set.
* **Skip controls** – skip discovery or advance to the next BSSID.
* **Clients & Handshakes…** – opens **Client Center** (see §6).

### 5.5 Log Panel

Timestamped logs (commands, exit codes, converter output, errors). Persisted to `session.log` with auto-rotation.
**Open logs directory** opens the active session folder.

---

## 6) Client Center

### 6.1 Access Points (left)

Displays BSSIDs that match your ESSID and band. Select one to view its clients.

### 6.2 Clients (right)

Lists client MACs under the selected BSSID with **Last seen** time.

* **Assign alias** (double-click or context menu → *Name…*)
  Save a human-readable label for a MAC (stored in `aliases.json`).
  **Remove alias** via context menu → *Clear alias*.

### 6.3 Action Bar

* **Start monitoring (BSSID)**
  Starts a **passive** handshake capture for the selected BSSID. Shows a countdown and **EAPOL** indicator.

* **Stop monitoring**
  Stops the capture.

* **Broadcast / Client-targeted**
  **Placeholders only** (no active deauth in this build). They **do** start a **passive** handshake capture for the same BSSID.

* **Packets**
  UI value for potential lab variants (not used here for deauth).

* **Export clients**
  Writes **CSV** (and **JSON** if enabled) of all known clients to the session logs folder.

### 6.4 .22000 Panel

* Shows the first lines of the latest **.22000** file.
* **Copy hash** copies text to the clipboard (no auto-clear in this build).
* **Open folder** opens the directory containing the `.22000`.

### 6.5 Status Bar

* **⏳ Timer** – counts down (or “running…” if indefinite).
* **EAPOL** – switches to “yes” once converter/stdout suggests a handshake.

---

## 7) Functional Workflow (Under the Hood)

* **Preflight** – Verifies required binaries; shows explicit errors if missing.
* **Monitor mode** – Switches interface to monitor mode and applies your monitor name; restores system state on STOP/exit.
* **Discovery** – Runs `airodump-ng --band <bg|a|6>` to CSV; robust **header-based** parser handles odd ESSIDs/CSV formats.
* **BSSID selection** – Filters by exact ESSID and selected band.
* **Per-BSSID monitoring** – Pins channel (with 6 GHz **frequency fallback**) and runs `airodump-ng --bssid … --channel …`; parses the CSV Stations section to show **new clients** live.
* **Handshake (.22000)** – During monitoring (or via Client Center buttons), converts newest `.cap` with `hcxpcapngtool`. When a non-empty `.22000` exists, it’s displayed and logged. Desktop notifications are issued where supported.
* **Watchdog** – If `airodump-ng` becomes silent, the process is cleanly restarted for that step (discovery or per-BSSID).
* **Inotify (optional)** – Uses inotify for immediate file-change parsing; falls back to lightweight mtime polling if unavailable.
* **Logging** – Captures both stdout/stderr; rotates `session.log` automatically.
* **Session persistence** – Continuously writes BSSIDs/clients/aliases/counters to `session.json` and reloads them on startup for the same ESSID.

---

## 8) Quick Start

1. **Configure**

   * Select **Wi-Fi interface** (e.g., `wlan1`).
   * Set **Monitor name** (e.g., `mon0`).
   * Choose **Band** (2.4/5/6 GHz).
   * Enter **ESSID** (exact).
   * Set **Discovery** to 15–30 s and **Per-BSSID** to 45–60 s.
   * Choose **Log level** `verbose`.

2. **Run**

   * Click **Start**. Watch discovery progress.
   * Review the **Discovery table** when it completes.

3. **Review BSSIDs**

   * The band-filtered list shows BSSIDs for your ESSID.

4. **Per-BSSID clients**

   * The app iterates BSSIDs and lists live **clients** per AP.

5. **Client Center**

   * Open **Clients & Handshakes…**.
   * Select a **BSSID** → view **clients**.
   * **Double-click** a client to assign an **alias**.
   * Click **Start monitoring (BSSID)** for a passive handshake capture.
   * On success: **EAPOL: yes** and `.22000` content appears.
   * Use **Copy hash** and **Open folder** as needed.

6. **Export**

   * Click **Export clients** to produce **CSV** (and JSON if enabled).

7. **Stop**

   * Click **STOP** to end processes and restore system state.

---

## 9) Discovery Filters & Search (if enabled)

* **Search** – filter by partial ESSID/BSSID.
* **Hide hidden SSIDs** – removes blank/`<hidden>` rows.
* Clear the search and uncheck the box to reset the view.

---

## 10) Session Save & Resume

The app writes to `session.json` continuously. Restarting with the **same ESSID** reloads:

* known **BSSIDs**,
* **clients** and **aliases**,
* last counters/settings.

---

## 11) Export Formats

* **CSV:** `clients.csv` with BSSID, ESSID, Channel, Client MAC, Alias, Last seen.
* **JSON** (optional): same data in machine-friendly format.
  Files are in `logs/<SAFE_ESSID>/`.

---

## 12) Self-Test (Diagnostics)

The **Self-test** window shows:

* Locations of `airodump-ng`, `hcxpcapngtool`, `iw`, `ip`, `systemctl`.
* `iw dev` output (interfaces).
* Capabilities via `iw list` (bands/channel widths your adapter supports).

---

## 13) Notifications & Dark Mode

* **Desktop notification** is sent when a valid `.22000` is produced.
* **Dark mode** toggles a dark theme suited for longer sessions.

---

## 14) Watchdog Behavior

If `airodump-ng` produces no output for a reasonable period:

* The process is **terminated cleanly** and **restarted** for that step.
* Events are logged with timestamps for traceability.

---

## 15) Inotify vs. Polling

* With **inotify**, CSV changes are parsed immediately.
* Without inotify, the app uses **low-overhead mtime polling**.
* Client discovery feels more responsive with inotify but both modes are supported.

---

## 16) Troubleshooting

* **Empty discovery**

  * Verify **band** selection.
  * Confirm adapter supports **5/6 GHz** (Self-test → `iw list`).
  * Ensure monitor mode is active (`iw dev` and app logs).

* **No results on 6 GHz**

  * May require newer kernel/driver/firmware.
  * 6 GHz often needs **frequency set** fallback; the app attempts this.

* **No clients**

  * Increase **Per-BSSID** to 90–120 s.
  * Try during busier hours.

* **No `.22000`**

  * Allow more time; ensure **EAPOL** traffic exists.
  * Review `hcxpcapngtool` messages in the log.

* **UI unresponsive / uncertain state**

  * Click **STOP**.
  * Restart the app.
  * Check `session.log` for exact command/exit code history.

---

## 17) FAQ

**Does the app perform deauth?**
No. The deauth buttons are **placeholders**. They only start **passive** capture.

**Can I monitor multiple BSSIDs simultaneously?**
The app scans **sequentially** per BSSID; the status shows progress (e.g., “2/5”).

**Does “Copy hash” clear the clipboard automatically?**
No. Clipboard content **persists** in this build.

**Where are outputs stored?**
Under `logs/<SAFE_ESSID>/` (see §4).

**Can I open everything quickly?**
Use **Open logs directory** from the main log panel.

---

## 18) Recommended Operating Practices

* Start with a shorter **Discovery** (10–20 s) for quick feedback; extend as needed.
* Use **Per-BSSID** ≥ 45–60 s; increase on quiet networks.
* Assign **aliases** to recurring clients for faster recognition.
* Work **per band** (2.4/5/6) for clarity.

---

## 19) Quick Reference

* **Run:** set *interface, monitor name, band, ESSID* → **Start**.
* **Discovery:** review table → filter if needed.
* **BSSIDs:** band-filtered list → per-BSSID client view populates.
* **Client Center:** **Start monitoring (BSSID)** → wait for **.22000** → **Copy hash**.
* **Export:** **Export clients** (CSV/JSON).
* **Stop:** **STOP** to restore system state.

---

If anything behaves unexpectedly, start with `session.log`. It records each command, output head, and exit code, which usually pinpoints the issue quickly.
