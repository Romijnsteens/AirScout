# Handleiding – Wi-Fi Passive Monitor (ESSID + bandfilter)

Deze gids legt **alle functies van de app** uit. Geen code-kennis nodig. Volg de stappen en check de screenshots in je hoofd 😉. Waar je “↪” ziet, staat precies wat je moet doen.

---

## 1) Wat deze app doet (in één zin)

De app **zoekt jouw doel-SSID**, toont **passende BSSIDs per band (2.4/5/6 GHz)**, **luistert passief per BSSID** naar verkeer om **clients te zien** en (alleen passief) **.22000-handshakes** weg te schrijven — **zonder actieve deauth** (deauth-knoppen zijn placeholders).

---

## 2) Systeemvereisten

* OS: Linux (met `iw`, `ip`, `systemd`/`NetworkManager`).
* Tools: `airodump-ng`/aircrack-ng (nieuwste), `airmon-ng`, `hcxpcapngtool`, `iw`, `ip`, `systemctl`.
* Rechten: start als root of met de juiste capabilities voor de capture-tools.
* Wi-Fi-adapter: ondersteunt **monitor mode** en de gekozen band(en). Voor **6 GHz** heeft je adapter/driver/kern vers genoeg nodig.

---

## 3) Eerste installatie

1. Controleer tools:

   * `which airodump-ng`, `which hcxpcapngtool`, …
2. Start de app:

   * `python3 jouw_script.py`
3. Zie je een fout “Start dit script als root”? Start dan als root.

> Tip: gebruik de **Self-test** (zie §12) om snel te zien of alles goed staat.

---

## 4) Bestandsstructuur

* `logs/<SAFE_ESSID>/session.log` – doorlopende log (met rotatie >5 MB).
* `logs/<SAFE_ESSID>/discovery-01.csv` – laatste discovery-output.
* `logs/<SAFE_ESSID>/<ESSID>_mon-01.csv` – per-BSSID monitor CSV.
* `logs/<SAFE_ESSID>/aliases.json` – jouw **aliassen** voor MAC-adressen.
* `logs/<SAFE_ESSID>/session.json` – **sessiegegevens** (BSSIDs, clients, UI-state).
* `logs/<SAFE_ESSID>/*hs* .22000` – **passief** opgeslagen WPA handshakes.

`<SAFE_ESSID>` is je SSID, schoongemaakt voor een veilige mapnaam.

---

## 5) UI-overzicht (hoofdfenster)

### 5.1 Topbalk (instellingen)

* **Wi-Fi interface**
  De **fysieke** interface, bv. `wlan1`.

* **Monitor naam**
  Hoe de interface in **monitor mode** heet, bv. `mon0`. De app zet je interface in monitor-mode en hernoemt indien nodig.

* **Band (2.4 / 5 / 6 GHz)**
  Kies de band waarop je de **doel-SSID** verwacht. 6 GHz werkt met de nieuwste aircrack-ng.

* **ESSID**
  Exacte **naam van het netwerk** waar je op filtert (hoofd-/kleine letters tellen).

* **Logniveau**
  `basic` (rustig), `verbose` (meer), `debug` (alles).

* **Discovery (s)**
  Hoe lang de **algemene scan** over de gekozen band loopt.

* **Per-BSSID scan (s)**
  Hoe lang je per **gevonden BSSID** passief luistert om **clients** te zien.

* **Start** / **STOP**
  Start de pipeline / stopt alles en **zet je systeem netjes terug** (processen beëindigen; NetworkManager & interface herstellen als dat van toepassing is).

### 5.2 Discovery-tabel

Toont **alle netwerken** die tijdens de discovery zijn gezien (BSSID, kanaal, band, ESSID).

* **Filteren** (als toegevoegd in jouw build):

  * Zoekveld: typ een stukje BSSID/ESSID → lijst filtert live.
  * Checkbox “Hidden SSIDs verbergen”: filtert lege/“<hidden>” namen uit.

### 5.3 Target & BSSID-selectie (band-gefilterd)

Laat alleen **BSSIDs** zien die:

* tot je **ESSID** behoren, én
* op de **gekozen band** zitten.

Handig om te zien **welke access points** exact bij je ESSID horen, incl. kanaal.

### 5.4 Monitoring (per BSSID)

* **Statusregel**
  Zegt waar je bent: discovery, welke BSSID, resttijd, enz.

* **Voortgangsbalk**

  * Discovery: **indeterminate** animatie + countdown.
  * Per-BSSID: tikt omlaag (0 → klaar/volgende).

* **Clients gezien (huidige BSSID)**
  Live lijst van **client-MACs** die aan deze BSSID hangen.
  Zie je **aliassen** als je ze hebt toegekend.

* **Skip-knoppen**

  * *Discovery overslaan*: stopt discovery direct en gaat door.
  * *Volgende BSSID (skip)*: springt naar de volgende BSSID.

* **Clients & Handshakes…**
  Opent het **Client Center** (zie §6).

### 5.5 Log

Console-achtige tekst met timestamps.
Alles wat belangrijk is komt hier voorbij (commando’s, exitcodes, converter-output, fouten). Opslag in `session.log` met automatische rotatie.

* **Open logs-map**
  Opent de map van de **huidige sessie**.

---

## 6) Client Center (tweede venster)

### 6.1 Access Points (links)

Overzicht van **BSSIDs** die bij je ESSID + band horen.
Selecteer er één om de bijbehorende **clients** te zien.

### 6.2 Clients (rechts)

Lijst van **client-MACs** onder de geselecteerde BSSID, met **Laatst gezien** tijd.

* **Alias geven** (dubbelklik of contextmenu → *Naam geven…*)
  Koppel een **leesbare naam** aan een MAC.
  Wordt bewaard in `aliases.json`.
  Alias verwijderen kan via contextmenu → *Alias wissen*.

### 6.3 Actie-knoppen

* **Start monitoren (BSSID)**
  Start **passieve handshake-capture** op de geselecteerde BSSID.
  ↪ Je ziet een **countdown** en een **EAPOL**-indicator.

* **Stop monitoren**
  Stopt de lopende capture.

* **Broadcast** / **Gericht op client**
  **Placeholders** (geen deauth-uitvoering in deze build).
  Ze starten **wel meteen** een **passieve** handshake-capture voor dezelfde BSSID.

* **Packets**
  Aantal dat je **eventueel** zou gebruiken in een actieve aanval (hier niet actief).
  Staat er voor je lab-varianten; functioneert hier alleen als UI-waarde.

* **Export clients**
  Schrijft **CSV** met alle bekende clients (per BSSID), en **JSON** (als je die optie hebt aangezet) met dezelfde inhoud, in de logs-map van je sessie.

### 6.4 .22000-paneel

* Toont de **eerste regels** van het laatst gevonden **.22000** bestand.
* **Copy hash**: kopieert de tekst naar je klembord. *(In deze build blijft de tekst staan — geen auto-clear meer.)*
* **Open map**: opent de map waar de **.22000** staat.

### 6.5 Statusrij beneden

* **⏳ teller**: loopt omlaag (of “loopt…” bij onbepaalde tijd).
* **EAPOL**: “ja” zodra converter-/stdout-signalen wijzen op een handshake.

---

## 7) Hoe het onder water werkt (functioneel)

* **Preflight**
  Checkt of benodigde binaries bestaan. Mist er iets? Je krijgt een foutmelding.

* **Monitor-mode**
  De app zet je interface in **monitor mode** en hernoemt die naar je **monitor-naam**.
  Aan het einde zet de app je **systeem netjes terug** (processen stoppen; NetworkManager & interface herstellen als dat vooraf actief/van toepassing was).

* **Discovery**
  Draait `airodump-ng --band <bg|a|6>` en schrijft een **CSV**.
  Parser is **header-gedreven** (robuust bij komma’s en rare ESSIDs).

* **BSSID selectie**
  Filtert op **exacte ESSID** en **gekozen band**.

* **Per-BSSID monitor**
  Pinned het **kanaal** van de monitor-interface (6 GHz heeft een **freq-fallback**) en draait `airodump-ng` met `--bssid` + `--channel`.
  Leest de **stations-sectie** uit de CSV en toont **nieuwe clients** live.

* **Handshake (.22000)**
  Tijdens monitoren (**of** via de Client Center knoppen) loopt een passieve capture.
  Nieuwe `.cap` → converteren met `hcxpcapngtool` → zodra `.22000` data bevat, tonen en loggen.
  Er is een **desktopmelding** bij handshake-detectie (als je notificaties aan hebt staan).

* **Watchdog**
  Als `airodump-ng` **te lang geen output** geeft, wordt het proces **netjes gestopt** en opnieuw gestart voor die stap. Dit voorkomt “stille hangers”.

* **Inotify (optioneel)**
  Waar mogelijk wordt **inotify** gebruikt: bij file-wijzigingen parsen we direct.
  Is inotify niet beschikbaar? Dan valt de app terug op **lichte mtime-polling**.

* **Logging**
  Zowel **stdout** als **stderr** van subprocessen komen in de log.
  `session.log` roteren we automatisch (bestand > 5 MB).

* **Sessie-opslag**
  BSSIDs, clients, aliassen en UI-staat worden naar `session.json` geschreven en **bij start** automatisch geladen — zo pak je na een herstart snel door.

---

## 8) Stap-voor-stap: jouw eerste run

1. **Instellen**

   * ↪ Kies *Wi-Fi interface* (bv. `wlan1`).
   * ↪ Kies *Monitor naam* (bv. `mon0`).
   * ↪ Kies *Band* (2.4/5/6 GHz).
   * ↪ Vul *ESSID* exact in.
   * ↪ Zet *Discovery (s)* op 15–30s en *Per-BSSID (s)* op 45–60s.
   * ↪ *Logniveau* op `verbose`.

2. **Start**

   * ↪ Klik *Start*. Je ziet de **discovery-progress**.
   * Na afloop zie je netwerken in de **tabel**.

3. **BSSID-s kiezen**

   * De **Target & BSSID**-lijst vult zich met BSSIDs van jouw **ESSID + band**.

4. **Per-BSSID clients**

   * De app loopt automatisch langs de BSSIDs.
   * Kijk rechts in **Clients gezien** — verschijnen er MACs, dan zit je goed.

5. **Client Center**

   * ↪ Klik *Clients & Handshakes…*.
   * Kies een **BSSID** links → zie **clients** rechts.
   * ↪ Dubbelklik een client → **Alias** geven.
   * ↪ Klik *Start monitoren (BSSID)* → **passieve handshake**.
   * Bij succes: **EAPOL: ja** + regels in het **.22000-paneel**.
   * ↪ *Copy hash* om de tekst te kopiëren.
   * ↪ *Open map* om de map met `.22000` te openen.

6. **Exporteren**

   * ↪ *Export clients* → krijg **CSV** (en JSON als aan) in de logs-map.

7. **Stoppen**

   * ↪ Klik *STOP* (hoofdscherm).
   * Processen stoppen, UI wordt gereset, systeem netjes hersteld.

---

## 9) Filters en zoeken (Discovery)

*(Als je build filters bevat.)*
Boven de discovery-tabel kun je:

* **Zoeken**: typ `cafe` → alleen ESSIDs/BSSIDs met “cafe”.
* **Hidden verbergen**: vink aan → regels zonder ESSID verdwijnen.

**Reset** door het zoekveld leeg te maken en de checkbox uit te zetten.

---

## 10) Sessies opslaan en hervatten

* De app schrijft continu naar `session.json`.
* Bij het opnieuw starten van dezelfde **ESSID** laadt de app:

  * bekenden **BSSIDs**,
  * **clients** en **aliassen**,
  * je laatste **instellingen**.

Zo hoef je niet elk detail opnieuw te zoeken.

---

## 11) Export

* **CSV**: `clients.csv` met BSSID, ESSID, Kanaal, Client MAC, Alias, Laatst gezien.
* **JSON** (optioneel): machine-vriendelijk bestand met dezelfde data.

Je vindt ze in `logs/<SAFE_ESSID>/`.

---

## 12) Self-test (Diagnose)

Knop **Self-test** (als aanwezig):

* Toont:

  * paden naar `airodump-ng`, `hcxpcapngtool`, `iw`, `ip`, `systemctl`;
  * output van `iw dev` (interfaces);
  * **capabilities** via `iw list` (welke banden/kanaalbreedtes je adapter aankan).
* Handig om meteen te zien waarom een band of kanaal niets oplevert.

---

## 13) Meldingen & dark mode

* **Desktopmelding** bij handshake-detectie (zodra `.22000` data bevat).
* **Dark mode** toggle schakelt over naar een donker thema (fijn voor lange sessies).

---

## 14) Watchdog – wat mag je verwachten?

* Als `airodump-ng` **geen output** geeft gedurende een redelijke tijd:

  * de app **stopt** het proces netjes;
  * en **start** het **automatisch opnieuw** voor die stap (discovery of per-BSSID).
* Je ziet dit terug in de **log** (met de naam van de stap en het herstart-moment).

---

## 15) Inotify vs. polling

* **Inotify aan boord?**
  CSV-wijziging → **direct** parsen → UI voelt sneller.
* **Geen inotify?**
  We gebruiken **lichte mtime-polling** (lage CPU-belasting).
* Je merkt het vooral als clients snel in/uit beeld komen.

---

## 16) Probleemoplossing

* **Lege discovery**

  * Klopt de **band**?
  * Ondersteunt je **adapter** 5/6 GHz? (check **Self-test → iw list**)
  * Staat de interface echt in **monitor mode**? (zie log + `iw dev`)

* **Niets op 6 GHz**

  * Nieuwe kernel/driver nodig?
  * Sommige adapters willen **`set freq`** i.p.v. puur kanaal — de app probeert beide.

* **Geen clients**

  * Verhoog **Per-BSSID (s)** naar 90–120s.
  * Probeer op drukke tijden.

* **Geen .22000**

  * Wacht langer; zorg dat er **EAPOL**-verkeer is.
  * Kijk de logoutput van `hcxpcapngtool` na voor hints.

* **UI hangt / onduidelijke staat**

  * Klik *STOP*.
  * Sluit de app en start opnieuw.
  * Check `session.log` in de logs-map.

---

## 17) Veelgestelde vragen

**Q: Voert de app deauth uit?**
A: **Nee.** De twee knoppen zijn **placeholders**. Ze starten enkel **passieve** capture.

**Q: Kan ik meerdere BSSIDs tegelijk monitoren?**
A: De app loopt **sequentieel** per BSSID. Je ziet de index (bijv. “2/5”).

**Q: Blijft mijn klembord gevuld na “Copy hash”?**
A: Ja. **Auto-clear is uit** in deze build.

**Q: Waar staat mijn data?**
A: In `logs/<SAFE_ESSID>/…` (zie §4).

**Q: Kan ik met één klik alles openmaken?**
A: Gebruik **Open logs-map**; daar vind je CSV/JSON/.22000.

---

## 18) Best practices (kalm en effectief)

* Begin met een **kortere discovery** (10–20s) voor snelle feedback; verleng later.
* **Per-BSSID** minimaal 45–60s, langer voor rustige netten.
* Geef **aliassen** aan terugkerende clients; scheelt zoeken later.
* Werk **per band** (2.4/5/6) apart voor overzicht.

---

## 19) Samenvattende cheat sheet

* **Starten** → *interface, monitornaam, band, ESSID* invullen → **Start**.
* **Discovery** → wacht animatie → check tabel → filter zo nodig.
* **BSSIDs** → zie lijst → app scant per stuk → **Clients** vullen.
* **Client Center** → *Start monitoren (BSSID)* → wacht op **.22000** → **Copy hash**.
* **Export** → *Export clients* (CSV/JSON).
* **Stoppen** → **STOP** (alles netjes teruggezet).

---

Dat is ‘m. Als je ergens op vastloopt, kijk eerst in `session.log`; die vertelt meestal exact wat er gebeurde (welk commando, met welke exitcode). En als je wilt, kan ik je scherm-voor-scherm door jouw specifieke setup loodsen.
