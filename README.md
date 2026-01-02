# Win11-Performance-Skript

Ein **PowerShell-Skript** zur Optimierung/Entlastung von **Windows 11** auf Low-End-Geräten (z. B. **Lenovo IdeaPad Duet 3, 4GB RAM / 64GB eMMC**).

Schwerpunkt:
- weniger Hintergrundlast (Background-Apps/Telemetry/Update-Downloads)
- Debloat (Entfernung typischer Consumer-Apps)
- Cleanup (Temp/Cache/Update-Downloads)
- **DryRun/Preview** (zeigt geplante Änderungen ohne etwas anzuwenden)
- konservative Autostart-Optimierung **ohne OneDrive standardmäßig abzuschalten**
- Fortschrittsanzeige + Log-Datei

> Hinweis: Das Skript ist so ausgelegt, dass Windows 11 weiterhin sinnvoll nutzbar bleibt (VS Code/Programmierung, Internet, Streaming). Änderungen erfolgen dennoch auf eigene Gefahr.

---

## Hinweis zur Erstellung (KI)

Dieses Repository (README und Skript) wurde vollständig **KI-gestützt** erstellt und iterativ angepasst – im **VS Code Agent Mode** mit **ChatGPT** als Agent/Modell. Bitte prüfe Änderungen vor dem Einsatz und nutze das Skript auf eigenes Risiko.

---

## Repository-Inhalt

Dieses Repository enthält:
- `Win11-Duet3-MasterTune.ps1` – All-in-one: Debloat + Cleanup + Tune + optional Autostart

---

## Voraussetzungen

- Windows 11
- PowerShell 5.1 oder PowerShell 7
- Für Apply-Läufe: **Administratorrechte**

Optional:
- DryRun ohne Admin: `-DryRun -AllowDryRunWithoutAdmin` (Appx/Provisioned-Abfragen sind dann eingeschränkt, es wird gewarnt statt Fehler zu werfen)

---

## Schnellstart

```powershell
Set-ExecutionPolicy Bypass -Scope Process

# Default/empfohlen (Profil Duet3LowEnd)
.\Win11-Duet3-MasterTune.ps1 -Apply -Profile Duet3LowEnd

# DryRun/Preview (keine Änderungen)
.\Win11-Duet3-MasterTune.ps1 -Apply -Profile Duet3LowEnd -DryRun

# DryRun ohne Admin (nur Preview, eingeschränkt)
.\Win11-Duet3-MasterTune.ps1 -Apply -Profile Duet3LowEnd -DryRun -AllowDryRunWithoutAdmin

# Aggressiv: MaxPerformance
.\Win11-Duet3-MasterTune.ps1 -Apply -Profile MaxPerformance
```

---

## Profile

- **`Duet3LowEnd`** (Default)
  - sinnvolle Low-End Defaults
  - reduziert Hintergrundlast (u. a. Background Apps, Telemetry Policies, Update-Bandwidth)
  - Component Store Cleanup/Trim (ResetBase) ist in diesem Profil standardmäßig aktiv
  - OneDrive-Autostart bleibt aktiv

- **`Conservative`**
  - vorsichtig: Cleanup + Tune, ohne Debloat

- **`MaxPerformance`**
  - aggressiver: Debloat + Cleanup + Tune
  - zusätzlich: Widgets/Teams consumer/Clipchamp entfernen
  - optional: Lenovo-„Nice-to-have“-Tools entfernen (keine Treiber)
  - OneDrive-Autostart bleibt aktiv

- **`Custom`**
  - eigene Flags setzen

---

## Wichtige Optionen (Auswahl)

- `-DryRun` – zeigt an, was passieren würde
- `-AllowDryRunWithoutAdmin` – DryRun ohne Admin erlauben (mit Warnungen/Abschlägen)
- `-OptimizeAutostart` – konservative Autostart-Bereinigung (Run-Keys)
- `-KeepOneDriveAutostart` – OneDrive NICHT anfassen
- `-RemoveLenovoOptional` – optional Lenovo Tools entfernen (Vantage/Utility/Service Bridge etc.)
- `-TrimComponentStore` – DISM ResetBase (mehr Platz, aber Rollback/Uninstall alter Patches eingeschränkt)

---

## Logs

Standard-Log:
- `%ProgramData%\Win11-Duet3\MasterTune.log`

---

## Empfehlungen nach dem Lauf

- Neustart
- danach 10–20 Minuten „idle“ lassen (Indexing/Store/Defender beruhigt sich)
- dann Performance prüfen

---

## Lizenz

Wenn du eine Lizenz verwenden willst: z. B. MIT (noch nicht gesetzt).
