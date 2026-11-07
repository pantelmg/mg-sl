# MG SiteLimiter

by [github.com/pantelmg](https://github.com/pantelmg)

Daily time limits for websites on Windows, enforced for every browser and app through a local DNS filter.

- **Limits per site or per pack** — a pack is a group of domains sharing one daily budget. `0` minutes = always blocked. Subdomains are included (`youtube.com` covers `m.youtube.com`).
- **Statistics** — daily (last 14 days) and weekly (last 12 weeks, Mon–Sun) usage charts for every site/pack, with the limit marked, hover details and a table view. History is kept for ~13 months.
- **Cloudflare 1.1.1.1 for Families** — optionally send every lookup that isn't limit-blocked to Cloudflare's filtering resolvers: *Block malware* (1.1.1.2 / 1.0.0.2) or *Block malware and adult content* (1.1.1.3 / 1.0.0.3).
- **Daily reset at a time you choose** — midnight by default, or e.g. 05:00.
- **Autostarts** — a Windows service starts at boot and launches the tray tracker in every user session (and relaunches it if it is closed).
- **Turning it off is gated** by a password, a waiting period (default 24 h), or either one.

## How it works

```
 ┌──────────────── SiteLimiter.exe (service, LocalSystem) ────────────────┐
 │  DNS filter on 127.0.0.1:53 / [::1]:53  ← every adapter's DNS points here │
 │    blocked name → 0.0.0.0 / ::   otherwise → forwarded to original DNS    │
 │  Limits engine + state  (C:\ProgramData\SiteLimiter, SYSTEM-only ACL)      │
 │  Dashboard + API on http://127.0.0.1:47811 (token-protected)              │
 │  Browser policies: DNS-over-HTTPS off (Chrome/Edge/Brave/Vivaldi/Firefox) │
 │  Network time check (SNTP) so changing the clock doesn't skip the delay   │
 └──────────────▲────────────────────────────────────────────────────────────┘
                │ usage reports every 5 s, blocked list back
 ┌──────────────┴─ SiteLimiter.exe --agent (per user session) ───────────────┐
 │  Reads the focused browser's address bar via UI Automation                │
 │  Counts foreground time only (never while the PC is locked)               │
 │  Closes the active tab of a blocked site (Ctrl+W) and shows a notification│
 │  Tray icon: click = dashboard, right-click = time left per limit          │
 └────────────────────────────────────────────────────────────────────────────┘
```

When a limit runs out, its domains stop resolving everywhere (all browsers, apps), the DNS cache is flushed, and an open tab on that site is closed.

## Build & install

> **WARNING: This is a strict limiter! Be careful.**

Requires the [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) to build:

```powershell
.\build.ps1                    # runs the core tests, writes .\dist\MGSL Installer.exe
```

`MGSL Installer.exe` is a single self-contained file (the target PC needs no .NET runtime). Double-click it and accept the administrator prompt. It installs to `C:\Program Files\SiteLimiter`, registers the auto-start service, and appears in *Settings → Apps* as **MG SiteLimiter**, with `MGSL Uninstaller.exe` as its uninstaller.

Within a few seconds the MG gauge icon appears in the tray. Click it, add your limits, then choose a lock in the *Lock* card. **Nothing is locked until you choose a lock**, so set up your limits first.

## Lock model

| Change | While locked |
|---|---|
| Add a site/pack, add domains to a pack, lower a limit, count more idle time, shorter unlock | Allowed |
| Raise/remove/disable a limit, remove a domain, change reset hour, count less idle time, longer unlock, turn off fail-closed, remove a tracked browser | Needs unlock |
| Turn all limits off (switch next to *Limits*), change the lock, disable autostart, uninstall | Needs unlock |
| Make the Cloudflare filter stricter | Allowed |
| Make the Cloudflare filter less strict or turn it off | Needs unlock |
| Turn limits back on, cancel a prepared uninstall | Always allowed |

- **Password** — unlock is instant; ideal when someone else holds the password.
- **Waiting period** — press *Start waiting period*; after N hours (default 24) an *Unlock now* button appears and stays available for 24 hours. The countdown uses network time, so the delay can't be shortened by changing the Windows clock (unlocking needs a successful online time check).
- **Either** — both options are available.

By default an unlock lasts until you press *Lock now*. You can set it to re-lock by itself after 5 minutes – 4 hours (making it longer needs an unlock).

By default time keeps counting while a limited site is in the foreground, even without mouse/keyboard input (*Stop counting after idle: Don't stop*). Time never counts while the PC is locked.

**Fail-closed:** if a user is logged on and the tracker hasn't reported for 45 s (e.g. it was killed and can't restart), every limited site is blocked until it's back.

**Tamper resistance.** Everything below needs the same unlock as uninstalling:

- **Two services watch each other.** `MG SiteLimiter` and `MG SiteLimiter Guard` check each other every second. If one is stopped it is started again; if one is *suspended* (e.g. Resource Monitor → Suspend process), it is killed and restarted immediately. A suspended tray agent is restarted the same way.
- **Locked service settings.** Administrators can't stop, delete or reconfigure either service (services.msc, `sc.exe`), and can't edit their registry keys or `C:\Program Files\SiteLimiter` (owned by SYSTEM, read-only for admins). Every 30 s both services also put back *Automatic* startup, the exe path and the Safe Mode entries if anything changed them.
- **Safe Mode with Networking.** Both services are registered to start there too.
- **Renamed or unlisted browsers are tracked.** Browsers are recognised by their window type and address bar (Chromium's omnibox, Firefox's URL bar), not only by process name. A copied/renamed `chrome.exe`, a portable browser or Tor Browser is timed and blocked like any other. Apps built on Chromium without an address bar (VS Code, Discord…) are ignored.
- **DNS settings can't be changed from Windows.** Every adapter's DNS points at SiteLimiter's local filter (127.0.0.1 / ::1), which applies the limits and then forwards to Cloudflare or your network's DNS. Changes made in Windows Settings, Control Panel or `netsh` are detected the moment they are written and reverted within about a second; new adapters (USB Wi-Fi, phone tethering) are switched over too. Uninstalling restores each adapter's original setting (usually automatic/DHCP).
- **Hosts file guard.** Entries in `C:\Windows\System32\drivers\etc\hosts` that redirect a limited domain (e.g. `142.250.1.1 youtube.com`) are commented out within 5 s. Blocking entries (`0.0.0.0`, `127.x`) are left alone.
- **Fail-closed.** If the tray agent isn't reporting, every limited site is blocked.

Only *Prepare uninstall* (needs an unlock) relaxes all of this, for 1 hour.

### What can still get around it

A commitment device, not a vault. For someone with **administrator rights**:
- **Offline access.** Booting a Linux live USB or the Windows Recovery Environment command prompt, then deleting `C:\ProgramData\SiteLimiter\config.json` **and** `config.json.bak`. On the next boot the service starts with no limits and no lock, so it can be uninstalled normally. (Deleting `C:\Program Files\SiteLimiter\SiteLimiter.exe` instead only breaks the internet until it is repaired; see below.)
- **System Restore** to a point before installation.
- **Deliberate admin tooling**: taking ownership of the service objects, editing the registry offline, or suspending both services at the same instant.
- **A VPN, proxy or virtual machine** with its own browser inside.

Using a **standard (non-admin) Windows account** day to day, with the admin password held by someone else, removes all of these except offline boot. A BIOS/UEFI password and BitLocker close that one too.

## Uninstall

1. Dashboard → *Uninstall* (last card) → **Prepare uninstall** (needs an unlock). This restores your DNS settings and browser policies.
2. Within 1 hour, run **MGSL Uninstaller.exe**: *Settings → Apps → MG SiteLimiter → Uninstall*, or from `C:\Program Files\SiteLimiter`. It asks: *Yes* deletes everything, *No* uninstalls but keeps your limits and statistics, *Cancel* does nothing. Run before step 1, it explains what to do and offers to open the dashboard.

Updating = prepare uninstall → MGSL Uninstaller.exe → *No* (keeps data) → run the new MGSL Installer.exe. Limits and usage are kept.

## Repair (e.g. after an antivirus removed it)

If an antivirus quarantines or deletes `SiteLimiter.exe` / `MGSL Uninstaller.exe`, the services can't run and every adapter's DNS still points at them, so websites stop loading.

- **Restore it from the antivirus quarantine**, then add `C:\Program Files\SiteLimiter` to the allow list. Everything resumes.
- **Or run `MGSL Installer.exe` again.** It detects the missing files (or a missing service) and offers **Repair**: it puts the exe back, recreates what's missing and restarts both services. Limits, statistics and the lock are kept; repair never removes the lock or any other safeguard.

## If the internet stops working

The service restores every adapter's DNS whenever it stops normally. If something still goes wrong, from an Administrator PowerShell:

```powershell
# Every adapter back to automatic DNS (works even if the program files are gone):
Get-NetAdapter | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses }
Clear-DnsClientCache
# or, if the uninstaller is still there:
& "C:\Program Files\SiteLimiter\MGSL Uninstaller.exe" --reset-dns
```

While the service is running it will point DNS back at itself within a second, so this is only for when it isn't running.

Logs: `C:\ProgramData\SiteLimiter\logs\service.log` and `%LOCALAPPDATA%\SiteLimiter\agent.log`.
Debug the service in a console (stop the service first, via *Prepare uninstall*): `SiteLimiter.exe --console`.

## Limitations

See *What can still get around it* above for tampering. Other known gaps:

- **Only the focused browser window's active tab is counted.** A video playing in a background tab or a picture-in-picture window doesn't use up time. (Once the limit is reached, DNS blocks the site everywhere.)
- **VPNs and proxies** (including the built-in VPNs in Opera and Edge) resolve names outside Windows DNS. The tracker still counts time on the visible tab and closes it when the limit is reached.
- **Apps that hard-code DNS-over-HTTPS by IP** bypass the DNS filter. Well-known DoH hostnames are blocked, and the policies switch it off in the major browsers.
- **Browsers show "Managed by your organization"** because of the DNS-over-HTTPS policy.
- **Cloudflare must be reachable.** With a filter selected, lookups go only to Cloudflare (no fallback to the network's DNS, which would skip the filter). On networks that block 1.1.1.x, or captive portals (hotel/airport Wi-Fi) that need their own DNS before you log in, set the filter to *Inactive* (needs an unlock) to get online.
- **Port 53 must be free.** If other DNS software (Acrylic, AdGuard Home, Technitium, some VPN clients) already listens on 127.0.0.1:53, the dashboard shows a warning and nothing is blocked.
- **Address bar reading** relies on each browser's accessibility tree. Chromium- and Firefox-based browsers are recognised automatically; a browser with a completely custom UI that isn't in the tracked list can't be timed.

## Project layout

```
src/SiteLimiter.Core/     platform-neutral logic: models, domain matching, lock state machine,
                          loosening rules, DNS wire format, password hashing
src/SiteLimiter/          the Windows exe
  Service/                service host, engine, DNS proxy, adapter DNS, policies, API, dashboard.html
  Agent/                  tray icon, UI Automation URL reader, usage reporting
  Native/                 Win32 + UI Automation COM interop (no NuGet dependencies)
  Assets/                 tray-dark.ico / tray-light.ico (generated by tools/make_icon.py)
tests/SiteLimiter.Core.Tests/   dependency-free test runner for the core logic
tools/make_icon.py        regenerates the MG gauge icons (Python + Pillow)
```
