# Collecting logs

Both scripts only **read** logs and write copies. Move the copies to the SOC machine over a cable or USB stick:
nothing goes to the internet.

## Windows

Once, as Administrator, turn on the logging the rules need:

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension" /success:enable
auditpol /set /subcategory:"User Account Management" /success:enable
Set-NetFirewallProfile -All -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 32767
```

Then, as Administrator, whenever you want fresh logs:

```powershell
powershell -ExecutionPolicy Bypass -File soc\collect\collect_windows.ps1 -OutDir C:\soc-logs -Name win01
```

Produces `win01_events.jsonl` (JSON Lines, UTC) and `win01_pfirewall.log` (text, local time).

## Ubuntu

Once: make sure the firewall logs allowed connections too (`medium` logs new allowed connections):

```bash
sudo ufw logging medium
```

Then, whenever you want fresh logs:

```bash
sudo bash soc/collect/collect_linux.sh /tmp/soc-logs ubu01
```

Produces `ubu01_auth.log`, `ubu01_ufw.log`, `ubu01_syslog`, `ubu01_dpkg.log`.

## Put it together

Copy all files into one folder and add `sources.yaml`, `assets.yaml` and `maintenance.yaml`.
Start from the ones in `soc/sample_logs/` and change the file names, host names and IP addresses
(`hostname` / `ipconfig` on Windows, `hostname` / `ip a` on Ubuntu). Then:

```bash
python correlation.py <folder>
```
