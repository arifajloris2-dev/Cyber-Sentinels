# Lab logs: real data from the team's VMs

Real logs exported from the lab VMs, kept **separate from the 50-device synthetic base** (`../fleet/`). That base is generated, the same on every run, and checked against an answer key; real VMs have other names and dates and no answer key.

```bash
python backend/correlation.py backend/soc/lab_logs     # report in backend/soc/lab_logs/out/
python -m frontend --logs backend/soc/lab_logs          # dashboard
```

## What's here
| File | What | Parser |
|---|---|---|
| `lab-win_events.jsonl` | Windows Security/System export (1,005 events, 20–21 Nov) from one VM. It was renamed during setup: `MINWINPC` → `WIN-0RKVQU2JH17` → `DESKTOP-U3ALSIH`. | `windows_events` |
| `lab-mail_events.jsonl` | Mail demo (4 lines, synthetic): one mail flagged `suspected_phishing` and one `clean`, each followed by a link click | `mail_events` |
| `sources.yaml`, `assets.yaml`, `maintenance.yaml` | Engine settings for this set | |
| `anonymise.py` | Makes a raw export safe to commit | |

## Result
| | |
|---|---|
| Lines read | 1,009, with 0 errors |
| VM setup | Windows install (services + setup accounts) and VMware Tools are covered by tickets `LAB-VM-OS-INSTALL` and `LAB-VM-TOOLS`: 23 alerts suppressed, 0 false incidents. Without the tickets this was a false P2 "System change". |
| Phishing | Rule MAIL-002: `lab-user` clicked a link in mail `demo-001`, which was flagged as phishing, so it becomes 1 incident (T1566.002, T1204.001). The click in the clean mail `demo-002` is not flagged. |

Checked in CI by `backend/soc/tests/test_lab_logs.py`.

## Adding a new VM export
1. Export with `backend/soc/collect/` (Windows: `collect_windows.ps1`, Ubuntu: `collect_linux.sh`).
2. **Anonymise before committing.** Never commit the raw file; real account names go on the command line only:
   ```bash
   python backend/soc/lab_logs/anonymise.py <raw export> backend/soc/lab_logs/<name>.jsonl --rename RealName=lab-user
   ```
   This replaces the names everywhere (case-insensitive) and masks machine-specific Windows SIDs (`S-1-5-21-0-0-0-<rid>`).
3. Add the file to `sources.yaml`, the machine to `assets.yaml`, and any planned setup or maintenance to `maintenance.yaml`.

Still missing: the Ubuntu VM's `auth.log` (the old report listed `edth-ubuntu-auth` with 1 event).
