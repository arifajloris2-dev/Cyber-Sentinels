# Member 4: VMware Simulation & Testing

Use one of the project’s local replay paths; neither requires a live VMware environment.

## Recommended: synthetic multi-source SOC scenario

The repeatable 50-device scenario includes multiple log sources, four planted attacks, benign activity,
scheduled maintenance, and a deliberately missing log source. It is the best fit for measuring correlation,
false incidents, and source-health behavior:

```powershell
python backend/soc/fleet/make_fleet.py --no-ecs
python backend/correlation.py backend/soc/fleet/logs
python -m frontend --logs backend/soc/fleet/logs
```

To measure time-to-flag from the repository root in PowerShell:

```powershell
$env:PYTHONPATH = "backend"
python -m soc replay backend/soc/fleet/logs
```

The generated logs are reproducible and rebuildable; they are not committed. Details and expected results are in
[`backend/soc/fleet/README.md`](../backend/soc/fleet/README.md).

## Optional: CSV dashboard replay

The locally downloaded dataset is at `simulation/cybersecurity_attacks/cybersecurity_attacks.csv` (kept out of
version control). Replay it in small batches:

```powershell
python -m frontend --csv simulation/cybersecurity_attacks/cybersecurity_attacks.csv --csv-batch 30 --csv-interval 2
```

This is useful for a visual walkthrough, but the 40,000-row sample has no benign-negative records, so it cannot
establish a false-alarm rate. The CSV adapter uses its attack labels only as replay ground truth, never as rule input.

To replay logs collected from an isolated VMware lab, place them in a folder with matching `sources.yaml`,
`assets.yaml`, and `maintenance.yaml`, then launch `python -m frontend --logs <folder>`.
