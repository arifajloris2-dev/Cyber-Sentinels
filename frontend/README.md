# Cyber Sentinels desktop dashboard

The dashboard is a local Python desktop application (Tkinter), not a web page or web server. It runs the
deterministic SOC pipeline against local log files and displays prioritized incidents, their evidence timeline,
MITRE ATT&CK mapping, source health, and operator-directed verification checks. It does not take response actions.

## Run

From the project root, install the SOC dependencies once and launch the app:

```powershell
python -m pip install -r backend/soc/requirements.txt
python -m pip install -r AI_Log_Analyzer/requirements.txt
python -m frontend
```

By default, the dashboard uses `backend/soc/sample_logs`. To use another local collection, pass its directory:

```powershell
python -m frontend --logs C:\path\to\collected-logs
```

The directory must include `sources.yaml`, `assets.yaml`, and `maintenance.yaml` alongside the configured log files.
The app stays on the desktop and processes the files locally.

## Automatic local Qwen3 summaries

When an incident is selected, the dashboard immediately shows a deterministic overview and automatically asks the
local Ollama runtime for a concise advisory summary in the background. The Qwen3 result includes a tentative triage
opinion (`likely suspicious`, `possibly authorized/benign`, or `inconclusive`), cited evidence groups, uncertainty,
and up to two operator verification checks. CPU inference may take time; the UI remains usable and shows the
deterministic overview while Qwen3 works. A **Regenerate** control retries the selected incident's summary.

The model does not detect attacks, change incident priority, close alerts, or take response actions. The operator
makes the decision. Raw source logs are hidden from the main dashboard and can be opened on demand with **View
source logs**.

Install Ollama separately, then download and start the model on the machine that will host it:

```powershell
ollama pull qwen3:4b
ollama serve
```

By default, the dashboard uses `127.0.0.1:11434`. To use a Qwen3 host on the same trusted LAN, set `OLLAMA_URL`
on the client to its private IP. The analyzer accepts loopback and private LAN IPs only; public addresses and
hostnames are rejected.

On the Windows host, set Ollama to listen on the LAN and restart it:

```powershell
[Environment]::SetEnvironmentVariable("OLLAMA_HOST", "0.0.0.0:11434", "User")
```

In Windows Defender Firewall, add an inbound TCP rule for port `11434`, apply it only to the **Private** profile,
and restrict remote addresses to the teammate's client IP. Do not create a router port-forward or enable the rule
for Public networks.

Set the host's private IP on each client before launching the dashboard:

```powershell
$env:OLLAMA_URL = "http://192.168.1.50:11434"
python -m frontend
```

On Kali/Linux, use `export OLLAMA_URL="http://192.168.1.50:11434"` in the terminal before running `python -m frontend`.
Replace the example address with the Windows host's private IPv4 address. If it changes, update the client setting
and firewall allowlist.

Ollama's API does not provide authentication or encrypt requests by itself. The firewall allowlist is the access
control: any process on the allowed client can submit prompts, and incident evidence travels over the LAN. Use this
only on a trusted WPA2/WPA3 network, with the host owner's permission, and never expose port `11434` to the public
Internet. For sensitive logs or untrusted Wi-Fi, leave the dashboard on the default loopback endpoint. Summaries
run off the UI thread, and deterministic detection remains usable if Ollama is unavailable.

## Integration contract

The UI consumes `DashboardSnapshot` from `frontend/models.py`. A provider implements `DashboardProvider.load()` in
`frontend/data_provider.py` and returns a snapshot with:

- `incidents`: correlated SOC incidents with alerts/evidence, hosts, ATT&CK techniques, confidence, links, and checks
- `sources`: per-source health records (`source`, `host`, `events`, `ok`, and optional `silent` gaps)
- `alerts`, `singles`, `maintenance`: SOC alert and approved-maintenance results
- `threat_findings` (optional): Member 1 OSINT findings, each with a `title` or `id`
- `advisories` (optional): map of incident ID to Member 3 briefing (`explanation`, optional `recommendations`)

The current `SocPipelineProvider` adapts Member 2's `backend.soc.pipeline.run()` output. When another member's
module is ready, add or update a provider adapter to map its output to this contract; the UI remains independent of
agent implementation details. Provider exceptions are shown to the operator rather than silently ignored.

## Project guardrails

- Detection and correlation stay deterministic; the local model explains existing results and does not assign severity.
- Approved patching and backup activity stays suppressed by the SOC maintenance rules.
- Incident timelines summarize evidence by default; original log lines remain available on demand.
- Missing log sources remain visible and lower incident confidence rather than hiding detection results.
- The engine remains advisory-only: there are no automatic changes or response actions on monitored systems.
- Keep the SOC regression tests green for the under-10-minute flagging target, low false-incident rate, cross-source
  correlation, missing-source behavior, and local performance:

```powershell
$env:PYTHONPATH = "backend"
python -m pytest frontend/tests AI_Log_Analyzer/test_validation.py backend/soc/tests -q
```
