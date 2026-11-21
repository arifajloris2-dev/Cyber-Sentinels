# Cyber Sentinels dashboard

The dashboard is a local browser UI built with NiceGUI. It runs the deterministic SOC pipeline against local logs
and displays prioritized incidents, their evidence timeline, MITRE ATT&CK mapping, source health, Member 1 threat
intelligence findings and targeted hunts, and operator-directed verification checks. It does not take response
actions.

## Run

From the project root, install the project dependencies and launch the app:

```powershell
python -m pip install -r requirements.txt
python -m frontend
```

The dashboard opens at `http://127.0.0.1:8080` and remains on this computer by default. The responsive layout
adapts to desktop, tablet, and phone-sized browser windows.

To access it from another device on a trusted LAN, use `python -m frontend --host 0.0.0.0`. The dashboard has no
login; restrict access with your firewall and never port-forward it to the Internet.

By default, the dashboard uses the 50-device synthetic scenario in `backend/soc/fleet/logs`. It generates the
scenario on first launch if needed, then opens the incidents, benign activity, maintenance, and source-health
results in the dashboard. To use another local collection, pass its directory:

```powershell
python -m frontend --logs C:\path\to\collected-logs
```

The directory must include `sources.yaml`, `assets.yaml`, and `maintenance.yaml` alongside the configured log files.

To stream a network-attack CSV as if it were live telemetry:

```powershell
python -m frontend --csv C:\path\to\cybersecurity_attacks.csv --csv-batch 30 --csv-interval 2
```

The simulator processes a small batch at a time, keeps a rolling window of recent telemetry, runs the same
deterministic SOC engine, and compares detections with the CSV `Attack Type` column. The replay clock advances
quickly so bursts can be tested, and the CSV repeats automatically when it reaches the end. Traffic from many
distinct sources to one asset can trigger the `NET-004` possible-bot-swarm rule. Detected activity appears in the
dashboard's paginated Alerts history. Cached OSINT vulnerability and credential findings are used as incident
context; they do not by themselves confirm an incident. No automatic response action is used.

The downloaded 40,000-row cybersecurity-attacks dataset is located at
`simulation/cybersecurity_attacks/cybersecurity_attacks.csv`.

## Automatic local Qwen3 summaries

When an incident is selected, one explanation panel shows a deterministic plain-language fallback while the
dashboard asks the local Ollama runtime for an advisory summary in the background. The Qwen3 result includes a
tentative triage opinion (`likely suspicious`, `possibly authorized/benign`, or `inconclusive`), cited evidence
groups, uncertainty, and up to two operator verification checks. CPU inference may take time; the dashboard remains
usable. Use **Test Qwen** to see whether the configured endpoint is reachable and whether the selected model exists.
The endpoint and model can be edited in the dashboard, and **Regenerate explanation** retries the selected incident.

The model does not detect attacks, change incident priority, close alerts, or take response actions. The operator
makes the decision. Raw source logs are hidden from the main dashboard and can be opened on demand with **View
source logs**.

Install Ollama separately, then download and start the model on the machine that will host it:

```powershell
ollama pull qwen3:4b
ollama serve
```

By default, the dashboard uses `http://127.0.0.1:11434`. The AI status in the UI reports the endpoint, model, and
specific connection error. To use a Qwen3 host on the same trusted LAN, set `OLLAMA_URL` on the client to its private
IP. The analyzer accepts loopback and private LAN IPs only; public addresses and hostnames are rejected.

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
- `threat_findings` (optional): Member 1 vulnerability and credential exposure findings
- `hunt_requests` (optional): Member 1 targeted investigations handed to Member 2
- `advisories` (optional): map of incident ID to Member 3 briefing (`explanation`, optional `recommendations`)

The `SocPipelineProvider` adapts Member 2's `backend.soc.pipeline.run()` output. `IntegratedAgentProvider`
combines it with Member 1's `backend.osint_agent.run_osint_agent()` vulnerability and credential findings, plus
targeted hunt requests. The dashboard launcher uses the integrated provider by default. Member 1 findings are shown
as intelligence context, not as confirmed incidents. Member 3 local Qwen3 summaries are requested for the selected
incident at runtime. Provider exceptions are shown to the operator rather than silently ignored.

## Project guardrails

- Detection and correlation stay deterministic; the local model explains existing results and does not assign severity.
- Approved patching and backup activity stays suppressed by the SOC maintenance rules.
- Incident timelines summarize evidence by default; original log lines remain available on demand.
- Missing log sources remain visible and lower incident confidence rather than hiding detection results.
- Source health is color-coded: healthy is green, warnings are amber, and silent sources are red; silence durations show hours and remaining minutes.
- The engine remains advisory-only: there are no automatic changes or response actions on monitored systems.
- Keep the SOC regression tests green for the under-10-minute flagging target, low false-incident rate, cross-source
  correlation, missing-source behavior, and local performance:

```powershell
$env:PYTHONPATH = "backend"
python -m pytest frontend/tests AI_Log_Analyzer/test_validation.py backend/soc/tests -q
```

## Prepare a demo (precomputed results)

The synthetic logs are deterministic, so the analysis and the AI explanations can be prepared once:

```powershell
python -m frontend.precompute --logs backend/soc/fleet/logs            # all incidents (~1-2 min each on a laptop CPU)
python -m frontend.precompute --logs backend/soc/fleet/logs --only P1  # only priority 1
python -m frontend.precompute --logs backend/soc/fleet/logs --no-ai    # only the engine analysis
```

Results are saved in `<logs>/out/` (`engine_cache.json.gz`, `ai_explanations.json`, not in git). The dashboard then
opens in about a second and shows every prepared explanation instantly, labelled "Prepared in advance … with
<model>". Each saved item carries a fingerprint: the engine cache of the log files, rules, imported knowledge and
engine code; each AI explanation of the exact prompt (incident, evidence, intel, source health) and the model. When
anything changes, the stale item is ignored and the result is computed live. "Regenerate explanation" always asks
the AI live and saves the new answer. The caches are plain JSON: loading them can never run code.
