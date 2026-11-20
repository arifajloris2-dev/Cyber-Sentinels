<#
Collect logs from one Windows machine for the SOC engine. READ-ONLY: it reads logs and writes copies; it changes nothing.

Run in PowerShell as Administrator (the Security log needs it):
    powershell -ExecutionPolicy Bypass -File soc\collect\collect_windows.ps1 -OutDir C:\soc-logs -Name win01

Writes:
    <Name>_events.jsonl    Security + System events the rules use, one JSON object per line, time in UTC
    <Name>_pfirewall.log   copy of the Windows Firewall log (local time: set utc_offset in sources.yaml)
    <Name>.state.json      newest event collected, so the next run only adds new events
#>
param(
    [string]$OutDir = "C:\soc-logs",
    [string]$Name = $env:COMPUTERNAME.ToLower(),
    [int]$FirstRunHours = 48
)
$ErrorActionPreference = "Stop"
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Error "Run as Administrator: the Security log cannot be read otherwise." }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$state = Join-Path $OutDir "$Name.state.json"
$eventsFile = Join-Path $OutDir "${Name}_events.jsonl"
$utf8 = New-Object System.Text.UTF8Encoding($false)
$since = (Get-Date).AddHours(-$FirstRunHours)
if (Test-Path $state) { $since = ([datetime]((Get-Content $state -Raw | ConvertFrom-Json).last)).AddMilliseconds(1) }

# Event IDs used by the rules (see soc/parsers.py, WIN_EVENTS)
$queries = @(
    @{ LogName = 'Security'; Id = 4624, 4625, 4648, 4672, 4697, 4719, 4720, 4946, 4947, 4948, 4950, 1102; StartTime = $since },
    @{ LogName = 'System'; Id = 7045; StartTime = $since },
    @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WindowsUpdateClient'; Id = 19; StartTime = $since }
)
$lines = New-Object System.Collections.Generic.List[string]
$latest = $since
foreach ($q in $queries) {
    foreach ($e in @(Get-WinEvent -FilterHashtable $q -ErrorAction SilentlyContinue)) {   # "no events found" is normal
        if ($null -eq $e) { continue }
        $xml = [xml]$e.ToXml()
        $data = [ordered]@{}
        foreach ($d in $xml.Event.EventData.Data) { if ($d.Name) { $data[$d.Name] = [string]$d.'#text' } }
        $rec = [ordered]@{
            TimeCreated = $e.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            Id          = $e.Id
            LogName     = $e.LogName
            MachineName = ($e.MachineName -split '\.')[0].ToUpper()
            RecordId    = $e.RecordId
            EventData   = $data
        }
        $lines.Add(($rec | ConvertTo-Json -Compress -Depth 4))
        if ($e.TimeCreated -gt $latest) { $latest = $e.TimeCreated }
    }
}
if ($lines.Count -gt 0) { [System.IO.File]::AppendAllLines($eventsFile, $lines, $utf8) }
@{ last = $latest.ToString("o") } | ConvertTo-Json | Set-Content -Path $state -Encoding UTF8
Write-Host "Events: $($lines.Count) new -> $eventsFile"

$fw = Join-Path $env:SystemRoot "System32\LogFiles\Firewall"
$parts = @("pfirewall.log.old", "pfirewall.log") | ForEach-Object { Join-Path $fw $_ } | Where-Object { Test-Path $_ }
if ($parts.Count -eq 0) {
    Write-Warning "No firewall log. Turn logging on once (see collect\README.md) and run again."
} else {
    $out = Join-Path $OutDir "${Name}_pfirewall.log"
    [System.IO.File]::WriteAllText($out, (($parts | ForEach-Object { Get-Content $_ -Raw }) -join "`n"), $utf8)
    Write-Host "Firewall log -> $out"
}
