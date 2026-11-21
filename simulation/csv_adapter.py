"""Convert a network-attack CSV into the SOC engine's synthetic log format."""
from __future__ import annotations

import csv
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator


def get_value(row: dict, *names: str) -> str:
    folded = {
        re.sub(r"[^a-z0-9]", "", str(key).lower()): value
        for key, value in row.items()
    }
    for name in names:
        key = re.sub(r"[^a-z0-9]", "", name.lower())
        if key in folded:
            return str(folded[key] or "").strip()
    return ""


def parse_timestamp(value: str) -> datetime:
    text = value.strip()
    if not text:
        return datetime.now(timezone.utc)
    try:
        result = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if result.tzinfo is None:
            result = result.replace(tzinfo=timezone.utc)
        return result
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise ValueError(f"Unsupported timestamp: {value}")


def is_attack(row: dict) -> bool:
    attack_type = get_value(row, "Attack Type")
    if attack_type:
        normalized = attack_type.lower()
        if normalized not in {"", "normal", "normal traffic", "benign", "none"}:
            return True
    warning = get_value(row, "Alerts/Warnings")
    return bool(warning and not re.search(r"\b(no|none|benign|normal)\b", warning, re.I))


def iter_csv_rows(csv_path: Path) -> Iterator[tuple[int, dict]]:
    with csv_path.open("r", encoding="utf-8-sig", newline="", errors="replace") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("The CSV is missing a header row.")
        for index, row in enumerate(reader, 1):
            yield index, row


def prepare_folder(folder: Path) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "sources.yaml").write_text(
        "sources:\n"
        "  - name: csv-windows-firewall\n"
        "    parser: windows_firewall\n"
        "    path: csv_firewall.log\n"
        "    host: sim-csv-host\n"
        "    utc_offset: '+00:00'\n"
        "  - name: csv-windows-events\n"
        "    parser: windows_events\n"
        "    path: csv_windows_events.jsonl\n"
        "    host: sim-csv-host\n"
        "  - name: csv-linux-auth\n"
        "    parser: linux_auth\n"
        "    path: csv_auth.log\n"
        "    host: sim-csv-host\n"
        "    utc_offset: '+00:00'\n"
        "baseline_hours: 24\n",
        encoding="utf-8",
    )
    (folder / "assets.yaml").write_text(
        "assets:\n"
        "  - host: sim-csv-host\n"
        "    ip: 10.50.0.10\n"
        "    role: simulated gateway\n"
        "    criticality: high\n",
        encoding="utf-8",
    )
    (folder / "maintenance.yaml").write_text("tickets: []\n", encoding="utf-8")
    firewall = folder / "csv_firewall.log"
    if not firewall.exists():
        firewall.write_text(
            "#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path\n",
            encoding="utf-8",
        )
    for name in ("csv_windows_events.jsonl", "csv_auth.log"):
        path = folder / name
        if not path.exists():
            path.write_text("", encoding="utf-8")


def reset_simulation(
    folder: Path,
    cycle: int = 1,
    simulation_start: datetime | None = None,
) -> None:
    prepare_folder(folder)
    (folder / "csv_firewall.log").write_text(
        "#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path\n",
        encoding="utf-8",
    )
    (folder / "csv_windows_events.jsonl").write_text("", encoding="utf-8")
    (folder / "csv_auth.log").write_text("", encoding="utf-8")
    (folder / "csv_ground_truth.json").write_text(
        json.dumps({
            "rows": [],
            "cycle": cycle,
            "simulation_start": (simulation_start or datetime.now(timezone.utc)).isoformat(),
        }, indent=2),
        encoding="utf-8",
    )


def append_rows(
    folder: Path,
    csv_path: Path,
    start_row: int,
    batch_size: int,
    rows: list[tuple[int, dict]] | None = None,
) -> dict:
    prepare_folder(folder)
    firewall = folder / "csv_firewall.log"
    manifest = folder / "csv_ground_truth.json"
    existing = json.loads(manifest.read_text(encoding="utf-8")) if manifest.exists() else {"rows": []}
    simulation_start = datetime.fromisoformat(existing["simulation_start"])
    rows_seen = 0
    ground_truth_attacks = 0
    benign = 0
    labels: list[dict] = []

    windows_events = folder / "csv_windows_events.jsonl"
    auth_log = folder / "csv_auth.log"
    with firewall.open("a", encoding="utf-8", newline="\n") as handle, \
         windows_events.open("a", encoding="utf-8", newline="\n") as windows_handle, \
         auth_log.open("a", encoding="utf-8", newline="\n") as auth_handle:
        source_rows = rows if rows is not None else iter_csv_rows(csv_path)
        for index, row in source_rows:
            if index < start_row:
                continue
            if rows_seen >= batch_size:
                break
            source_timestamp = parse_timestamp(get_value(row, "Timestamp"))
            timestamp = simulation_start + timedelta(seconds=index - 1)
            src_ip = get_value(row, "Source IP Address") or "10.50.0.1"
            original_dst_ip = get_value(row, "Destination IP Address") or "10.50.0.10"
            dst_ip = "10.50.0.10"
            src_port = get_value(row, "Source Port") or "0"
            dst_port = get_value(row, "Destination Port") or "0"
            protocol = get_value(row, "Protocol") or "TCP"
            packet_length = get_value(row, "Packet Length") or "0"
            action = get_value(row, "Action Taken")
            attack = is_attack(row)
            attack_type = get_value(row, "Attack Type") or "Benign"
            dropped = action.lower() in {"blocked", "dropped", "denied", "rejected"} or attack
            firewall_action = "DROP" if dropped else "ALLOW"
            line = (
                f"{timestamp:%Y-%m-%d %H:%M:%S} {firewall_action} {protocol.upper()} "
                f"{src_ip} {dst_ip} {src_port} {dst_port} {packet_length} "
                f"- 0 0 0 - - CSV-ROW-{index} "
                "RECEIVE\n"
            )
            handle.write(line)

            if attack_type.lower() == "malware":
                windows_handle.write(json.dumps({
                    "TimeCreated": timestamp.isoformat(),
                    "Id": 4697,
                    "MachineName": "sim-csv-host",
                    "EventData": {
                        "TargetUserName": "svc_csv_sim",
                        "ServiceName": f"csv-malware-{index}",
                        "ImagePath": f"C:\\\\Temp\\\\CSV-ROW-{index}.exe",
                    },
                }) + "\n")

            if attack_type.lower() == "intrusion":
                auth_handle.write(
                    f"{timestamp:%Y-%m-%dT%H:%M:%SZ} sim-csv-host sshd[100]: "
                    f"Failed password for csv_operator from {src_ip} port 2201 ssh2 CSV-ROW-{index}\n"
                )
                auth_handle.write(
                    f"{timestamp:%Y-%m-%dT%H:%M:%SZ} sim-csv-host sshd[100]: "
                    f"Failed password for csv_operator from {src_ip} port 2201 ssh2 CSV-ROW-{index}\n"
                )
                auth_handle.write(
                    f"{timestamp:%Y-%m-%dT%H:%M:%SZ} sim-csv-host sshd[100]: "
                    f"Accepted password for csv_operator from {src_ip} port 2201 ssh2 CSV-ROW-{index}\n"
                )
            rows_seen += 1
            if attack:
                ground_truth_attacks += 1
            else:
                benign += 1
            labels.append({
                "row": index,
                "timestamp": timestamp.isoformat(),
                "source_timestamp": source_timestamp.isoformat(),
                "source_ip": src_ip,
                "destination_ip": original_dst_ip,
                "destination_port": dst_port,
                "attack_type": get_value(row, "Attack Type") or "Benign",
                "attack": attack,
            })

    existing["rows"].extend(labels)
    manifest.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    return {
        "rows_seen": rows_seen,
        "next_row": start_row + rows_seen,
        "ground_truth_attacks": ground_truth_attacks,
        "benign": benign,
    }
