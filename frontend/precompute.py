"""Prepare the dashboard before a demo: run the analysis once and let the local AI explain every incident once.

    python -m frontend.precompute --logs backend/soc/fleet/logs            # all incidents (~1-2 min each on a laptop CPU)
    python -m frontend.precompute --logs backend/soc/fleet/logs --only P1  # only priority 1
    python -m frontend.precompute --logs backend/soc/scenarios/kosovo_ddos --force   # ask again even if saved

Results go to <logs>/out/engine_cache.json.gz and <logs>/out/ai_explanations.json. The dashboard then shows every
explanation instantly; anything that changed (logs, rules, imported knowledge, model) is asked live instead.
Offline only: the AI runs on the local Ollama server; nothing leaves the machine.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from AI_Log_Analyzer.ai_log_analyzer import AnalysisError, OllamaError, analyze_incident, check_ollama_model
from frontend import cache
from frontend.data_provider import IntegratedAgentProvider

ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--logs", type=Path, default=ROOT / "backend" / "soc" / "fleet" / "logs")
    ap.add_argument("--url", default=os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434"))
    ap.add_argument("--model", default=os.environ.get("OLLAMA_MODEL", "qwen3:4b"))
    ap.add_argument("--only", choices=["P1", "P2", "P3", "all"], default="all")
    ap.add_argument("--timeout", type=float, default=300)
    ap.add_argument("--force", action="store_true", help="ask the AI again even when a saved explanation matches")
    ap.add_argument("--no-ai", action="store_true", help="only prepare the engine analysis")
    args = ap.parse_args(argv)

    t0 = time.perf_counter()
    provider = IntegratedAgentProvider(args.logs.resolve())
    snap = provider.load()
    print(f"engine: {len(snap.incidents)} incidents, {len(snap.events):,} events "
          f"({'saved result reused' if provider.from_cache else 'analysed and saved'}, {time.perf_counter() - t0:.1f} s)")
    if args.no_ai:
        return 0
    try:
        check_ollama_model(args.url, args.model)
    except (OllamaError, ValueError) as exc:
        print(f"local AI not available ({exc}); the engine analysis is saved, explanations will be generated live")
        return 1
    store = cache.AiCache(args.logs.resolve())
    todo = [i for i in sorted(snap.incidents, key=lambda i: -int(i.get("score", 0)))
            if args.only == "all" or i.get("priority") == args.only]
    done = failed = reused = 0
    for n, inc in enumerate(todo, 1):
        iid = str(inc.get("id"))
        payload, refs = cache.ai_payload(inc, snap)
        fp = cache.ai_fingerprint(payload, args.model)
        if store.get(fp) and not args.force:
            reused += 1
            print(f"[{n}/{len(todo)}] {iid} {inc.get('priority')}: already prepared")
            continue
        print(f"[{n}/{len(todo)}] {iid} {inc.get('priority')}: asking {args.model}… ", end="", flush=True)
        t = time.perf_counter()
        try:
            result = analyze_incident(payload, base_url=args.url, model=args.model, timeout=args.timeout, retries=1)
        except (AnalysisError, OllamaError, ValueError) as exc:
            failed += 1
            print(f"failed after {time.perf_counter() - t:.0f} s ({str(exc)[:120]})")
            continue
        store.put(fp, iid, args.model, result, refs, time.perf_counter() - t)
        done += 1
        print(f"done in {time.perf_counter() - t:.0f} s: {str(result.get('summary', ''))[:90]}")
    print(f"\n{done} explained, {reused} already prepared, {failed} failed · saved in {store.path} · "
          f"total {time.perf_counter() - t0:.0f} s")
    return 0 if not failed else 2


if __name__ == "__main__":
    sys.exit(main())
