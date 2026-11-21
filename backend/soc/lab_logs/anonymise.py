"""Make a real lab log safe to commit: replace account names and machine-specific Windows SIDs.

    python backend/soc/lab_logs/anonymise.py <raw file> <output file> --rename RealName=lab-user [--rename X=Y ...]

- every --rename is applied to the whole line, case-insensitive (names in fields, paths, messages)
- domain SIDs S-1-5-21-<a>-<b>-<c>-<rid> become S-1-5-21-0-0-0-<rid> (the account number is kept, the machine id is not)
- well-known SIDs (S-1-5-18 SYSTEM, -19, -20, ...) are left as they are
Pass the real names on the command line only, so they never end up in the repository. The raw file stays local.
"""
import argparse
import re
import sys
from pathlib import Path

DOMAIN_SID = re.compile(r"S-1-5-21-\d+-\d+-\d+-(\d+)")


def anonymise(text: str, renames: list[tuple[str, str]]) -> str:
    for old, new in renames:
        text = re.sub(re.escape(old), new, text, flags=re.IGNORECASE)
    return DOMAIN_SID.sub(r"S-1-5-21-0-0-0-\1", text)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("raw", type=Path)
    ap.add_argument("out", type=Path)
    ap.add_argument("--rename", action="append", default=[], metavar="OLD=NEW")
    args = ap.parse_args(argv)
    renames = [tuple(r.split("=", 1)) for r in args.rename]
    if any(len(r) != 2 or not r[0] for r in renames):
        ap.error("--rename needs OLD=NEW")
    text = anonymise(args.raw.read_text(encoding="utf-8-sig"), renames)
    left = [old for old, _ in renames if old.lower() in text.lower()]
    if left:
        print(f"still present: {left}", file=sys.stderr)
        return 1
    args.out.write_text(text, encoding="utf-8", newline="\n")
    print(f"{args.out}: {len(text.splitlines()):,} lines, {len(renames)} name(s) replaced, domain SIDs masked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
