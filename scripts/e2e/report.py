import argparse
import json
import sys
from collections import Counter, defaultdict


def load(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    counts = defaultdict(Counter)
    failing = defaultdict(set)
    for rec in data:
        check = rec["metadata"]["event_code"]
        status = rec["status_code"]
        counts[check][status] += 1
        if status == "FAIL":
            res = rec["resources"][0]
            failing[check].add(res.get("name") or res.get("uid"))
    return counts, failing


def cell(counts, check):
    c = counts.get(check, Counter())
    return "%d / %d" % (c["FAIL"], c["PASS"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--checks", required=True)
    ap.add_argument("--before", required=True)
    ap.add_argument("--templates", required=True)
    ap.add_argument("--final", required=True)
    ap.add_argument("--mapping", required=True)
    ap.add_argument("--not-seedable", default="")
    ap.add_argument("--note", action="append", default=[])
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    with open(args.checks, encoding="utf-8") as fh:
        checks = [x.strip() for x in fh if x.strip()]
    skip = {x for x in args.not_seedable.split(",") if x}
    notes = dict(n.split("=", 1) for n in args.note)

    before, _ = load(args.before)
    mid, mid_failing = load(args.templates)
    final, final_failing = load(args.final)

    with open(args.mapping, encoding="utf-8") as fh:
        mapping_rows = [ln for ln in fh if ln.startswith("| prowler |")]
    status_of = defaultdict(set)
    for ln in mapping_rows:
        cols = [c.strip() for c in ln.strip().strip("|").split("|")]
        status_of[cols[1]].add(cols[5])

    lines = [
        "| Check | Fix path | FAIL / PASS before | after terraform apply | after follow-up | Result |",
        "|---|---|---|---|---|---|",
    ]
    errors = []
    for check in checks:
        st = status_of.get(check, set())
        if "remediated" in st:
            path = "template"
        elif "guidance only" in st:
            path = "guidance"
        elif check in skip:
            path = "n/a"
        else:
            path = "none"
        b_fail = before.get(check, Counter())["FAIL"]
        f_fail = final.get(check, Counter())["FAIL"]
        if check in skip:
            result = "not seedable"
        else:
            if b_fail == 0:
                errors.append("%s: no FAIL before, the seed did not create a bad resource" % check)
            if f_fail != 0:
                errors.append("%s: %d FAIL left after the fix: %s" % (check, f_fail, sorted(final_failing[check])))
            if "no mapping" in st or not st:
                errors.append("%s: remediate produced no mapped row" % check)
            result = "fixed" if (b_fail > 0 and f_fail == 0) else "NOT FIXED"
            if check in notes:
                result += " (" + notes[check] + ")"
        lines.append("| %s | %s | %s | %s | %s | %s |" % (check, path, cell(before, check), cell(mid, check), cell(final, check), result))

    text = "\n".join(lines) + "\n"
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(text)
    if errors:
        print("E2E ASSERTIONS FAILED:", file=sys.stderr)
        for e in errors:
            print("  - " + e, file=sys.stderr)
        sys.exit(1)
    print("E2E ASSERTIONS PASSED")


if __name__ == "__main__":
    main()
