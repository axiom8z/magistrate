"""Scores one run of the secret scanner over the sets from make_sets.py, and prints the tables.

    python -I -X utf8 bench/secrets/score.py <set folder> --expect-rules <hash> --date <YYYY-MM-DD>
        [--ledger eval/ledger.jsonl]

Reads s1.jsonl and s2.jsonl only for their hashes, IDs and marks, and never prints from them. The results
come from test/secretscore, as s1.results.jsonl and s2.results.jsonl in the same folder, and hold only
IDs, blocked or not, and rule IDs. Appends one line per set to the ledger, once: it refuses a set that
is already there.

A miss is a case the scanner let through. "Blocked" includes a scan that stopped over budget, because
that also blocks the call, and the tables show those apart. Cases the set marks as expected misses
stay out of recall. Every percentage and rate is cut, never rounded, so nothing here is rounded up.
The failure lines are checked on exact counts.
"""
import argparse
import collections
import hashlib
import json
import math
import pathlib
import sys

Z = 1.959963984540054  # two-sided 95%
OVER_BUDGET = "scan-over-budget"
ENCODINGS = ("plain", "percent", "base64", "hex", "nested", "split")


def wilson(k, n):
    if n == 0:
        return 0.0, 0.0
    p = k / n
    d = 1 + Z * Z / n
    c = p + Z * Z / (2 * n)
    h = Z * math.sqrt(p * (1 - p) / n + Z * Z / (4 * n * n))
    low = 0.0 if k == 0 else max(0.0, (c - h) / d)
    high = 1.0 if k == n else min(1.0, (c + h) / d)
    return low, high


def cut(value, places):
    # The tiny addition only undoes floating-point noise, as in 2899.9999999999995.
    scale = 10**places
    return f"{math.floor(value * scale + 1e-9) / scale:.{places}f}"


def pct(k, n):
    # Exact integer division: 99.996% prints as 99.99 and not as 100.00.
    if n == 0:
        return "-"
    whole = k * 10000 // n
    return f"{whole // 100}.{whole % 100:02d}"


def per_1000(k, n):
    if n == 0:
        return "-"
    whole = k * 1000 * 10000 // n
    return f"{whole // 10000}.{whole % 10000:04d}"


def table(title, header, rows):
    print(title)
    rows = [[str(cell) for cell in row] for row in rows]
    widths = [max([len(header[i])] + [len(row[i]) for row in rows]) for i in range(len(header))]

    def line(cells):
        parts = [c.ljust(w) if i == 0 else c.rjust(w) for i, (c, w) in enumerate(zip(cells, widths))]
        return "  ".join(parts).rstrip()

    print(line(header))
    for row in rows:
        print(line(row))
    print()


def listing(title, ids):
    print(f"{title}: {len(ids)}")
    for case_id in ids:
        print(f"  {case_id}")
    print()


class Tally:
    """Counts for one group of counted S1 cases."""

    def __init__(self):
        self.cases = self.blocked = self.own_rule = self.other_rule = self.over_budget = 0

    def add(self, case):
        self.cases += 1
        if not case["blocked"]:
            return
        self.blocked += 1
        if case["rule"] == OVER_BUDGET:
            self.over_budget += 1
        elif case["rule"] == case["expected"]:
            self.own_rule += 1
        else:
            self.other_rule += 1

    def row(self, name):
        low, high = wilson(self.blocked, self.cases)
        return [
            name, self.cases, self.blocked, pct(self.blocked, self.cases),
            cut(low * 100, 2), cut(high * 100, 2),
            self.own_rule, self.other_rule, self.over_budget, self.cases - self.blocked,
        ]

    def under_95(self):
        return self.blocked * 100 < 95 * self.cases


def tally_table(title, label, groups):
    header = [
        label, "cases", "blocked", "recall%", "wilson95 low%", "high%",
        "by own rule", "by other rule", "over budget", "missed",
    ]
    table(title, header, [tally.row(name) for name, tally in groups])


def read_marks(path):
    # The IDs in order, and which ones the set marks as expected misses. Values are dropped here.
    ids, expected_misses = [], set()
    with open(path, encoding="utf-8") as lines:
        for line in lines:
            case = json.loads(line)
            ids.append(case["id"])
            if case.get("expected_miss"):
                expected_misses.add(case["id"])
    return ids, expected_misses


def read_results(path, ids):
    with open(path, encoding="utf-8") as lines:
        rules_hash = json.loads(next(lines))["rules_hash"]
        results = []
        for line in lines:
            result = json.loads(line)
            if set(result) != {"id", "blocked", "rule"} or result["blocked"] != bool(result["rule"]):
                sys.exit(f"{path.name}: a result line has the wrong shape")
            results.append(result)
    if [result["id"] for result in results] != ids:
        sys.exit(f"{path.name}: the results do not line up with the set, case by case")
    return rules_hash, results


def score_s1(results, marked, manifest):
    counted, expected_misses = [], []
    for result in results:
        _, rule, variant, instance, encoding, form = result["id"].split("/")
        case = result | {"expected": rule, "variant": variant, "encoding": encoding, "form": form}
        (expected_misses if result["id"] in marked else counted).append(case)

    overall = Tally()
    per_encoding = {name: Tally() for name in ENCODINGS}
    per_rule = {name: Tally() for name in manifest["rules"]}
    per_pair = collections.defaultdict(Tally)
    per_form = collections.defaultdict(Tally)
    per_variant = collections.defaultdict(Tally)
    crossfire = collections.Counter()
    miss_groups = collections.Counter()
    for case in counted:
        variant_name, form_name = f'{case["expected"]}/{case["variant"]}', f'{case["encoding"]}/{case["form"]}'
        overall.add(case)
        per_encoding[case["encoding"]].add(case)
        per_rule[case["expected"]].add(case)
        per_pair[(case["expected"], case["encoding"])].add(case)
        per_form[form_name].add(case)
        per_variant[variant_name].add(case)
        if case["blocked"] and case["rule"] not in (case["expected"], OVER_BUDGET):
            crossfire[(case["expected"], case["rule"])] += 1
        if not case["blocked"]:
            miss_groups[(variant_name, form_name)] += 1

    misses = [case["id"] for case in counted if not case["blocked"]]
    caught_anyway = [f'{case["id"]} {case["rule"]}' for case in expected_misses if case["blocked"]]
    low, high = wilson(overall.blocked, overall.cases)
    total = overall.cases

    print("S1, SELF-WRITTEN FAKES")
    print(
        f"recall {overall.blocked}/{total} = {pct(overall.blocked, total)}%, "
        f"Wilson 95% {cut(low * 100, 2)}-{cut(high * 100, 2)}%"
    )
    print(f"blocked by the rule for that format: {overall.own_rule}/{total} = {pct(overall.own_rule, total)}%")
    print(
        f"blocked by another rule: {overall.other_rule}; "
        f"blocked because the scan stopped over budget: {overall.over_budget}; missed: {len(misses)}"
    )
    print(
        f"expected misses, left out of recall: {len(expected_misses)}; "
        f"of those blocked anyway: {len(caught_anyway)}"
    )
    print("Wilson intervals treat every case as independent. Cases share fakes and formats, so the real")
    print("uncertainty is wider.")
    print()

    tally_table("Per encoding", "encoding", [(name, per_encoding[name]) for name in ENCODINGS])
    tally_table("Per rule", "rule", [(name, per_rule[name]) for name in manifest["rules"]])
    tally_table(
        "Per rule and encoding",
        "rule/encoding",
        [(f"{rule}/{name}", per_pair[(rule, name)]) for rule in manifest["rules"] for name in ENCODINGS],
    )
    tally_table("Per form", "encoding/form", sorted(per_form.items()))
    tally_table(
        "Per format variant",
        "rule/variant",
        [
            (f"{rule}/{variant}", per_variant[f"{rule}/{variant}"])
            for rule in manifest["rules"]
            for variant in manifest["variants"][rule]
        ],
    )
    table(
        "Blocked by a rule other than the one for that format",
        ["format's rule", "rule that fired", "cases"],
        [[own, other, count] for (own, other), count in sorted(crossfire.items())],
    )

    per_class = collections.defaultdict(lambda: [0, 0])
    for case in expected_misses:
        entry = per_class[f'{case["encoding"]}/{case["form"]}']
        entry[0] += 1
        entry[1] += 1 if case["blocked"] else 0
    table(
        "Expected misses",
        ["encoding/form", "cases", "blocked anyway"],
        [[name, cases, blocked] for name, (cases, blocked) in sorted(per_class.items())],
    )
    listing("Expected misses that were blocked anyway, with the rule", caught_anyway)
    table(
        "Misses, grouped by format variant and form",
        ["rule/variant", "encoding/form", "missed"],
        [[variant, form, count] for (variant, form), count in sorted(miss_groups.items())],
    )
    listing("Every miss, by case ID", misses)

    return {
        "cases": len(results),
        "counted": total,
        "blocked": overall.blocked,
        "recall_pct": pct(overall.blocked, total),
        "wilson95_pct": [cut(low * 100, 2), cut(high * 100, 2)],
        "by_own_rule": overall.own_rule,
        "by_other_rule": overall.other_rule,
        "over_budget": overall.over_budget,
        "missed": len(misses),
        "expected_misses": len(expected_misses),
        "expected_misses_blocked": len(caught_anyway),
        "failure_line": "known-format recall under 95%",
        "crossed": overall.blocked * 100 < 95 * total,
    }, {
        "rules": [name for name, tally in per_rule.items() if tally.under_95()],
        "encodings": [name for name, tally in per_encoding.items() if tally.under_95()],
    }


def rate_cells(k, n):
    if k == 0:
        return per_1000(0, n), "0", "at most " + per_1000(3, n) + " (3/n)"
    low, high = wilson(k, n)
    return per_1000(k, n), cut(low * 1000, 4), cut(high * 1000, 4)


def score_s2(results, manifest):
    per_class = collections.defaultdict(lambda: [0, 0, 0])
    per_rule = collections.Counter()
    hits = []
    for result in results:
        name = result["id"].split("/")[1]
        entry = per_class[name]
        entry[0] += 1
        if result["blocked"]:
            entry[1] += 1
            entry[2] += 1 if result["rule"] == OVER_BUDGET else 0
            per_rule[result["rule"]] += 1
            hits.append(f'{result["id"]} {result["rule"]}')
    total = len(results)
    over_budget = per_rule[OVER_BUDGET]
    rate, low, high = rate_cells(len(hits), total)

    print("S2, SELF-WRITTEN LOOK-ALIKES")
    if hits:
        print(f"false hits {len(hits)}/{total} = {rate} per 1,000 strings, Wilson 95% {low}-{high} per 1,000")
    else:
        print(f"false hits 0/{total}: {high} per 1,000 strings")
    print(f"of those, stopped over budget: {over_budget}")
    print("The mix of classes is a choice made when writing the set, so this is a stress rate and not a")
    print("rate on real traffic.")
    print()

    rows = []
    for name in manifest["s2_classes"]:
        strings, class_hits, class_over = per_class[name]
        class_rate, class_low, class_high = rate_cells(class_hits, strings)
        rows.append([name, strings, class_hits, class_over, class_rate, class_low, class_high])
    table(
        "Per class",
        ["class", "strings", "false hits", "over budget", "per 1,000", "wilson95 low", "high"],
        rows,
    )
    table(
        "Per rule that fired",
        ["rule", "false hits"],
        [[rule, count] for rule, count in sorted(per_rule.items()) if count],
    )
    listing("Every false hit, by case ID, with the rule", hits)

    low_value, high_value = wilson(len(hits), total)
    return {
        "strings": total,
        "false_hits": len(hits),
        "over_budget": over_budget,
        "per_1000": rate,
        "wilson95_per_1000": [cut(low_value * 1000, 4), cut(high_value * 1000, 4)] if hits else None,
        "at_most_per_1000": None if hits else per_1000(3, total),
        "failure_line": "over 1 false hit per 1,000 strings",
        "crossed": len(hits) * 1000 > total,
    }


def append_ledger(path, entries):
    # Append-only: a set scored once stays scored once.
    path.parent.mkdir(parents=True, exist_ok=True)
    known = set()
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            known.add(json.loads(line)["set_hash"])
    if any(entry["set_hash"] in known for entry in entries):
        sys.exit("the ledger already holds one of these sets, so nothing was appended")
    with open(path, "a", encoding="utf-8", newline="\n") as ledger:
        for entry in entries:
            ledger.write(json.dumps(entry, separators=(",", ":")) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Score one run of the secret scanner.")
    parser.add_argument("folder", type=pathlib.Path)
    parser.add_argument("--expect-rules", required=True, help="the published rule-table hash")
    parser.add_argument("--date", required=True)
    parser.add_argument("--ledger", type=pathlib.Path, help="append the headline numbers here")
    args = parser.parse_args()
    sys.stdout.reconfigure(newline="\n")

    manifest = json.loads((args.folder / "manifest.json").read_text(encoding="utf-8"))
    results, marks = {}, {}
    for name, entry in manifest["sets"].items():
        path = args.folder / entry["file"]
        if hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
            sys.exit(f"{entry['file']} does not match the hash in the manifest")
        ids, marks[name] = read_marks(path)
        rules_hash, results[name] = read_results(args.folder / f"{name}.results.jsonl", ids)
        if rules_hash != args.expect_rules:
            sys.exit(f"{name} was scanned with other rules, so it says nothing about the frozen table")

    print("Magistrate secret scanner, scored once")
    print(f"date                {args.date}")
    print(f"rule-table hash     {args.expect_rules}")
    print(f"generator hash      {manifest['generator_sha256']}")
    print(f"generator seed      {manifest['seed']}")
    print(f"S1 hash             {manifest['sets']['s1']['sha256']}")
    print(f"S2 hash             {manifest['sets']['s2']['sha256']}")
    print("Percentages and rates are cut, never rounded. The failure lines are checked on exact counts.")
    print()

    s1, under = score_s1(results["s1"], marks["s1"], manifest)
    s2 = score_s2(results["s2"], manifest)

    def state(crossed):
        return "CROSSED" if crossed else "not crossed"

    print("FAILURE LINES")
    print(
        f"known-format recall under 95%: {state(s1['crossed'])}, "
        f"recall {s1['blocked']}/{s1['counted']} = {s1['recall_pct']}%, "
        f"Wilson 95% {s1['wilson95_pct'][0]}-{s1['wilson95_pct'][1]}%"
    )
    print(f"rules under 95% taken alone: {', '.join(under['rules']) or 'none'}")
    print(f"encodings under 95% taken alone: {', '.join(under['encodings']) or 'none'}")
    print(
        f"over 1 false hit per 1,000 strings: {state(s2['crossed'])}, "
        f"{s2['false_hits']}/{s2['strings']} = {s2['per_1000']} per 1,000"
    )

    if args.ledger:
        common = {
            "date": args.date,
            "rules_hash": args.expect_rules,
            "generator_hash": manifest["generator_sha256"],
            "seed": manifest["seed"],
        }
        append_ledger(args.ledger, [
            {"set": "S1", **common, "set_hash": manifest["sets"]["s1"]["sha256"], "headline": s1},
            {"set": "S2", **common, "set_hash": manifest["sets"]["s2"]["sha256"], "headline": s2},
        ])


if __name__ == "__main__":
    main()
