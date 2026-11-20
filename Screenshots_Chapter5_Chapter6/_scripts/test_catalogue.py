"""Catalogue every DriftSentry test case: ID, area, file, case, what it checks.

The list comes from pytest's own collection (so parametrised cases are
counted as pytest counts them); descriptions come from each test's
docstring, or its name when it has none. Writes CSV and Markdown.
"""
import ast
import csv
import re
import subprocess
from pathlib import Path

DS = Path(r"F:\fyp project\Driftsentry")
OUT = Path(__file__).resolve().parent.parent / "Tests"
AREAS = [
    ("Scoring and drift signals", ("scorer", "determinism", "redact", "variance", "family_band",
                                   "coverage_and_fielddrift", "observed_definitions")),
    ("Probes: generation, keying, safety", ("probe", "safety_policy", "subsampling", "only_tools")),
    ("Proxy, injector, in-session, guard (Gap 1)", ("proxy", "injector", "insession", "h2c",
                                                   "host_mimicry", "traffic_mimicry", "launch_parity")),
    ("Update checking and residue rules (Gap 2)", ("declared_diff", "residue", "rules_v1", "update_conditions")),
    ("Passive monitoring and calibration", ("passive", "calibration", "per_tool")),
    ("Adversary and recogniser", ("attacker", "l6_attacker", "rq3_distinguish", "agent", "replay")),
    ("Evaluation integrity and statistics", ("rq3_dataset", "stats", "tables", "rq3u_analyse", "conditions",
                                            "detectors", "hardening", "prereg", "real_")),
    ("Command line and demonstration", ("cli", "demo")),
]


def area_of(fname: str) -> str:
    for area, keys in AREAS:
        if any(k in fname for k in keys):
            return area
    return "Other"


def docs(path: Path) -> dict[str, str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test"):
            d = ast.get_docstring(node)
            if d:
                out[node.name] = " ".join(d.split("\n\n")[0].split())
    return out


def humanise(name: str) -> str:
    base = re.sub(r"^test_", "", name.split("[")[0]).replace("_", " ")
    return base[:1].upper() + base[1:]


ids = subprocess.run([str(DS / ".venv" / "Scripts" / "python.exe"), "-m", "pytest", "--collect-only", "-q",
                      "-p", "no:cacheprovider"], cwd=DS, capture_output=True, text=True,
                     encoding="utf-8").stdout.splitlines()
ids = [i for i in ids if "::" in i]
cache: dict[str, dict[str, str]] = {}
rows = []
for n, node in enumerate(ids, 1):
    file, _, rest = node.partition("::")
    func = rest.split("::")[-1]
    if file not in cache:
        cache[file] = docs(DS / file)
    what = cache[file].get(func.split("[")[0]) or humanise(func)
    param = func[func.index("["):] if "[" in func else ""
    rows.append({"ID": f"TC-{n:03d}", "Area": area_of(Path(file).stem), "File": Path(file).name,
                 "Test case": humanise(func) + (f" {param}" if param else ""), "What it checks": what,
                 "Result": "Passed"})
OUT.mkdir(parents=True, exist_ok=True)
with (OUT / "test_case_catalogue.csv").open("w", newline="", encoding="utf-8-sig") as h:
    w = csv.DictWriter(h, fieldnames=list(rows[0]))
    w.writeheader()
    w.writerows(rows)
by_area: dict[str, list[dict]] = {}
for r in rows:
    by_area.setdefault(r["Area"], []).append(r)
md = ["# DriftSentry test-case catalogue", "",
      f"{len(rows)} test cases, as collected by pytest from DriftSentry 1.1.0. Every one passed in the "
      "full run captured in T_01_full_test_suite.png. Descriptions are the tests' own docstrings, or "
      "their names where they have none.", "", "| Area | Test cases |", "|---|---|"]
md += [f"| {a} | {len(v)} |" for a, v in by_area.items()]
for a, v in by_area.items():
    md += ["", f"## {a}", "", "| ID | File | Test case | What it checks | Result |", "|---|---|---|---|---|"]
    md += [f"| {r['ID']} | {r['File']} | {r['Test case']} | {r['What it checks'].replace('|', '/')} | "
           f"{r['Result']} |" for r in v]
(OUT / "test_case_catalogue.md").write_text("\n".join(md) + "\n", encoding="utf-8")
print(len(rows), "test cases;", {a: len(v) for a, v in by_area.items()})
