"""Check measured UPnP production coverage, excluding tests and other modules."""
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = {"src/easyp2p/portmap.rs", "src/easyp2p/portmap/desktop.rs",
            "src/easyp2p/portmap/android.rs"}
files = {}
for dataset in report["data"]:
    for entry in dataset["files"]:
        filename = entry["filename"].replace(chr(92), "/")
        for suffix in expected:
            if filename.endswith("/" + suffix):
                files[suffix] = entry["summary"]
if files.keys() != expected:
    raise SystemExit("Missing UPnP coverage sources")
if not files["src/easyp2p/portmap/desktop.rs"]["branches"]["count"]:
    raise SystemExit("No branch instrumentation: line coverage is insufficient")

minimum = 90.0
passed = True
totals = {}
for metric in ("lines", "branches", "functions"):
    count = sum(item[metric]["count"] for item in files.values())
    covered = sum(item[metric]["covered"] for item in files.values())
    totals[metric] = {"count": count, "covered": covered,
                      "percent": 100.0 * covered / count if count else None}
for filename, summary in sorted(files.items()):
    for metric in ("lines", "branches"):
        data = summary[metric]
        if data["count"]:
            passed &= data["percent"] >= minimum
            print(f"{filename}: {metric} {data['covered']}/{data['count']} "
                  f"({data['percent']:.2f}%)")

result = {"scope": "UPnP production sources only; tests and other modules excluded",
          "minimum_per_file_percent": minimum,
          "enforced_metrics": ["lines", "branches"], "passed": passed,
          "totals": totals, "files": files}
Path(sys.argv[2]).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
if not passed:
    raise SystemExit("UPnP line or branch coverage is below 90%")
