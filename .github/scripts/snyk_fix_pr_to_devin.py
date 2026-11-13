"""
Scanner findings → Devin Security, in two modes.

Snyk fix PR (default), when Snyk opens a fix pull request:
1. scan the code the PR targets with two tools, Snyk and OSV-Scanner, and
   upload their reports to Devin,
2. start a Devin Security ingestion scan with them, so the findings land on
   the Security screen, triaged and deduplicated across both tools,
3. remediate the open findings (any severity) about the packages Snyk's PR
   changes, with Snyk's branch as the base: Devin's fixes finish Snyk's upgrade.

Backlog (BACKLOG=true): scan every npm and Python manifest in the repo and
ingest the reports as one Devin Security scan. npm manifests get Snyk and
OSV-Scanner; Python manifests get OSV-Scanner only, because Snyk would have to
install every pinned package to resolve them. Nothing is remediated
automatically: pick findings on the Security screen and use Fix with Devin.

Environment: GH_TOKEN, SNYK_TOKEN, DEVIN_V3_API_KEY, DEVIN_ORG_ID,
DEVIN_INGEST_PROFILE_ID, REPO, PR_NUMBER, BACKLOG, DRY_RUN, MAX_REMEDIATIONS.
"""

import json
import os
import re
import subprocess
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

DEVIN_API = "https://api.devin.ai/v3/organizations"
# Absolute, because Snyk runs in scratch directories and writes reports here
REPORTS = Path("scanner-reports").resolve()
TERMINAL = {"completed", "failed", "cancelled"}
POLL_SECONDS, POLL_LIMIT_SECONDS = 30, 45 * 60
# Fields written for humans. Dropping them keeps reports small enough to
# upload; Devin can look any advisory up by its ID.
VERBOSE_KEYS = {"details", "description", "references", "credits", "versions"}


def run(cmd: list[str], cwd: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


# ── Pull request ──────────────────────────────────────────────

def pull_request(repo: str, number: str) -> dict:
    fields = "number,title,url,headRefName,baseRefOid,headRefOid"
    result = run(["gh", "pr", "view", number, "--repo", repo, "--json", fields])
    if result.returncode != 0:
        raise RuntimeError(f"Could not read PR #{number}: {result.stderr}")
    return json.loads(result.stdout)


def manifest_at(rev: str, path: str) -> dict:
    shown = run(["git", "show", f"{rev}:{path}"])
    return json.loads(shown.stdout) if shown.returncode == 0 else {}


def changed_packages(pr: dict) -> dict[str, list[str]]:
    """Per manifest, the dependencies whose version the PR changes."""
    diff = run(["git", "diff", "--name-only", pr["baseRefOid"], pr["headRefOid"], "--", "**/package.json"])
    changes = {}
    for manifest in (p for p in diff.stdout.split() if p.endswith("package.json")):
        before, after = manifest_at(pr["baseRefOid"], manifest), manifest_at(pr["headRefOid"], manifest)
        deps = lambda m: {**m.get("dependencies", {}), **m.get("devDependencies", {})}
        changes[manifest] = sorted(name for name, version in deps(after).items() if deps(before).get(name) != version)
    return changes


def backlog_manifests(rev: str) -> tuple[list[str], list[str]]:
    """npm and Python manifests in the repo. The root package.json is skipped:
    it only declares the npm workspaces and dev tooling."""
    files = run(["git", "ls-tree", "-r", "--full-tree", "--name-only", rev]).stdout.split()
    npm = [f for f in files if f.endswith("/package.json")]
    python = [f for f in files if re.search(r"(^|/)requirements[^/]*\.txt$", f)]
    return npm, python


# ── Scanners: Snyk and OSV-Scanner ────────────────────────────

def mirror(rev: str, manifest: str) -> Path:
    """Copy a manifest as it was at a commit into a scratch directory and
    return that directory. Each manifest is resolved on its own: the repo root
    declares npm workspaces, which would otherwise move the lockfile to the
    root. The repo-relative path keeps report locations relative to the repo."""
    workdir = Path(f"/tmp/scan-{rev[:7]}")
    target = workdir / manifest
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(run(["git", "show", f"{rev}:{manifest}"]).stdout)
    return workdir


def report_stem(manifest: str) -> Path:
    REPORTS.mkdir(exist_ok=True)
    return REPORTS / manifest.replace("/", "_").rsplit(".", 1)[0]


def compact(report: Path) -> None:
    def strip(node):
        if isinstance(node, dict):
            return {k: strip(v) for k, v in node.items() if k not in VERBOSE_KEYS}
        return [strip(v) for v in node] if isinstance(node, list) else node
    report.write_text(json.dumps(strip(json.loads(report.read_text())), indent=1))


def npm_reports(rev: str, manifest: str) -> list[Path]:
    """Snyk (JSON, SARIF) and OSV-Scanner (JSON) reports for an npm manifest."""
    workdir = mirror(rev, manifest)
    lock = run(["npm", "install", "--package-lock-only", "--ignore-scripts",
                "--legacy-peer-deps", "--no-audit", "--no-fund"], cwd=str((workdir / manifest).parent))
    if lock.returncode != 0:
        raise RuntimeError(f"npm could not resolve {manifest}: {lock.stderr[-500:]}")
    lockfile = str(Path(manifest).parent / "package-lock.json")
    stem = report_stem(manifest)
    snyk_json, snyk_sarif = Path(f"{stem}.snyk.json"), Path(f"{stem}.snyk.sarif")
    # One Snyk test writes both formats, so each manifest costs one test
    scan = run(["snyk", "test", f"--file={lockfile}", "--severity-threshold=low",
                f"--json-file-output={snyk_json}", f"--sarif-file-output={snyk_sarif}"], cwd=str(workdir))
    if scan.returncode not in (0, 1) or not snyk_json.exists():  # 0 = clean, 1 = issues found
        raise RuntimeError(f"Snyk failed on {manifest}: {scan.stdout[-500:]}{scan.stderr[-500:]}")
    compact(snyk_json)
    return [snyk_json, snyk_sarif, osv_report(workdir / lockfile, Path(f"{stem}.osv.json"))]


def python_reports(rev: str, manifest: str) -> list[Path]:
    """OSV-Scanner (JSON) report for a Python requirements file."""
    workdir = mirror(rev, manifest)
    return [osv_report(workdir / manifest, Path(f"{report_stem(manifest)}.osv.json"), "requirements.txt")]


def osv_report(lockfile: Path, out: Path, parse_as: str | None = None) -> Path:
    """OSV-Scanner findings for runtime dependencies only. Snyk skips
    devDependencies by default, so both tools cover the same scope."""
    target = f"{parse_as}:{lockfile}" if parse_as else str(lockfile)
    scan = run(["osv-scanner", "scan", "source", "--lockfile", target, "--format", "json"])
    if scan.returncode not in (0, 1, 128):  # 0 = clean, 1 = vulnerabilities found, 128 = no packages
        raise RuntimeError(f"OSV-Scanner failed on {lockfile}: {scan.stderr[-500:]}")
    report = json.loads(scan.stdout) if scan.returncode != 128 else {"results": []}
    for result in report.get("results", []):
        result["packages"] = [p for p in result.get("packages", []) if p.get("dependency_groups") != ["dev"]]
    out.write_text(json.dumps(report))
    compact(out)
    return out


def advisories(report: Path) -> int:
    data = json.loads(report.read_text())
    if report.name.endswith(".snyk.json"):
        return len({v["id"] for v in data.get("vulnerabilities", [])})
    return sum(len(p.get("vulnerabilities", [])) for r in data.get("results", []) for p in r.get("packages", []))


def snyk_counts(json_report: Path) -> str:
    issues = {v["id"]: v for v in json.loads(json_report.read_text()).get("vulnerabilities", [])}.values()
    counts = {s: sum(1 for i in issues if i["severity"] == s) for s in ("critical", "high", "medium", "low")}
    return ", ".join(f"{n} {s}" for s, n in counts.items() if n) or "no issues"


def osv_counts(json_report: Path) -> str:
    packages = [p for r in json.loads(json_report.read_text()).get("results", []) for p in r.get("packages", [])]
    names = ", ".join(sorted(f"{p['package']['name']}@{p['package']['version']}" for p in packages))
    return f"{advisories(json_report)} advisories in {len(packages)} packages ({names})" if packages else "no issues"


def scan_lines(manifest: str, reports: list[Path]) -> list[str]:
    lines = [f"- `{manifest}`"]
    for report in reports:
        if report.name.endswith(".snyk.json"):
            lines.append(f"  - Snyk: {snyk_counts(report)}")
        elif report.name.endswith(".osv.json"):
            lines.append(f"  - OSV-Scanner: {osv_counts(report)}")
    return lines


INGESTION_NOTES = """# How to read these reports

The reports attached to this scan come from two scanners run by CI:

- Snyk Open Source: `*.snyk.json` and `*.snyk.sarif` (npm manifests)
- OSV-Scanner: `*.osv.json` (npm and Python manifests; runtime dependencies
  only, like Snyk)

The file name encodes the manifest, e.g. `packages_frontend_package.snyk.json`
is `packages/frontend/package.json`. Long descriptions, references and
affected-version lists were removed to keep the reports small; look advisories
up by their ID.

Deduplicate across tools and manifests: the same package and version with the
same CVE or GHSA ID is one finding, whichever tools and files report it. On
each finding, say which tools reported it and list every manifest it appears
in.
"""


def ingestion_notes() -> Path:
    path = REPORTS / "README-ingestion.md"
    path.write_text(INGESTION_NOTES)
    return path


# ── Devin Security (v3 API) ───────────────────────────────────

def devin(method: str, path: str, body: dict | None = None, raw: bytes | None = None,
          content_type: str = "application/json") -> dict:
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    request = urllib.request.Request(
        f"{DEVIN_API}/{os.environ['DEVIN_ORG_ID']}{path}", method=method, data=data,
        headers={"Authorization": f"Bearer {os.environ['DEVIN_V3_API_KEY']}", "Content-Type": content_type},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"Devin API {method} {path} → {error.code}: {error.read().decode()[:500]}") from error


def upload(report: Path) -> str:
    boundary = uuid.uuid4().hex
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{report.name}\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n").encode() + report.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
    return devin("POST", "/attachments", raw=body, content_type=f"multipart/form-data; boundary={boundary}")["url"]


def start_ingestion(repo: str, reports: list[Path]) -> str:
    scan = devin("POST", "/code-scans/ingestion", {
        "profile_id": os.environ["DEVIN_INGEST_PROFILE_ID"],
        "repo_name": repo,
        "attachment_urls": [upload(r) for r in [ingestion_notes(), *reports]],
    })
    return scan["scan_id"]


def wait_for(scan_id: str, repo: str) -> str:
    waited = 0
    while waited < POLL_LIMIT_SECONDS:
        scans = devin("GET", f"/code-scans/scans?first=50&repo_name={urllib.parse.quote(repo)}").get("items", [])
        status = next((s["status"] for s in scans if s["scan_id"] == scan_id), "unknown")
        print(f"  scan {scan_id}: {status}", flush=True)
        if status in TERMINAL:
            return status
        time.sleep(POLL_SECONDS)
        waited += POLL_SECONDS
    return "timed out"


def open_findings(scan_id: str) -> list[dict]:
    """Every open finding, at any severity: triage may lower Snyk's severity
    (e.g. when the vulnerable code isn't reachable), and the package Snyk's
    PR targets should still be finished."""
    query = urllib.parse.urlencode({"scan_id": scan_id, "status": "open", "first": 100})
    return devin("GET", f"/code-scans/findings?{query}").get("items", [])


def about(finding: dict, packages: set[str]) -> bool:
    text = f"{finding.get('title', '')} {finding.get('description', '')}".lower()
    return any(package.lower() in text for package in packages)


def remediate(finding: dict, branch: str) -> str:
    return devin("POST", f"/code-scans/findings/{finding['finding_id']}/remediate", {"branch": branch})["session_id"]


# ── Modes ─────────────────────────────────────────────────────

def write_summary(lines: list[str]) -> None:
    text = "\n".join(lines)
    print(text)
    if (summary := os.environ.get("GITHUB_STEP_SUMMARY")):
        with open(summary, "a") as f:
            f.write(text + "\n")


def dry_run() -> bool:
    return os.environ.get("DRY_RUN") == "true"


def ingest_and_fix_snyk_pr(repo: str, number: str) -> None:
    pr = pull_request(repo, number)
    changes = changed_packages(pr)
    packages = {name for names in changes.values() for name in names}
    summary = [f"## Snyk fix PR → Devin Security: [#{number}]({pr['url']}) {pr['title']}",
               f"Packages Snyk's PR changes: {', '.join(sorted(packages)) or 'none'}", ""]
    reports = []
    for manifest in changes:
        found = npm_reports(pr["baseRefOid"], manifest)
        reports += found
        summary += scan_lines(f"{manifest}` at `{pr['baseRefOid'][:7]}", found)
    if not reports or dry_run():
        write_summary(summary + ["", "Dry run or nothing to scan: nothing sent to Devin."])
        return

    scan_id = start_ingestion(repo, reports)
    summary += ["", f"**Devin Security ingestion scan:** `{scan_id}`"]
    status = wait_for(scan_id, repo)
    summary.append(f"Scan status: {status}")
    if status != "completed":
        write_summary(summary)
        raise SystemExit(1)

    findings = open_findings(scan_id)
    # Only the packages Snyk's PR changes: other findings stay in Devin
    # Security for triage and bulk assignment, not on Snyk's branch.
    targeted = [f for f in findings if about(f, packages)]
    cap = int(os.environ.get("MAX_REMEDIATIONS", "3"))
    summary += ["", f"{len(findings)} open findings; {len(targeted)} about {', '.join(sorted(packages))}; "
                    f"remediating {min(len(targeted), cap)} against `{pr['headRefName']}`.", "",
                "| Severity | Finding | Devin session |", "|---|---|---|"]
    for finding in targeted[:cap]:
        session = remediate(finding, pr["headRefName"])
        summary.append(f"| {finding['severity']} | {finding['title']} | https://app.devin.ai/sessions/{session.removeprefix('devin-')} |")
    write_summary(summary)


def ingest_backlog(repo: str) -> None:
    rev = run(["git", "rev-parse", "HEAD"]).stdout.strip()
    npm, python = backlog_manifests(rev)
    summary = [f"## Backlog → Devin Security: `{repo}` at {rev[:7]}", ""]
    reports = []
    for manifest, scan in [*((m, npm_reports) for m in npm), *((m, python_reports) for m in python)]:
        try:
            found = scan(rev, manifest)
        except RuntimeError as error:  # one unresolvable manifest shouldn't sink the backlog
            summary.append(f"- `{manifest}`: skipped. {error}")
            continue
        reports += found
        summary += scan_lines(manifest, found)
    total = sum(advisories(r) for r in reports if r.suffix == ".json")
    size_kb = sum(r.stat().st_size for r in reports) // 1024
    summary += ["", f"**{total} advisories** across {len(npm) + len(python)} manifests and two scanners; "
                    f"{len(reports)} reports, {size_kb} KB."]
    if not reports or dry_run():
        write_summary(summary + ["", "Dry run or nothing to scan: nothing sent to Devin."])
        return
    scan_id = start_ingestion(repo, reports)
    write_summary(summary + ["", f"**Devin Security ingestion scan:** `{scan_id}`. Triage continues in Devin: "
                                 "pick findings on the Security screen and use Fix with Devin."])


def main() -> None:
    repo = os.environ["REPO"]
    if os.environ.get("BACKLOG") == "true":
        ingest_backlog(repo)
    elif os.environ.get("PR_NUMBER"):
        ingest_and_fix_snyk_pr(repo, os.environ["PR_NUMBER"])
    else:
        raise SystemExit("Set PR_NUMBER (a Snyk fix PR) or BACKLOG=true.")


if __name__ == "__main__":
    main()
