"""
Snyk fix PR → Devin Security.

When Snyk opens a fix pull request:
1. run Snyk on the code the PR targets and upload its JSON and SARIF reports
   to Devin,
2. start a Devin Security ingestion scan with them, so the findings land on
   the Security screen, triaged and deduplicated,
3. remediate the open high/critical findings about the packages Snyk's PR
   changes, with Snyk's branch as the base: Devin's fixes finish Snyk's upgrade.

Environment: GH_TOKEN, SNYK_TOKEN, DEVIN_V3_API_KEY, DEVIN_ORG_ID,
DEVIN_INGEST_PROFILE_ID, REPO, PR_NUMBER, DRY_RUN, MAX_REMEDIATIONS.
"""

import json
import os
import subprocess
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

DEVIN_API = "https://api.devin.ai/v3/organizations"
REPORTS = Path("snyk-reports")
TERMINAL = {"completed", "failed", "cancelled"}
POLL_SECONDS, POLL_LIMIT_SECONDS = 30, 45 * 60


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


# ── Snyk ──────────────────────────────────────────────────────

def snyk_reports(rev: str, manifest: str) -> list[Path]:
    """Snyk JSON and SARIF reports for a manifest as it was at a commit."""
    # Resolve the manifest on its own: the repo root declares npm workspaces,
    # which would otherwise move the lockfile to the root. The mirrored path
    # keeps report locations relative to the repo (packages/frontend/...).
    workdir = Path(f"/tmp/snyk-{rev[:7]}")
    package_dir = workdir / Path(manifest).parent
    package_dir.mkdir(parents=True, exist_ok=True)
    (package_dir / "package.json").write_text(run(["git", "show", f"{rev}:{manifest}"]).stdout)
    lock = run(["npm", "install", "--package-lock-only", "--ignore-scripts",
                "--legacy-peer-deps", "--no-audit", "--no-fund"], cwd=str(package_dir))
    if lock.returncode != 0:
        raise RuntimeError(f"npm could not resolve {manifest}: {lock.stderr[-500:]}")
    REPORTS.mkdir(exist_ok=True)
    stem = REPORTS / manifest.replace("/", "_").removesuffix(".json")
    lockfile = str(Path(manifest).parent / "package-lock.json")
    outputs = []
    for flag, suffix in (("--json", ".snyk.json"), ("--sarif", ".snyk.sarif")):
        scan = run(["snyk", "test", f"--file={lockfile}", "--severity-threshold=low", flag], cwd=str(workdir))
        if scan.returncode not in (0, 1):  # 0 = clean, 1 = issues found
            raise RuntimeError(f"Snyk failed on {manifest}: {scan.stdout[-500:]}{scan.stderr[-500:]}")
        path = Path(f"{stem}{suffix}")
        path.write_text(scan.stdout)
        outputs.append(path)
    return outputs


def snyk_counts(json_report: Path) -> str:
    issues = {v["id"]: v for v in json.loads(json_report.read_text()).get("vulnerabilities", [])}.values()
    counts = {s: sum(1 for i in issues if i["severity"] == s) for s in ("critical", "high", "medium", "low")}
    return ", ".join(f"{n} {s}" for s, n in counts.items() if n) or "no issues"


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


def start_ingestion(repo: str, attachment_urls: list[str]) -> str:
    scan = devin("POST", "/code-scans/ingestion", {
        "profile_id": os.environ["DEVIN_INGEST_PROFILE_ID"],
        "repo_name": repo,
        "attachment_urls": attachment_urls,
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
    findings = []
    for severity in ("critical", "high"):
        query = urllib.parse.urlencode({"scan_id": scan_id, "severity": severity, "status": "open", "first": 100})
        findings += devin("GET", f"/code-scans/findings?{query}").get("items", [])
    return findings


def about(finding: dict, packages: set[str]) -> bool:
    text = f"{finding.get('title', '')} {finding.get('description', '')}".lower()
    return any(package.lower() in text for package in packages)


def remediate(finding: dict, branch: str) -> str:
    return devin("POST", f"/code-scans/findings/{finding['finding_id']}/remediate", {"branch": branch})["session_id"]


# ── Main ──────────────────────────────────────────────────────

def write_summary(lines: list[str]) -> None:
    text = "\n".join(lines)
    print(text)
    if (summary := os.environ.get("GITHUB_STEP_SUMMARY")):
        with open(summary, "a") as f:
            f.write(text + "\n")


def main() -> None:
    repo, number = os.environ["REPO"], os.environ["PR_NUMBER"]
    pr = pull_request(repo, number)
    changes = changed_packages(pr)
    packages = {name for names in changes.values() for name in names}
    summary = [f"## Snyk fix PR → Devin Security: [#{number}]({pr['url']}) {pr['title']}",
               f"Packages Snyk's PR changes: {', '.join(sorted(packages)) or 'none'}", ""]

    reports = []
    for manifest in changes:
        manifest_reports = snyk_reports(pr["baseRefOid"], manifest)
        reports += manifest_reports
        summary.append(f"- Snyk on `{manifest}` at {pr['baseRefOid'][:7]}: {snyk_counts(manifest_reports[0])}")
    if not reports or os.environ.get("DRY_RUN") == "true":
        write_summary(summary + ["", "Dry run or nothing to scan: nothing sent to Devin."])
        return

    scan_id = start_ingestion(repo, [upload(r) for r in reports])
    summary += ["", f"**Devin Security ingestion scan:** `{scan_id}`"]
    status = wait_for(scan_id, repo)
    summary.append(f"Scan status: {status}")
    if status != "completed":
        write_summary(summary)
        raise SystemExit(1)

    findings = open_findings(scan_id)
    targeted = [f for f in findings if about(f, packages)] or findings
    cap = int(os.environ.get("MAX_REMEDIATIONS", "3"))
    summary += ["", f"{len(findings)} open high/critical findings; remediating {min(len(targeted), cap)} "
                    f"against `{pr['headRefName']}`.", "",
                "| Severity | Finding | Devin session |", "|---|---|---|"]
    for finding in targeted[:cap]:
        session = remediate(finding, pr["headRefName"])
        summary.append(f"| {finding['severity']} | {finding['title']} | https://app.devin.ai/sessions/{session.removeprefix('devin-')} |")
    write_summary(summary)


if __name__ == "__main__":
    main()
