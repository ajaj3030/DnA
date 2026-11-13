"""
Snyk → Devin: start a Devin remediation session for each NEW high or critical
dependency finding introduced by a push.

"New" means present after the push and absent before it, so the existing
backlog never spawns sessions. Findings are grouped per vulnerable package
(one upgrade fixes them all), and a package that already has a session
(tagged snyk-auto:<package>@<version>) is skipped.

Environment: SNYK_TOKEN, DEVIN_API_KEY, REPO, HEAD_SHA, BASE_SHA (optional),
MANIFESTS (optional, comma-separated), DRY_RUN, MAX_SESSIONS, DEVIN_MAX_ACU.
"""

import json
import os
import subprocess
import tempfile
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

DEVIN_API = "https://api.devin.ai/v1"
SEVERITY_THRESHOLD = "high"
NO_COMMIT = "0" * 40


@dataclass
class Finding:
    """All new issues in one vulnerable package version: one upgrade fixes them."""
    manifest: str
    package: str
    version: str
    severity: str
    issues: list = field(default_factory=list)

    @property
    def tag(self) -> str:
        return f"snyk-auto:{self.package}@{self.version}"


def run(cmd: list[str], cwd: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def commit_exists(sha: str) -> bool:
    return bool(sha) and sha != NO_COMMIT and run(["git", "cat-file", "-e", f"{sha}^{{commit}}"]).returncode == 0


def changed_manifests(base: str, head: str) -> list[str]:
    diff = run(["git", "diff", "--name-only", base, head, "--", "packages/**/package.json"])
    return [path for path in diff.stdout.split() if path.endswith("package.json")]


def snyk_issues(rev: str, manifest: str) -> dict[str, dict]:
    """High+ Snyk issues for a manifest at a commit, keyed by Snyk issue id."""
    content = run(["git", "show", f"{rev}:{manifest}"])
    if content.returncode != 0:
        return {}  # manifest didn't exist at this commit
    with tempfile.TemporaryDirectory() as work:
        Path(work, "package.json").write_text(content.stdout)
        lock = run(["npm", "install", "--package-lock-only", "--ignore-scripts",
                    "--legacy-peer-deps", "--no-audit", "--no-fund"], cwd=work)
        if lock.returncode != 0:
            raise RuntimeError(f"npm could not resolve {manifest}@{rev[:7]}: {lock.stderr[-500:]}")
        scan = run(["snyk", "test", "--file=package-lock.json",
                    f"--severity-threshold={SEVERITY_THRESHOLD}", "--json"], cwd=work)
    if scan.returncode not in (0, 1):  # 0 = clean, 1 = issues found
        raise RuntimeError(f"Snyk failed on {manifest}@{rev[:7]}: {scan.stdout[-500:]}{scan.stderr[-500:]}")
    return {v["id"]: v for v in json.loads(scan.stdout).get("vulnerabilities", [])}


def group_new_findings(manifest: str, before: dict, after: dict) -> list[Finding]:
    groups: dict[tuple, Finding] = {}
    for issue_id, issue in after.items():
        if issue_id in before:
            continue
        key = (issue["packageName"], issue["version"])
        finding = groups.setdefault(key, Finding(manifest, *key, issue["severity"]))
        if issue["severity"] == "critical":
            finding.severity = "critical"
        finding.issues.append(issue)
    return list(groups.values())


def devin_request(method: str, path: str, body: dict | None = None) -> dict:
    request = urllib.request.Request(
        f"{DEVIN_API}{path}", method=method,
        data=json.dumps(body).encode() if body else None,
        headers={"Authorization": f"Bearer {os.environ['DEVIN_API_KEY']}",
                 "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def existing_session(tag: str) -> str | None:
    sessions = devin_request("GET", f"/sessions?limit=1&tags={urllib.parse.quote(tag)}").get("sessions", [])
    return sessions[0]["session_id"] if sessions else None


def describe_issue(issue: dict) -> str:
    cves = ", ".join(issue.get("identifiers", {}).get("CVE", [])) or "no CVE"
    fixed = ", ".join(issue.get("fixedIn", [])) or "no fixed version published"
    path = " > ".join(issue.get("from", [])[1:])
    return (f"- [{issue['severity'].upper()}] {issue['title']} ({cves}), Snyk {issue['id']}\n"
            f"  fixed in: {fixed}; dependency path: {path}\n"
            f"  https://security.snyk.io/vuln/{issue['id']}")


def remediation_prompt(finding: Finding, repo: str, head: str) -> str:
    issues = "\n".join(describe_issue(i) for i in finding.issues)
    package_dir = str(Path(finding.manifest).parent)
    return f"""Snyk flagged a new {finding.severity} vulnerability on {repo} at commit {head[:7]}.

Package: {finding.package}@{finding.version} in {finding.manifest}
{issues}

Fix it:
1. Branch from main and change {finding.manifest} so {finding.package} resolves to the lowest version that fixes every issue above. If that is a major-version change, find and update the code that uses it.
2. Prove the fix is safe. In {package_dir}: run `npm install --package-lock-only --ignore-scripts --legacy-peer-deps`, then `snyk test --file=package-lock.json --severity-threshold=high` (SNYK_TOKEN is provided) and confirm these issues are gone without new ones. Then `npm install --legacy-peer-deps` and `npm run build`, and run the tests if they exist.
3. Open a pull request against {repo}, base main. Never open pull requests or issues on mercedes-benz/DnA. Do not merge it.
4. In the PR description: the Snyk issues fixed, the version change, the evidence from step 2 (Snyk before/after, build and test results), and any code that uses {finding.package} and how you checked it still works.
"""


def start_session(finding: Finding, repo: str, head: str) -> dict:
    return devin_request("POST", "/sessions", {
        "title": f"Snyk: fix {finding.severity} {finding.package}@{finding.version}",
        "prompt": remediation_prompt(finding, repo, head),
        "tags": ["snyk-auto", finding.tag],
        "idempotent": True,
        "max_acu_limit": int(os.environ.get("DEVIN_MAX_ACU", "10")),
        "session_secrets": [{"key": "SNYK_TOKEN", "value": os.environ["SNYK_TOKEN"]}],
    })


def write_summary(lines: list[str]) -> None:
    text = "\n".join(lines)
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write(text + "\n")


def main() -> None:
    repo, head = os.environ["REPO"], os.environ["HEAD_SHA"]
    base = os.environ.get("BASE_SHA") or f"{head}^"
    dry_run = os.environ.get("DRY_RUN") == "true"
    max_sessions = int(os.environ.get("MAX_SESSIONS", "3"))
    if not commit_exists(base):
        write_summary([f"No earlier commit to compare with ({base[:12]}); skipping so the backlog isn't re-reported."])
        return

    manifests = [m for m in os.environ.get("MANIFESTS", "").split(",") if m] or changed_manifests(base, head)
    findings = []
    for manifest in manifests:
        findings += group_new_findings(manifest, snyk_issues(base, manifest), snyk_issues(head, manifest))

    rows = ["## Snyk → Devin", f"Compared {base[:7]} → {head[:7]} on {', '.join(manifests) or 'no manifests'}.", ""]
    if not findings:
        write_summary(rows + ["No new high or critical findings."])
        return
    rows += ["| Package | Severity | Issues | Devin session |", "|---|---|---|---|"]
    for index, finding in enumerate(findings):
        cves = ", ".join(c for i in finding.issues for c in i.get("identifiers", {}).get("CVE", [])) or "—"
        if dry_run:
            outcome = "dry run"
        elif index >= max_sessions:
            outcome = f"skipped (cap of {max_sessions} per run)"
        elif (session_id := existing_session(finding.tag)):
            outcome = f"already in progress: https://app.devin.ai/sessions/{session_id.removeprefix('devin-')}"
        else:
            outcome = start_session(finding, repo, head)["url"]
        rows.append(f"| {finding.package}@{finding.version} | {finding.severity} | {cves} | {outcome} |")
    write_summary(rows)


if __name__ == "__main__":
    main()
