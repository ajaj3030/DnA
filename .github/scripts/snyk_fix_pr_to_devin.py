"""
Snyk fix PR → Devin: when Snyk opens a fix pull request, re-scan the
dependency tree before and after it, then start one Devin session that takes
the PR over: verify the upgrade, adapt code it breaks, prove the fix with a
Snyk re-scan and a build, and push to the PR's branch.

A PR that already has a session (tagged snyk-pr:<repo>#<number>) is skipped.

Environment: GH_TOKEN, SNYK_TOKEN, DEVIN_API_KEY, REPO, PR_NUMBER, DRY_RUN,
DEVIN_MAX_ACU.
"""

import json
import os
import subprocess
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

DEVIN_API = "https://api.devin.ai/v1"
SEVERITY_THRESHOLD = "high"


def run(cmd: list[str], cwd: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def pull_request(repo: str, number: str) -> dict:
    fields = "number,title,url,body,headRefName,baseRefOid,headRefOid,author"
    result = run(["gh", "pr", "view", number, "--repo", repo, "--json", fields])
    if result.returncode != 0:
        raise RuntimeError(f"Could not read PR #{number}: {result.stderr}")
    return json.loads(result.stdout)


def changed_manifests(base: str, head: str) -> list[str]:
    diff = run(["git", "diff", "--name-only", base, head, "--", "**/package.json"])
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


def describe_issue(issue: dict) -> str:
    cves = ", ".join(issue.get("identifiers", {}).get("CVE", [])) or "no CVE"
    return (f"- [{issue['severity'].upper()}] {issue['packageName']}@{issue['version']}: "
            f"{issue['title']} ({cves}) https://security.snyk.io/vuln/{issue['id']}")


def rescan(pr: dict, manifests: list[str]) -> tuple[list[dict], list[dict]]:
    """Issues the PR fixes, and high+ issues still present (or introduced) after it."""
    fixed, remaining = [], []
    for manifest in manifests:
        before = snyk_issues(pr["baseRefOid"], manifest)
        after = snyk_issues(pr["headRefOid"], manifest)
        fixed += [issue for issue_id, issue in before.items() if issue_id not in after]
        remaining += list(after.values())
    return fixed, remaining


def takeover_prompt(pr: dict, repo: str, manifests: list[str], fixed: list, remaining: list) -> str:
    fixed_text = "\n".join(describe_issue(i) for i in fixed) or "- none detected by the re-scan"
    remaining_text = "\n".join(describe_issue(i) for i in remaining) or "- none"
    dirs = ", ".join(sorted({str(Path(m).parent) for m in manifests}))
    return f"""Snyk opened a security fix pull request on {repo}: {pr['url']}
"{pr['title']}" (branch {pr['headRefName']})

Our Snyk re-scan of the PR:
Fixed by this PR:
{fixed_text}
High or critical issues still present after it:
{remaining_text}

Take this PR over and make it safe to merge. Work on the existing branch {pr['headRefName']}; don't open a new PR. Never open pull requests or issues on mercedes-benz/DnA.
1. Check Snyk's version change. If it is a major-version upgrade, read the package's changelog for breaking changes, find every place the code uses the package, and update that code.
2. If high or critical issues remain in packages this PR touches, upgrade further to resolve them.
3. Prove the fix is safe. In {dirs}: `npm install --package-lock-only --ignore-scripts --legacy-peer-deps`, then `snyk test --file=package-lock.json --severity-threshold=high` (SNYK_TOKEN is provided) and confirm the issues above are gone with nothing new; then `npm install --legacy-peer-deps`, `npm run build`, and the tests if they exist.
4. Push your commits to {pr['headRefName']} and comment on the PR with: what Snyk changed, what you changed and why, the evidence from step 3 (Snyk before/after, build and test results), and the code paths you checked. Do not merge.
"""


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


def start_session(pr: dict, prompt: str, tag: str) -> str:
    return devin_request("POST", "/sessions", {
        "title": f"Snyk PR #{pr['number']}: {pr['title'].removeprefix('[Snyk] ')}",
        "prompt": prompt,
        "tags": ["snyk-fix-pr", tag],
        "idempotent": True,
        "max_acu_limit": int(os.environ.get("DEVIN_MAX_ACU", "10")),
        "session_secrets": [{"key": "SNYK_TOKEN", "value": os.environ["SNYK_TOKEN"]}],
    })["url"]


def write_summary(lines: list[str]) -> None:
    text = "\n".join(lines)
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write(text + "\n")


def main() -> None:
    repo, number = os.environ["REPO"], os.environ["PR_NUMBER"]
    pr = pull_request(repo, number)
    manifests = changed_manifests(pr["baseRefOid"], pr["headRefOid"])
    fixed, remaining = rescan(pr, manifests)
    tag = f"snyk-pr:{repo}#{number}"

    if os.environ.get("DRY_RUN") == "true":
        outcome = "dry run, no session started"
    elif (session_id := existing_session(tag)):
        outcome = f"already in progress: https://app.devin.ai/sessions/{session_id.removeprefix('devin-')}"
    else:
        outcome = start_session(pr, takeover_prompt(pr, repo, manifests, fixed, remaining), tag)

    write_summary([
        f"## Snyk fix PR → Devin: [#{number}]({pr['url']}) {pr['title']}",
        f"Manifests: {', '.join(manifests) or 'none'}",
        "", "**Fixed by the PR**", *(describe_issue(i) for i in fixed or []), "" if fixed else "- none",
        "", "**Still high or critical after it**", *(describe_issue(i) for i in remaining), "" if remaining else "- none",
        "", f"**Devin:** {outcome}",
    ])


if __name__ == "__main__":
    main()
