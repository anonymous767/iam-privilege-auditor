# IAM Privilege Escalation Detector & Auditor

A tool that scans an AWS account's IAM users and roles to find identities
that can escalate their own privileges — usually to full admin — through
known IAM privilege escalation techniques. Cross-references findings
against CloudTrail to show whether the risky permissions have actually
been used.

## How it works (pipeline)

1. **`iam_collector.py`** — Lists every IAM user/role and uses AWS's
   `iam:SimulatePrincipalPolicy` API to determine exactly which
   privesc-relevant actions each identity is allowed to perform (this
   correctly accounts for attached policies, inline policies, group
   memberships, and explicit denies — we don't hand-parse policy JSON).
2. **`privesc_rules.py`** — A knowledge base of ~14 known IAM privesc
   techniques (e.g. `iam:PassRole` + `ec2:RunInstances` lets you launch an
   instance with someone else's role and steal its credentials).
3. **`analyzer.py`** — Matches each identity's allowed actions against the
   rules to find actual escalation paths.
4. **`cloudtrail_check.py`** — For every finding, checks CloudTrail to see
   if that risky permission has actually been exercised recently.
5. **`report.py`** — Generates a console report and a Markdown report,
   ranked by severity.
6. **`policy_evaluator.py`** — A from-scratch IAM policy evaluator
   (Allow/Deny precedence, wildcard actions, implicit deny) used as a
   fallback whenever `iam:SimulatePrincipalPolicy` isn't available —
   which is the normal case when running against LocalStack instead of
   real AWS. See the LocalStack section below.

## Web dashboard (GUI)

Instead of the CLI, you can run a Flask-based web dashboard:

```bash
python3 app.py
```

Then open **http://localhost:5000** in your browser. Fill in the endpoint
URL (defaults to `http://localhost:4566` for LocalStack), leave "Local
policy evaluation" and "Skip CloudTrail" checked for LocalStack runs, and
click **Run audit**. Findings render as a list, color-coded by severity,
with a link to download the same Markdown report the CLI produces.

Leave the Endpoint URL field blank to scan a real AWS account using your
configured profile/credentials instead of LocalStack.

The dashboard is a thin layer over the exact same pipeline as `main.py` —
no logic is duplicated between the two.

## Setup

```bash
pip install -r requirements.txt
```

You need AWS credentials configured (via `aws configure`, environment
variables, or an IAM role) for an identity with at minimum:

```
iam:ListUsers
iam:ListRoles
iam:SimulatePrincipalPolicy
cloudtrail:LookupEvents   (only needed if not using --skip-cloudtrail)
```

**Recommended: don't run this against your real production AWS account
first.** Set up a free-tier sandbox account, create a few test IAM users
with intentionally loose policies (this is a great way to practice
building vulnerable-by-design labs, too), and run against that.

## Usage

```bash
# Full run against default AWS profile
python main.py

# Use a specific named profile
python main.py --profile my-sandbox

# Skip CloudTrail check (faster, needs fewer permissions)
python main.py --skip-cloudtrail

# Look back further than the default 90 days
python main.py --lookback-days 180
```

Output: a console summary plus `iam_privesc_report.md` written to the
current directory.

## Testing it against LocalStack (no AWS account needed)

This is the recommended way to test/demo the tool if you don't have an
unrestricted AWS account.

### 1. Get a free LocalStack account + auth token

As of 2026, LocalStack requires a (free, non-commercial) account and auth
token to start the container at all — there's no more anonymous image.

1. Go to LocalStack's site and sign up for the free Hobby/non-commercial
   plan (GitHub or email signup).
2. Once logged in, generate a personal auth token from your account
   settings.
3. Export it in your terminal:
   ```bash
   export LOCALSTACK_AUTH_TOKEN=your_token_here
   ```

### 2. Start LocalStack

```bash
docker compose up -d
```

Check it's healthy:
```bash
curl http://localhost:4566/_localstack/health
```

### 3. Seed some test identities

```bash
python seed_vulnerable_account.py
```

This creates 4 IAM identities in your LocalStack instance:
- `vulnerable-dev` (user) — has `iam:CreateAccessKey` → should be flagged CRITICAL
- `automation-role` (role) — has `ec2:RunInstances` + `iam:PassRole` → should be flagged CRITICAL
- `sloppy-contractor` (user) — has `iam:AttachUserPolicy` → should be flagged CRITICAL
- `readonly-analyst` (user) — only harmless S3 read access → should produce **no findings** (this is the control case, proving the tool doesn't cry wolf)

### 4. Run the auditor against it

```bash
python main.py --endpoint-url http://localhost:4566 --local-eval --skip-cloudtrail
```

- `--endpoint-url` points boto3 at LocalStack instead of real AWS.
- `--local-eval` tells the tool to evaluate IAM policies itself
  (`policy_evaluator.py`) rather than calling AWS's `SimulatePrincipalPolicy`,
  since that API's availability depends on your LocalStack plan's
  entitlements — this way the tool works regardless.
- `--skip-cloudtrail` is recommended here: LocalStack's CloudTrail
  emulation doesn't reliably capture IAM management-plane events the way
  real AWS does, so the usage cross-reference step won't be meaningful in
  this environment. Check `iam_privesc_report.md` for the resulting
  report.

You should see 3 CRITICAL findings and `readonly-analyst` should not
appear anywhere in the report.

### 5. Tear down

```bash
docker compose down
```

## Testing against real AWS

If you later get access to an unrestricted AWS sandbox account, create a
test IAM user with one of these attached and run `python main.py`
normally (no `--endpoint-url` / `--local-eval` flags needed — it'll use
AWS's real `SimulatePrincipalPolicy`):

- `iam:CreateAccessKey` on `*`
- `iam:PassRole` + `ec2:RunInstances`

## Extending this project

Ideas if you want to take this further for a portfolio piece:
- Add a `--fix` mode that generates (but does not auto-run) remediation
  IAM policy patches for each finding.
- Add resource-level scoping awareness (right now we treat "allowed on
  some resource" as a finding; a v2 could distinguish "`*`-scoped" from
  "scoped to one specific role ARN" findings, which are lower severity).
- Package as a Lambda that runs on a schedule and posts findings to Slack/SNS.
- Add an HTML report option using the same data structures.
