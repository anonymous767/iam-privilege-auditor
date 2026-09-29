# IAM Privilege Escalation Auditor — Project Explanation

## 1. What problem this solves

In AWS, permissions are granted through IAM (Identity and Access Management)
policies attached to users and roles. A very common — and dangerous —
misconfiguration is granting an identity a permission that seems harmless
on its own, but which actually lets that identity **grant itself more
permissions**, up to and including full admin access, without anyone
else's involvement.

This is called **IAM privilege escalation**. It's not a bug in AWS — it's
a side effect of how flexible IAM's permission model is. A junior developer
might legitimately need `iam:PassRole` to let CloudFormation deploy
resources on their behalf, without realizing that same permission, combined
with `ec2:RunInstances`, lets them launch an EC2 instance, attach someone
else's more privileged role to it, and pull that role's credentials from
the instance's metadata service.

There is a well-documented list of roughly 20 such permission
*combinations* that lead to privilege escalation (originally cataloged by
security researchers at Rhino Security Labs). Manually checking whether any
of your AWS account's dozens or hundreds of IAM identities hold one of
these combinations is tedious and error-prone. **This project automates
that check.**

## 2. What the tool actually does, end to end

Given access to an AWS account (real or emulated), the tool:

1. Lists every IAM user and role in the account
2. For each one, works out exactly which permissions it effectively holds
3. Checks those permissions against the ~14 known privilege-escalation
   patterns
4. For anything it flags, checks CloudTrail (AWS's audit log service) to
   see if that risky permission has actually been *used* recently
5. Produces a report ranking findings by severity, and a web dashboard to
   view them

It is a **read-only auditing tool** — it never modifies IAM, it only reads
and reports.

## 3. Architecture — the pieces and how they connect

```
                    ┌─────────────────┐
                    │  privesc_rules.py │  <- static knowledge base of
                    │  (knowledge base) │     ~14 known escalation patterns
                    └────────┬─────────┘
                             │
   AWS/LocalStack            │
   ┌──────────┐    ┌─────────▼──────────┐
   │   IAM    │◄───┤  iam_collector.py  │  <- lists identities, resolves
   │  service │    │   (data gathering)  │     "what can each one do?"
   └──────────┘    └─────────┬──────────┘
                             │ (allowed actions per identity)
                    ┌─────────▼──────────┐
                    │    analyzer.py     │  <- matches permissions
                    │  (rule matching)    │     against the rules
                    └─────────┬──────────┘
                             │ (list of findings)
   AWS/LocalStack            │
   ┌──────────┐    ┌─────────▼──────────┐
   │CloudTrail│◄───┤cloudtrail_check.py │  <- "has this actually
   │  service │    │ (usage evidence)    │     been used?"
   └──────────┘    └─────────┬──────────┘
                             │ (enriched findings)
                    ┌─────────▼──────────┐
                    │     report.py      │  <- turns findings into
                    │  (output formatting)│     console + Markdown output
                    └─────────┬──────────┘
                             │
                ┌────────────┴────────────┐
                │                         │
        ┌───────▼───────┐        ┌────────▼────────┐
        │    main.py     │        │     app.py      │
        │  (CLI runner)  │        │ (web dashboard) │
        └────────────────┘        └─────────────────┘
```

Both `main.py` and `app.py` call the *exact same* underlying pipeline
(`iam_collector` → `analyzer` → `cloudtrail_check` → `report`). The only
difference is how the result is presented — one prints to a terminal, the
other renders in a browser. No detection logic is duplicated between them.

## 4. How each module works, in detail

### `privesc_rules.py` — the knowledge base
This is just data: a list of dictionaries, each describing one escalation
technique as a **combination of IAM actions**. For example:

```python
{
    "name": "CreateEC2WithExistingInstanceProfile",
    "required": ["ec2:RunInstances", "iam:PassRole"],
    "severity": "CRITICAL",
}
```

This says: *if an identity can do both `ec2:RunInstances` AND
`iam:PassRole`, that's a privilege escalation path.* Having only one of
the two is not dangerous by itself — it's the combination that matters.

### `iam_collector.py` — figuring out what each identity can actually do
This is the most technically interesting part. Answering "can identity X
perform action Y?" sounds simple, but IAM permission resolution is
genuinely complex: an identity's effective permissions come from its own
attached managed policies, its own inline policies, and (for users) every
group it belongs to — and an explicit `Deny` anywhere in that stack
overrides any number of `Allow` statements.

The tool handles this two ways:

- **Against real AWS**, it asks AWS itself, via the
  `iam:SimulatePrincipalPolicy` API. This is AWS's own policy evaluation
  engine — the same one AWS uses to make real authorization decisions — so
  it's authoritative and avoids re-implementing (and potentially getting
  wrong) something AWS already does correctly.
- **Against LocalStack** (see section 6), that API's availability isn't
  guaranteed depending on plan/entitlements, so the tool falls back to
  `policy_evaluator.py` — a policy engine written from scratch for this
  project (see below).

### `policy_evaluator.py` — a hand-built IAM policy engine
This implements the core AWS IAM evaluation algorithm directly:

1. Gather every policy document that applies to an identity
2. If **any** statement explicitly **Denies** the action → not allowed,
   full stop (explicit deny always wins)
3. Else if **any** statement explicitly **Allows** the action → allowed
4. Else → not allowed (AWS's default is "implicit deny" — nothing is
   permitted unless something explicitly grants it)

It also has to handle **wildcards**: a policy granting `iam:*` should
match a check for `iam:CreateAccessKey`. This is done with pattern
matching (`fnmatch`), translating IAM's `*`/`?` wildcard syntax into
matching logic.

Building this by hand — rather than only ever relying on AWS's built-in
simulator — is what makes this project demonstrate genuine understanding
of IAM's authorization model, rather than just calling an API and trusting
its answer.

### `analyzer.py` — connecting permissions to techniques
Straightforward set logic: for every identity, for every rule, check
whether the identity's allowed-actions set is a **superset** of the rule's
required actions. If so, that's a finding. Findings are sorted so
CRITICAL severity surfaces first.

### `cloudtrail_check.py` — separating "risky" from "actively exploited"
A permission that's dangerous in theory but has never been used is a
*configuration hardening* task. A permission that's dangerous **and has
recently been exercised** is a potential *active incident*. This module
queries CloudTrail (AWS's request-logging service) for each risky action,
filtered to events performed by that specific identity, within a
configurable lookback window (default 90 days).

### `report.py` — output formatting
Takes the enriched findings and renders them two ways: a readable console
report (with color-coded severity icons) and a Markdown file suitable for
attaching to a writeup.

## 5. The two interfaces: CLI and Web Dashboard

- **`main.py`** — a command-line tool. Good for scripting, automation, or
  running in a CI pipeline.
- **`app.py`** — a Flask web application. Serves a single dashboard page
  (`templates/index.html`, styled by `static/style.css`) with a form to
  configure and trigger a scan, and renders findings as a color-coded list
  with a summary strip (counts by severity) and a report download link.

Flask works like this: `app.py` defines **routes** (URL paths mapped to
Python functions). `GET /` renders the dashboard with whatever the last
scan's results were (kept in memory). `POST /scan` reads the form values
the user submitted, runs the exact same pipeline as `main.py`, stores the
results, and redirects back to `/`. `GET /download-report` serves the
generated Markdown file as a downloadable attachment.

## 6. Why LocalStack, and how the testing setup works

A real AWS account with permissive-enough access to intentionally create
vulnerable IAM configurations is needed to actually **prove** the tool
works — but a restricted student AWS account can't be used for this.

**LocalStack** is a tool that emulates AWS's APIs on your own machine
inside a Docker container. boto3 (the AWS SDK this project is built on)
can be pointed at LocalStack's local endpoint (`http://localhost:4566`)
instead of real AWS, and it behaves the same way from the code's
perspective — same API calls, same request/response shapes. This lets the
entire pipeline be exercised against a **safe, disposable, free**
environment.

The testing procedure:
1. `docker-compose up -d` starts a LocalStack container with the IAM, STS,
   S3, EC2, and CloudTrail services enabled
2. `seed_vulnerable_account.py` creates 4 test identities inside that
   LocalStack instance: 3 deliberately vulnerable (each triggering a
   different rule) and 1 clean "control" identity with only harmless S3
   read access — proving the tool doesn't just flag everything
3. `main.py --endpoint-url http://localhost:4566 --local-eval
   --skip-cloudtrail` (or the equivalent form fields in the web dashboard)
   runs the full pipeline against that LocalStack instance
4. The tool correctly identified all 3 vulnerable identities and correctly
   produced **zero** findings for the control identity — validating both
   detection accuracy and the absence of false positives

## 7. Current setup and running instructions

Environment: Kali Linux VM, Docker + Docker Compose (standalone
`docker-compose`), Python 3.14, LocalStack (free/Hobby-tier account with
an auth token).

```bash
# One-time setup
cd ~/iam-privesc-auditor
pip3 install -r requirements.txt --break-system-packages
export LOCALSTACK_AUTH_TOKEN=your_token_here

# Start the emulated AWS environment
docker-compose up -d

# Seed test data (only needed once, or after docker-compose down removes it)
python3 seed_vulnerable_account.py

# Option A: CLI
python3 main.py --endpoint-url http://localhost:4566 --local-eval --skip-cloudtrail

# Option B: Web dashboard
python3 app.py
# then open http://localhost:5000 in a browser inside the VM
```

## 8. What this demonstrates for a capstone writeup

- Understanding of AWS IAM's authorization model (policy evaluation order,
  explicit deny precedence, wildcard matching, implicit deny)
- Applied offensive-security knowledge (privilege escalation techniques)
  used for defensive tooling
- Practical use of AWS's audit/logging service (CloudTrail) for
  correlating configuration risk with actual behavior
- A realistic testing methodology using infrastructure emulation
  (LocalStack) when a real cloud environment isn't available — itself a
  skill used professionally for cost control and CI testing
- A full-stack deliverable: CLI tool, from-scratch policy engine, and a
  web dashboard, all sharing one underlying pipeline rather than
  duplicating logic
