"""
iam_collector.py

Connects to AWS and, for every IAM user and role in the account, works out
which of our "watched" privesc-relevant actions (see privesc_rules.py) they
are actually ALLOWED to perform.

Key design decision: rather than manually parsing each identity's attached
managed policies + inline policies + group policies and evaluating Allow/
Deny/wildcards/conditions ourselves (easy to get subtly wrong), we use
AWS's own policy simulator API: iam:SimulatePrincipalPolicy.

You give it an identity ARN + a list of actions, and AWS's own policy
engine tells you which ones are actually allowed for that identity right
now, accounting for every attached/inline/group policy AND any explicit
denies. This is the same engine AWS uses when it makes real authorization
decisions, so it's authoritative.

Required IAM permissions to RUN this tool (real AWS):
    iam:ListUsers
    iam:ListRoles
    iam:SimulatePrincipalPolicy

Against LocalStack, SimulatePrincipalPolicy may not be available depending
on your plan's entitlements. If it fails, this collector automatically
falls back to evaluating each identity's policies itself, using
policy_evaluator.py. Pass use_local_eval=True to skip straight to that
path (e.g. when you already know you're on LocalStack's free tier) and
avoid a failed API call per identity.
"""

import json
import boto3
from botocore.exceptions import ClientError
from privesc_rules import all_watched_actions
from policy_evaluator import evaluate_actions


class IAMCollector:
    def __init__(self, session=None, use_local_eval=False):
        self.session = session or boto3.Session()
        self.iam = self.session.client("iam")
        self.watched_actions = sorted(all_watched_actions())
        self.use_local_eval = use_local_eval
        # Once we hit one SimulatePrincipalPolicy failure, don't keep
        # retrying it for every remaining identity — just fall back for
        # the rest of the run too.
        self._simulate_unavailable = use_local_eval

    def list_identities(self):
        """Return a list of dicts: {arn, name, type} for every user and role."""
        identities = []

        paginator = self.iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                identities.append({
                    "arn": user["Arn"],
                    "name": user["UserName"],
                    "type": "user",
                })

        paginator = self.iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                # Skip AWS service-linked roles — they're managed by AWS,
                # not editable by account users, and clutter the report.
                if "/aws-service-role/" in role["Arn"]:
                    continue
                identities.append({
                    "arn": role["Arn"],
                    "name": role["RoleName"],
                    "type": "role",
                })

        return identities

    def get_allowed_actions(self, identity_arn, identity_name, identity_type):
        """
        Determine which of our watched actions this identity is allowed to
        perform. Tries AWS's real policy simulator first; falls back to our
        own policy_evaluator.py if that API isn't available (LocalStack
        free tier, or a caller without simulate permission).
        """
        if not self._simulate_unavailable:
            allowed = self._get_allowed_via_simulator(identity_arn)
            if allowed is not None:
                return allowed
            # None means the call failed — switch to local evaluation for
            # this and all subsequent identities.
            print("  [!] SimulatePrincipalPolicy unavailable — "
                  "falling back to local policy evaluation for this run.")
            self._simulate_unavailable = True

        return self._get_allowed_via_local_eval(identity_name, identity_type)

    def _get_allowed_via_simulator(self, identity_arn):
        """Returns a set of allowed actions, or None if the API call failed."""
        allowed = set()
        try:
            response = self.iam.simulate_principal_policy(
                PolicySourceArn=identity_arn,
                ActionNames=self.watched_actions,
            )
        except ClientError:
            return None

        for result in response.get("EvaluationResults", []):
            if result["EvalDecision"] == "allowed":
                allowed.add(result["EvalActionName"])

        while response.get("IsTruncated"):
            response = self.iam.simulate_principal_policy(
                PolicySourceArn=identity_arn,
                ActionNames=self.watched_actions,
                Marker=response["Marker"],
            )
            for result in response.get("EvaluationResults", []):
                if result["EvalDecision"] == "allowed":
                    allowed.add(result["EvalActionName"])

        return allowed

    def _get_policy_documents_for_user(self, username):
        """Gather every policy document that applies to a user: their own
        attached + inline policies, plus policies inherited from every
        group they belong to."""
        docs = []

        for policy in self.iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]:
            docs.append(self._fetch_managed_policy_document(policy["PolicyArn"]))

        for name in self.iam.list_user_policies(UserName=username)["PolicyNames"]:
            resp = self.iam.get_user_policy(UserName=username, PolicyName=name)
            docs.append(resp["PolicyDocument"])

        for group in self.iam.list_groups_for_user(UserName=username)["Groups"]:
            group_name = group["GroupName"]
            for policy in self.iam.list_attached_group_policies(GroupName=group_name)["AttachedPolicies"]:
                docs.append(self._fetch_managed_policy_document(policy["PolicyArn"]))
            for name in self.iam.list_group_policies(GroupName=group_name)["PolicyNames"]:
                resp = self.iam.get_group_policy(GroupName=group_name, PolicyName=name)
                docs.append(resp["PolicyDocument"])

        return [d for d in docs if d is not None]

    def _get_policy_documents_for_role(self, role_name):
        """Same idea as above, but for a role (no group concept for roles)."""
        docs = []

        for policy in self.iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]:
            docs.append(self._fetch_managed_policy_document(policy["PolicyArn"]))

        for name in self.iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
            resp = self.iam.get_role_policy(RoleName=role_name, PolicyName=name)
            docs.append(resp["PolicyDocument"])

        return [d for d in docs if d is not None]

    def _fetch_managed_policy_document(self, policy_arn):
        try:
            policy = self.iam.get_policy(PolicyArn=policy_arn)["Policy"]
            version_id = policy["DefaultVersionId"]
            version = self.iam.get_policy_version(
                PolicyArn=policy_arn, VersionId=version_id
            )
            doc = version["PolicyVersion"]["Document"]
            # boto3 usually already decodes this to a dict, but some
            # LocalStack responses return it URL-encoded/as a JSON string.
            if isinstance(doc, str):
                doc = json.loads(doc)
            return doc
        except ClientError as e:
            print(f"  [!] Could not fetch policy {policy_arn}: {e}")
            return None

    def _get_allowed_via_local_eval(self, identity_name, identity_type):
        if identity_type == "user":
            docs = self._get_policy_documents_for_user(identity_name)
        else:
            docs = self._get_policy_documents_for_role(identity_name)

        return evaluate_actions(docs, self.watched_actions)

    def collect(self):
        """
        Main entry point. Returns:
        {
            "arn:aws:iam::123:user/alice": {
                "name": "alice",
                "type": "user",
                "allowed_actions": {"iam:CreateAccessKey", ...}
            },
            ...
        }
        """
        results = {}
        identities = self.list_identities()
        print(f"[*] Found {len(identities)} identities (users + roles). Simulating permissions...")

        for identity in identities:
            print(f"    -> {identity['type']}: {identity['name']}")
            allowed = self.get_allowed_actions(
                identity["arn"], identity["name"], identity["type"]
            )
            results[identity["arn"]] = {
                "name": identity["name"],
                "type": identity["type"],
                "allowed_actions": allowed,
            }

        return results


if __name__ == "__main__":
    # Quick standalone test: run this file directly to just see the raw
    # collected data before any rule-matching happens.
    collector = IAMCollector()
    data = collector.collect()
    for arn, info in data.items():
        if info["allowed_actions"]:
            print(f"\n{info['type'].upper()} {info['name']} ({arn})")
            for action in sorted(info["allowed_actions"]):
                print(f"    - {action}")
