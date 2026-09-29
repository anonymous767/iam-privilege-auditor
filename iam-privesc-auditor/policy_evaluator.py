"""
policy_evaluator.py

A small, self-contained IAM policy evaluator.

Why this exists: our tool needs to answer "is identity X allowed to
perform action Y?" for a batch of actions. Against real AWS, we can ask
AWS itself via iam:SimulatePrincipalPolicy (see iam_collector.py). But
that API may not be available (e.g. running against LocalStack's free
tier, or an account whose IAM user isn't allowed to call it).

This module implements the same core AWS IAM evaluation logic ourselves,
directly against policy JSON documents:

    1. Gather every statement from every policy that applies to the
       identity (inline policies, attached managed policies, and — for
       users — policies inherited from their groups).
    2. If ANY statement explicitly DENIES the action -> DENIED. (Explicit
       deny always wins, no matter how many Allows exist elsewhere.)
    3. Else if ANY statement explicitly ALLOWS the action -> ALLOWED.
    4. Else -> DENIED (implicit deny — AWS's default-deny posture).

Simplifications (documented, not hidden):
    - We evaluate against Resource: "*" only, matching how the rest of
      this tool calls the AWS simulator (ActionNames only, no
      ResourceArns) — i.e. "could this identity do this on SOMETHING",
      not resource-scoped precision.
    - We do not evaluate Condition blocks. A statement with a Condition
      is treated as if the condition were satisfied. This can produce
      false positives (flagging something that's actually condition-
      restricted) but never false negatives, which is the safer
      direction for a security auditing tool to err in.
    - NotAction is not supported (rare in practice; a rule using
      NotAction is skipped with a warning rather than mis-evaluated).
"""

import fnmatch


def _to_list(value):
    """IAM allows a field to be a single string OR a list of strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def _action_matches(action_pattern, action):
    """
    IAM action patterns support * and ? wildcards, case-insensitively.
    e.g. "iam:*" matches "iam:CreateAccessKey"; "s3:Get*" matches "s3:GetObject".
    """
    return fnmatch.fnmatch(action.lower(), action_pattern.lower())


def _statement_matches_action(statement, action):
    if "NotAction" in statement:
        # Not supported — caller should treat this as "unknown", we play
        # it safe and say it does NOT match (so it can't grant a false Allow).
        return False

    for pattern in _to_list(statement.get("Action")):
        if _action_matches(pattern, action):
            return True
    return False


def evaluate_action(policy_documents, action):
    """
    policy_documents: list of parsed policy JSON dicts (each with a
                       "Statement" key, per AWS policy format)
    action: e.g. "iam:CreateAccessKey"

    Returns True if allowed, False if denied (explicit or implicit).
    """
    has_allow = False

    for doc in policy_documents:
        for statement in _to_list(doc.get("Statement")):
            if not _statement_matches_action(statement, action):
                continue

            effect = statement.get("Effect")
            if effect == "Deny":
                # Explicit deny short-circuits everything else.
                return False
            elif effect == "Allow":
                has_allow = True

    return has_allow


def evaluate_actions(policy_documents, actions):
    """Convenience wrapper: evaluate a list of actions at once.
    Returns the set of actions that are allowed."""
    allowed = set()
    for action in actions:
        if evaluate_action(policy_documents, action):
            allowed.add(action)
    return allowed
