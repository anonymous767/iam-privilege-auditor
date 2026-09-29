"""
seed_vulnerable_account.py

Populates a running LocalStack instance with a handful of IAM identities:
some intentionally vulnerable (to prove the auditor catches them), and one
clean identity (to prove the auditor doesn't false-positive on safe
permissions).

Run this AFTER `docker compose up -d` and BEFORE running main.py.

Usage:
    python seed_vulnerable_account.py
"""

import json
import boto3

ENDPOINT_URL = "http://localhost:4566"


def get_local_session():
    return boto3.Session(
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="us-east-1",
    )


def get_iam_client(session):
    return session.client("iam", endpoint_url=ENDPOINT_URL)


def create_user_with_inline_policy(iam, username, policy_doc, description):
    print(f"[*] Creating user '{username}' — {description}")
    try:
        iam.create_user(UserName=username)
    except iam.exceptions.EntityAlreadyExistsException:
        print(f"    (user already exists, skipping create)")

    iam.put_user_policy(
        UserName=username,
        PolicyName=f"{username}-inline-policy",
        PolicyDocument=json.dumps(policy_doc),
    )


def create_role_with_inline_policy(iam, rolename, policy_doc, description):
    print(f"[*] Creating role '{rolename}' — {description}")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    try:
        iam.create_role(
            RoleName=rolename,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
        )
    except iam.exceptions.EntityAlreadyExistsException:
        print(f"    (role already exists, skipping create)")

    iam.put_role_policy(
        RoleName=rolename,
        PolicyName=f"{rolename}-inline-policy",
        PolicyDocument=json.dumps(policy_doc),
    )


def main():
    session = get_local_session()
    iam = get_iam_client(session)

    # --- VULNERABLE #1: can mint access keys for ANY user (CRITICAL) ---
    create_user_with_inline_policy(
        iam,
        "vulnerable-dev",
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["iam:CreateAccessKey", "s3:GetObject"],
                "Resource": "*",
            }],
        },
        "has iam:CreateAccessKey — should trigger CreateAccessKeyForAnotherUser",
    )

    # --- VULNERABLE #2: EC2 + PassRole combo (CRITICAL) ---
    create_role_with_inline_policy(
        iam,
        "automation-role",
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["ec2:RunInstances", "iam:PassRole"],
                "Resource": "*",
            }],
        },
        "has ec2:RunInstances + iam:PassRole — should trigger "
        "CreateEC2WithExistingInstanceProfile",
    )

    # --- VULNERABLE #3: can attach admin policy to self (CRITICAL) ---
    create_user_with_inline_policy(
        iam,
        "sloppy-contractor",
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["iam:AttachUserPolicy"],
                "Resource": "*",
            }],
        },
        "has iam:AttachUserPolicy — should trigger AttachAdminPolicyToSelf",
    )

    # --- SAFE: only harmless S3 read access (should produce NO findings) ---
    create_user_with_inline_policy(
        iam,
        "readonly-analyst",
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": "*",
            }],
        },
        "read-only S3 access only — should trigger NO findings (control case)",
    )

    print("\n[*] Seeding complete. Run `python main.py --endpoint-url "
          f"{ENDPOINT_URL} --local-eval` to audit this LocalStack account.")


if __name__ == "__main__":
    main()
