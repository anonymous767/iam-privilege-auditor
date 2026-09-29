"""
privesc_rules.py

Knowledge base of known AWS IAM privilege escalation vectors.

Each rule describes a COMBINATION of IAM permissions that, together,
let an identity (user or role) escalate their own privileges — usually
to full admin — without needing any additional access granted to them.

This is the same category of technique documented publicly by cloud
security researchers (e.g. Rhino Security Labs' "AWS IAM Privilege
Escalation" research). We are not inventing new attack techniques here;
we are encoding known ones so we can DETECT them defensively in an
account we're auditing.

Each rule is a dict:
    name:        short identifier
    description: what the technique does
    required:    list of IAM actions ALL of which must be present
                  (a permission is "present" if the identity's policies
                  allow it, whether directly or via an attached/inline
                  policy — see analyzer.py for how we resolve that)
    severity:     CRITICAL / HIGH / MEDIUM — how directly it leads to admin
"""

PRIVESC_RULES = [
    {
        "name": "CreateNewPolicyVersion",
        "description": (
            "Identity can create a new default version of any policy they "
            "control, effectively rewriting its permissions to full admin "
            "('*':'*')."
        ),
        "required": ["iam:CreatePolicyVersion"],
        "severity": "CRITICAL",
    },
    {
        "name": "SetExistingDefaultPolicyVersion",
        "description": (
            "Identity can switch a policy's active version to a prior "
            "version that may grant broader access."
        ),
        "required": ["iam:SetDefaultPolicyVersion"],
        "severity": "HIGH",
    },
    {
        "name": "CreateEC2WithExistingInstanceProfile",
        "description": (
            "Identity can launch an EC2 instance and attach an existing "
            "instance profile/role, then retrieve that role's credentials "
            "from instance metadata."
        ),
        "required": ["ec2:RunInstances", "iam:PassRole"],
        "severity": "CRITICAL",
    },
    {
        "name": "CreateAccessKeyForAnotherUser",
        "description": (
            "Identity can create access keys for ANY IAM user, including "
            "higher-privileged ones, and authenticate as them."
        ),
        "required": ["iam:CreateAccessKey"],
        "severity": "CRITICAL",
    },
    {
        "name": "CreateLoginProfileForAnotherUser",
        "description": (
            "Identity can set a console password for another IAM user "
            "that doesn't already have one, gaining console access as them."
        ),
        "required": ["iam:CreateLoginProfile"],
        "severity": "HIGH",
    },
    {
        "name": "UpdateLoginProfileForAnotherUser",
        "description": (
            "Identity can reset the console password of another IAM user."
        ),
        "required": ["iam:UpdateLoginProfile"],
        "severity": "HIGH",
    },
    {
        "name": "AttachAdminPolicyToSelf",
        "description": (
            "Identity can attach an existing managed policy (e.g. "
            "AdministratorAccess) directly to their own user or a group "
            "they belong to."
        ),
        "required": ["iam:AttachUserPolicy"],
        "severity": "CRITICAL",
    },
    {
        "name": "AttachAdminPolicyToGroup",
        "description": (
            "Identity can attach an admin-level managed policy to a group, "
            "escalating everyone in that group."
        ),
        "required": ["iam:AttachGroupPolicy"],
        "severity": "CRITICAL",
    },
    {
        "name": "PutInlinePolicyToSelf",
        "description": (
            "Identity can write an inline policy directly onto their own "
            "user granting arbitrary permissions."
        ),
        "required": ["iam:PutUserPolicy"],
        "severity": "CRITICAL",
    },
    {
        "name": "AddUserToPrivilegedGroup",
        "description": (
            "Identity can add themselves to any IAM group, including "
            "groups with admin-level policies attached."
        ),
        "required": ["iam:AddUserToGroup"],
        "severity": "HIGH",
    },
    {
        "name": "UpdateRolePolicyToAssumeAnyRole",
        "description": (
            "Identity can modify a role's trust policy to allow themselves "
            "to assume it, then use sts:AssumeRole to gain that role's "
            "permissions."
        ),
        "required": ["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"],
        "severity": "CRITICAL",
    },
    {
        "name": "PassExistingRoleToNewLambdaThenInvoke",
        "description": (
            "Identity can create a Lambda function, attach an existing "
            "privileged execution role to it, and invoke it to run code "
            "with that role's permissions."
        ),
        "required": [
            "lambda:CreateFunction",
            "iam:PassRole",
            "lambda:InvokeFunction",
        ],
        "severity": "CRITICAL",
    },
    {
        "name": "PassExistingRoleToNewGlueDevEndpoint",
        "description": (
            "Identity can create a Glue development endpoint with an "
            "existing role attached, then SSH into it to get that role's "
            "credentials."
        ),
        "required": ["glue:CreateDevEndpoint", "iam:PassRole"],
        "severity": "HIGH",
    },
    {
        "name": "PassExistingRoleToCloudFormation",
        "description": (
            "Identity can create a CloudFormation stack, passing an "
            "existing privileged role for CloudFormation to assume during "
            "stack creation, running arbitrary resource creation as that "
            "role."
        ),
        "required": ["cloudformation:CreateStack", "iam:PassRole"],
        "severity": "HIGH",
    },
    {
        "name": "EditExistingLambdaFunctionCode",
        "description": (
            "Identity can overwrite the code of an EXISTING Lambda "
            "function that already has a privileged execution role "
            "attached, then trigger it."
        ),
        "required": ["lambda:UpdateFunctionCode"],
        "severity": "HIGH",
    },
]


def all_watched_actions():
    """Return the flat set of every IAM action referenced by any rule.
    Used by the collector/analyzer to know which actions are worth checking
    for, without hardcoding the list in multiple places."""
    actions = set()
    for rule in PRIVESC_RULES:
        actions.update(rule["required"])
    return actions
