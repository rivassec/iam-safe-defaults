import pulumi
import pulumi_aws as aws
from typing import List, Dict, Union, Optional


def create_safe_role(
    name: str, assume_policy: str, opts: Optional[pulumi.ResourceOptions] = None
) -> aws.iam.Role:
    """
    Create an IAM role with restrictive, secure defaults.
    """
    return aws.iam.Role(
        name,
        assume_role_policy=assume_policy,
        force_detach_policies=True,
        max_session_duration=3600,
        permissions_boundary=None,  # Optionally attach a known-safe permissions boundary
        opts=opts,
    )


def is_policy_overly_permissive(policy_doc: Dict) -> bool:
    """
    Checks if an IAM policy document contains wildcard permissions or overly broad access.
    """
    for statement in policy_doc.get("Statement", []):
        if statement.get("Effect") == "Allow":
            actions = statement.get("Action", [])
            resources = statement.get("Resource", [])
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]

            if "*" in actions or "*" in resources:
                return True
    return False


def generate_safe_policy(
    actions: Union[str, List[str]], resources: Union[str, List[str]]
) -> Dict:
    """
    Generates a minimal IAM policy document allowing specific actions on specific resources.
    Raises ValueError if inputs are invalid.
    """
    if isinstance(actions, str):
        actions = [actions]
    if isinstance(resources, str):
        resources = [resources]

    if not actions or not all(isinstance(a, str) and a for a in actions):
        raise ValueError("Actions must be a non-empty list of non-empty strings.")

    if not resources or not all(isinstance(r, str) and r for r in resources):
        raise ValueError("Resources must be a non-empty list of non-empty strings.")

    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": actions,
                "Resource": resources,
            }
        ],
    }
