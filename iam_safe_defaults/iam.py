import json
import pulumi
import pulumi_aws as aws
from typing import Iterable, List, Dict, Union, Optional

# Sentinel distinguishing "not passed" from "explicitly None".
_UNSET = object()

_ADMIN_EQUIVALENT_ACTIONS = {"*", "*:*", "iam:*", "sts:*"}


def _assume_policy_has_wildcard_principal(assume_policy: str) -> bool:
    """True if the trust policy grants AssumeRole to a wildcard principal.

    Fails loud: a trust policy that cannot be verified is never reported as
    "no wildcard". A non-string policy (e.g. a ``pulumi.Output``) or a string
    that is not parseable JSON raises, so ``create_safe_role`` refuses it
    rather than silently creating the role. Callers who genuinely need an
    un-inspectable policy opt out with ``allow_wildcard_principal=True``.
    """
    if not isinstance(assume_policy, str):
        raise TypeError(
            "create_safe_role can only verify a literal JSON-string trust "
            f"policy; got {type(assume_policy).__name__}. Resolve it to a JSON "
            "string (e.g. json.dumps(...) or an Output.apply that returns one), "
            "or pass allow_wildcard_principal=True to opt out explicitly."
        )
    try:
        doc = json.loads(assume_policy)
    except ValueError as exc:
        raise ValueError(
            "create_safe_role could not parse the trust policy as JSON to "
            "verify its Principal. Fix the policy JSON, or pass "
            "allow_wildcard_principal=True to opt out explicitly."
        ) from exc
    for statement in doc.get("Statement", []):
        if statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        if principal == "*":
            return True
        if isinstance(principal, dict):
            for _, value in principal.items():
                if value == "*":
                    return True
                if isinstance(value, list) and "*" in value:
                    return True
    return False


def create_safe_role(
    name: str,
    assume_policy: str,
    permissions_boundary=_UNSET,
    allow_no_boundary: bool = False,
    allow_wildcard_principal: bool = False,
    max_session_duration: int = 3600,
    opts: Optional[pulumi.ResourceOptions] = None,
) -> aws.iam.Role:
    """Create an IAM role with restrictive defaults; opt-outs raise unless toggled."""
    if permissions_boundary is _UNSET and not allow_no_boundary:
        raise ValueError(
            "create_safe_role requires permissions_boundary. "
            "Pass the boundary ARN, or set allow_no_boundary=True to opt out explicitly."
        )
    if not allow_wildcard_principal and _assume_policy_has_wildcard_principal(
        assume_policy
    ):
        raise ValueError(
            "create_safe_role rejects trust policies with a wildcard Principal. "
            "Narrow Principal to a specific account, role, or service, or pass "
            "allow_wildcard_principal=True to opt out explicitly."
        )

    role_kwargs = {
        "assume_role_policy": assume_policy,
        "force_detach_policies": True,
        "max_session_duration": max_session_duration,
        "opts": opts,
    }
    if permissions_boundary is not _UNSET:
        role_kwargs["permissions_boundary"] = permissions_boundary
    return aws.iam.Role(name, **role_kwargs)


def _iter_strs(value: Union[str, Iterable[str], None]) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def is_policy_overly_permissive(policy_doc: Dict) -> bool:
    """True if any Allow statement grants admin-equivalent access."""
    for statement in policy_doc.get("Statement", []):
        if statement.get("Effect") != "Allow":
            continue

        if "NotAction" in statement or "NotResource" in statement:
            return True

        actions = _iter_strs(statement.get("Action"))
        resources = _iter_strs(statement.get("Resource"))

        action_is_wildcard = any(a == "*" or a.endswith(":*") for a in actions)
        resource_is_wildcard = any(r == "*" for r in resources)

        if action_is_wildcard:
            return True
        if resource_is_wildcard and not actions:
            return True
    return False


def generate_safe_policy(
    actions: Union[str, List[str]],
    resources: Union[str, List[str]],
    allow_wildcard: bool = False,
) -> Dict:
    """Generate a minimal IAM policy doc; rejects wildcard inputs unless allow_wildcard=True."""
    if isinstance(actions, str):
        actions = [actions]
    if isinstance(resources, str):
        resources = [resources]

    if not actions or not all(isinstance(a, str) and a for a in actions):
        raise ValueError("Actions must be a non-empty list of non-empty strings.")
    if not resources or not all(isinstance(r, str) and r for r in resources):
        raise ValueError("Resources must be a non-empty list of non-empty strings.")

    if not allow_wildcard:
        admin_hits = [a for a in actions if a in _ADMIN_EQUIVALENT_ACTIONS]
        if admin_hits:
            raise ValueError(
                f"generate_safe_policy rejects admin-equivalent actions {admin_hits}. "
                "Narrow to specific actions, or pass allow_wildcard=True to opt out explicitly."
            )
        wildcard_suffix_hits = [a for a in actions if a.endswith(":*")]
        if wildcard_suffix_hits:
            raise ValueError(
                f"generate_safe_policy rejects wildcard-suffix actions {wildcard_suffix_hits}. "
                "Narrow to specific actions (e.g. 's3:GetObject' instead of 's3:*'), "
                "or pass allow_wildcard=True to opt out explicitly."
            )
        if "*" in resources:
            raise ValueError(
                "generate_safe_policy rejects Resource: '*'. "
                "Narrow to specific ARNs, or pass allow_wildcard=True to opt out explicitly."
            )

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
