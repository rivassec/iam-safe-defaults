# Pulumi IAM Safe Defaults

A lightweight Python component library that enforces secure IAM patterns. This library follows the "fail-loud" philosophy: it breaks your build if you attempt to create insecure infrastructure, forcing explicit acknowledgment of security risks.

> 📝 Design rationale: [IAM Roles That Fail Loud: Small Defaults, Big Difference](https://rivassec.com/iam-safe-defaults-fail-loud.html)

## Why use this?

Standard Pulumi/AWS resources are permissive by default. This library flips the script:

* **Mandatory Boundaries:** Prevents role creation without a Permissions Boundary.
* **No Silent Wildcards:** Blocks `Principal: "*"` and `Action: "*"` unless you explicitly opt-in.
* **Audit-Ready:** Every security bypass requires an explicit flag (`allow_no_boundary=True`), making "shady" infrastructure easy to find in a code review.



## Quick Start

### Installation

Clone the repo and import from a Pulumi project in the same venv. The package is not yet published or `pip install`-able; see `examples/basic_usage.py` for the shape of a consuming stack.

### Basic Usage

```python
import pulumi_aws as aws
import iam_safe_defaults.iam as safe_iam

role = safe_iam.create_safe_role(
    "app-role",
    assume_role_policy=my_trust_policy,
    permissions_boundary="arn:aws:iam::123456789012:policy/AppBoundary"
)

# 2. Generate a scoped-down policy
# This will FAIL if you try to use "s3:*" or Resource: "*"
policy_doc = safe_iam.generate_safe_policy(
    actions=["s3:GetObject"],
    resources=["arn:aws:s3:::my-bucket/*"]
)

```



## Feature Set

### 1. Hardened Roles (`create_safe_role`)

Wraps `aws.iam.Role` with mandatory guardrails:

* **Requires** a Permissions Boundary.
* **Rejects** trust policies with wildcard `Principal` (e.g., `*`).

### 2. Guarded Policies (`generate_safe_policy`)

A helper for building minimal policy documents. It automatically blocks "Admin-equivalent" inputs:

* `*` (Full Wildcards)
* `iam:*`, `sts:*`, or `<service>:*`
* `Resource: "*"`

### 3. Policy Linting (`is_policy_overly_permissive`)

A utility function to scan existing policy dictionaries for `NotAction`/`NotResource` inversions or unconstrained action+resource pairs.



## Explicit Opt-outs

If you have a legitimate use case for a broad permission, you must acknowledge the risk via an explicit flag. This makes security exceptions searchable in your codebase.

| Security Guard | Requirement | How to Bypass |
| --- | --- | --- |
| **Permissions Boundary** | Mandatory | `allow_no_boundary=True` |
| **Trust Principals** | No wildcards | `allow_wildcard_principal=True` |
| **Policy Actions** | No wildcards | `allow_wildcard=True` |



## Security & Integrity

* **Static Analysis:** Every PR runs [Bandit](https://github.com/PyCQA/bandit) to catch common Python security issues.
* **Supply Chain:** CI/CD workflows use pinned commit SHAs for third-party actions and hash-verified dependencies (`pip --require-hashes`).

**License:** Apache 2.0
