import pulumi
import pulumi_aws as aws
import json
import iam_safe_defaults.iam as safe_iam

# Trust policy for EC2
assume_role_policy = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

# Demo opts out of boundary requirement; real callers should pass permissions_boundary=<arn>.
secure_role = safe_iam.create_safe_role(
    "secure-example-role",
    assume_role_policy,
    allow_no_boundary=True,
)

# Generate a restrictive policy allowing only GetObject on a specific S3 bucket
policy_doc = safe_iam.generate_safe_policy(
    actions=["s3:GetObject"], resources=["arn:aws:s3:::my-secure-bucket/*"]
)

# Attach the policy to the role as an inline policy
aws_policy = aws.iam.RolePolicy(
    "secure-inline-policy", role=secure_role.name, policy=json.dumps(policy_doc)
)

# Export outputs (optional)
pulumi.export("role_name", secure_role.name)
pulumi.export("policy_json", json.dumps(policy_doc, indent=2))
