import pulumi
import pulumi_aws as aws
from iam_safe_defaults.iam import create_safe_role

# Create a stub provider with fake credentials and region
aws_provider = aws.Provider(
    "stub",
    region="us-west-2",
    access_key="FAKEKEY",
    secret_key="FAKESECRET",
    skip_credentials_validation=True,
    skip_metadata_api_check=True,
    skip_region_validation=True,
    skip_requesting_account_id=True,
)

# Dummy IAM assume role policy
dummy_assume_policy = """{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": { "Service": "ec2.amazonaws.com" },
            "Action": "sts:AssumeRole"
        }
    ]
}"""

# Create the role using your helper function and the stub provider
role = create_safe_role(
    name="test-safe-role",
    assume_policy=dummy_assume_policy,
    opts=pulumi.ResourceOptions(provider=aws_provider),
)

# Export output values
pulumi.export("role_name", role.name)
pulumi.export("max_session_duration", role.max_session_duration)
