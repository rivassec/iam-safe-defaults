import unittest
import asyncio
from pulumi.runtime import set_mocks
import pulumi
from iam_safe_defaults import iam
import warnings

# Suppress DeprecationWarning for asyncio
warnings.filterwarnings("ignore", category=DeprecationWarning)


class MyMocks(pulumi.runtime.Mocks):
    def new_resource(self, args):
        return [f"{args.name}_id", args.inputs]

    def call(self, args):
        return {}


class TestSafeIAMRole(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        set_mocks(MyMocks())

    def test_create_safe_role_properties(self):
        assume_policy = """{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": { "Service": "ec2.amazonaws.com" },
                    "Action": "sts:AssumeRole"
                }
            ]
        }"""

        async def pulumi_test():
            # Create the role using the Pulumi function
            role = iam.create_safe_role("test-role", assume_policy)
            # Define assertions on role properties
            result = await pulumi.Output.all(
                role.name,
                role.max_session_duration,
                role.force_detach_policies,
                role.assume_role_policy,
            ).apply(
                lambda args: (
                    self.assertIn("test-role", args[0]),
                    self.assertEqual(args[1], 3600),
                    self.assertTrue(args[2]),
                    self.assertIn("ec2.amazonaws.com", args[3]),
                )
            )

        # Run Pulumi stack asynchronously
        asyncio.run(pulumi.runtime.run_in_stack(pulumi_test))


if __name__ == "__main__":
    unittest.main()
