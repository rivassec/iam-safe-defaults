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
            # Opt out of boundary requirement: this test checks resource shape only.
            role = iam.create_safe_role(
                "test-role", assume_policy, allow_no_boundary=True
            )
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


class TestSafeDefaultsGuards(unittest.TestCase):
    """Non-Pulumi tests for the four safe-default guards."""

    trust_policy_ok = """{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }
        ]
    }"""

    trust_policy_wildcard = """{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sts:AssumeRole"
            }
        ]
    }"""

    def test_create_safe_role_requires_boundary(self):
        with self.assertRaisesRegex(ValueError, "permissions_boundary"):
            iam.create_safe_role("r", self.trust_policy_ok)

    def test_create_safe_role_rejects_wildcard_principal(self):
        with self.assertRaisesRegex(ValueError, "wildcard Principal"):
            iam.create_safe_role(
                "r",
                self.trust_policy_wildcard,
                allow_no_boundary=True,
            )

    # --- fail-loud guarantee: an un-verifiable trust policy must NOT silently
    # pass (the detector used to swallow json.loads errors and return False,
    # so a malformed or Output-typed wildcard trust policy was created without
    # raising -- a fail-OPEN in a library whose whole thesis is "fail loud").
    def test_wildcard_principal_check_fails_loud_on_malformed_json(self):
        malformed = '{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"}'
        with self.assertRaises(ValueError):
            iam._assume_policy_has_wildcard_principal(malformed)

    def test_wildcard_principal_check_fails_loud_on_non_string(self):
        # e.g. a pulumi.Output-typed trust policy: json.loads raises TypeError,
        # which must surface, not be swallowed into a "no wildcard" verdict.
        with self.assertRaises(TypeError):
            iam._assume_policy_has_wildcard_principal({"Statement": []})

    def test_create_safe_role_fails_loud_on_unparseable_trust_policy(self):
        with self.assertRaises((ValueError, TypeError)):
            iam.create_safe_role("r", '{"broken": ', allow_no_boundary=True)

    def test_create_safe_role_opt_out_skips_unverifiable_trust_policy(self):
        # The explicit opt-out must still bypass the check entirely: an
        # un-verifiable policy with allow_wildcard_principal=True does not raise
        # the wildcard/type guard (caller took responsibility).
        try:
            iam.create_safe_role(
                "r",
                '{"broken": ',
                allow_no_boundary=True,
                allow_wildcard_principal=True,
            )
        except (ValueError, TypeError) as exc:
            self.fail(f"opt-out should skip trust-policy verification, raised: {exc}")
        except Exception:
            # Any non-guard error (e.g. Pulumi resource construction outside a
            # stack) is fine -- it proves the guard did not reject the input.
            pass

    def test_is_policy_overly_permissive_catches_wildcard_suffix(self):
        doc = {
            "Statement": [
                {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::b"}
            ]
        }
        self.assertTrue(iam.is_policy_overly_permissive(doc))

    def test_is_policy_overly_permissive_catches_bare_wildcard(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        self.assertTrue(iam.is_policy_overly_permissive(doc))

    def test_is_policy_overly_permissive_catches_not_action(self):
        doc = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "NotAction": "iam:DeleteUser",
                    "Resource": "arn:aws:iam::*:user/*",
                }
            ]
        }
        self.assertTrue(iam.is_policy_overly_permissive(doc))

    def test_is_policy_overly_permissive_allows_narrow_policy(self):
        doc = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::b/*",
                }
            ]
        }
        self.assertFalse(iam.is_policy_overly_permissive(doc))

    def test_generate_safe_policy_rejects_admin(self):
        with self.assertRaisesRegex(ValueError, "admin-equivalent"):
            iam.generate_safe_policy(actions=["*"], resources=["arn:aws:s3:::b"])

    def test_generate_safe_policy_rejects_wildcard_suffix(self):
        with self.assertRaisesRegex(ValueError, "wildcard-suffix"):
            iam.generate_safe_policy(actions=["s3:*"], resources=["arn:aws:s3:::b"])

    def test_generate_safe_policy_rejects_wildcard_resource(self):
        with self.assertRaisesRegex(ValueError, "Resource: '\\*'"):
            iam.generate_safe_policy(actions=["s3:GetObject"], resources=["*"])

    def test_generate_safe_policy_happy_path(self):
        doc = iam.generate_safe_policy(
            actions=["s3:GetObject"], resources=["arn:aws:s3:::b/*"]
        )
        self.assertEqual(doc["Statement"][0]["Action"], ["s3:GetObject"])

    def test_generate_safe_policy_allow_wildcard_opt_out(self):
        # Opt-out intentionally produces a doc that is_policy_overly_permissive flags.
        doc = iam.generate_safe_policy(
            actions=["*"], resources=["*"], allow_wildcard=True
        )
        self.assertTrue(iam.is_policy_overly_permissive(doc))


if __name__ == "__main__":
    unittest.main()
