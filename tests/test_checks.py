"""
Tests unitaires pour le Cloud Security Scanner.

On utilise moto pour mocker les services AWS (S3, IAM, EC2).
Cela permet de tester sans connexion AWS ni LocalStack.
"""

import json
import pytest
import boto3
from moto import mock_aws

from scanner.checks.s3_checks import run_s3_checks
from scanner.checks.iam_checks import run_iam_checks
from scanner.checks.network_checks import run_network_checks
from scanner.main import calculate_score


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def aws_session():
    """Cree une session AWS mockee."""
    return boto3.Session(
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        region_name="us-east-1"
    )


# =============================================================================
# Tests S3
# =============================================================================

class TestS3Checks:
    @mock_aws
    def test_bucket_without_versioning(self, aws_session):
        """Un bucket sans versioning doit generer un finding MEDIUM."""
        s3 = aws_session.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-bucket")

        findings = run_s3_checks(aws_session)
        versioning_findings = [
            f for f in findings if f["check"] == "S3 Versioning"
        ]
        assert len(versioning_findings) >= 1
        assert versioning_findings[0]["severity"] == "MEDIUM"

    @mock_aws
    def test_bucket_with_versioning(self, aws_session):
        """Un bucket avec versioning ne doit pas generer de finding versioning."""
        s3 = aws_session.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="secure-bucket")
        s3.put_bucket_versioning(
            Bucket="secure-bucket",
            VersioningConfiguration={"Status": "Enabled"}
        )

        findings = run_s3_checks(aws_session)
        versioning_findings = [
            f for f in findings if f["check"] == "S3 Versioning"
        ]
        assert len(versioning_findings) == 0

    @mock_aws
    def test_bucket_public_access_finding(self, aws_session):
        """Un bucket sans Block Public Access doit generer un finding CRITICAL."""
        s3 = aws_session.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="public-bucket")

        findings = run_s3_checks(aws_session)
        public_findings = [
            f for f in findings if f["check"] == "S3 Public Access"
        ]
        assert len(public_findings) >= 1
        assert public_findings[0]["severity"] == "CRITICAL"

    @mock_aws
    def test_no_buckets_returns_empty(self, aws_session):
        """Sans buckets, le scanner ne doit retourner aucun finding."""
        findings = run_s3_checks(aws_session)
        assert findings == []


# =============================================================================
# Tests IAM
# =============================================================================

class TestIAMChecks:
    @mock_aws
    def test_user_without_mfa(self, aws_session):
        """Un utilisateur sans MFA doit generer un finding CRITICAL."""
        iam = aws_session.client("iam", region_name="us-east-1")
        iam.create_user(UserName="insecure-user")

        findings = run_iam_checks(aws_session)
        mfa_findings = [f for f in findings if f["check"] == "IAM MFA"]
        assert len(mfa_findings) >= 1
        assert mfa_findings[0]["severity"] == "CRITICAL"
        assert "insecure-user" in mfa_findings[0]["resource"]

    @mock_aws
    def test_wildcard_policy(self, aws_session):
        """Une policy avec Action: * doit generer un finding HIGH."""
        iam = aws_session.client("iam", region_name="us-east-1")

        policy_doc = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }]
        })

        iam.create_policy(
            PolicyName="admin-full-access",
            PolicyDocument=policy_doc
        )

        findings = run_iam_checks(aws_session)
        wildcard_findings = [
            f for f in findings if f["check"] == "IAM Wildcard Policy"
        ]
        assert len(wildcard_findings) >= 1
        assert wildcard_findings[0]["severity"] == "HIGH"

    @mock_aws
    def test_specific_policy_no_finding(self, aws_session):
        """Une policy avec des permissions specifiques ne doit pas trigger."""
        iam = aws_session.client("iam", region_name="us-east-1")

        policy_doc = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": "arn:aws:s3:::my-bucket/*"
            }]
        })

        iam.create_policy(
            PolicyName="s3-readonly",
            PolicyDocument=policy_doc
        )

        findings = run_iam_checks(aws_session)
        wildcard_findings = [
            f for f in findings if f["check"] == "IAM Wildcard Policy"
        ]
        assert len(wildcard_findings) == 0


# =============================================================================
# Tests Security Groups
# =============================================================================

class TestNetworkChecks:
    @mock_aws
    def test_ssh_open_to_world(self, aws_session):
        """Un SG avec SSH ouvert sur 0.0.0.0/0 doit generer un CRITICAL."""
        ec2 = aws_session.client("ec2", region_name="us-east-1")

        sg = ec2.create_security_group(
            GroupName="insecure-sg",
            Description="Test SG with SSH open"
        )

        ec2.authorize_security_group_ingress(
            GroupId=sg["GroupId"],
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }]
        )

        findings = run_network_checks(aws_session)
        ssh_findings = [
            f for f in findings if "22" in f["check"]
        ]
        assert len(ssh_findings) >= 1
        assert ssh_findings[0]["severity"] == "CRITICAL"

    @mock_aws
    def test_rdp_open_to_world(self, aws_session):
        """Un SG avec RDP ouvert sur 0.0.0.0/0 doit generer un CRITICAL."""
        ec2 = aws_session.client("ec2", region_name="us-east-1")

        sg = ec2.create_security_group(
            GroupName="rdp-sg",
            Description="Test SG with RDP open"
        )

        ec2.authorize_security_group_ingress(
            GroupId=sg["GroupId"],
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 3389,
                "ToPort": 3389,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }]
        )

        findings = run_network_checks(aws_session)
        rdp_findings = [
            f for f in findings if "3389" in f["check"]
        ]
        assert len(rdp_findings) >= 1

    @mock_aws
    def test_restricted_ssh_no_finding(self, aws_session):
        """Un SG avec SSH restreint a une IP specifique ne doit pas trigger."""
        ec2 = aws_session.client("ec2", region_name="us-east-1")

        sg = ec2.create_security_group(
            GroupName="secure-sg",
            Description="Test SG with restricted SSH"
        )

        ec2.authorize_security_group_ingress(
            GroupId=sg["GroupId"],
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "10.0.0.1/32"}]
            }]
        )

        findings = run_network_checks(aws_session)
        ssh_findings = [
            f for f in findings if "22" in f.get("check", "")
        ]
        assert len(ssh_findings) == 0


# =============================================================================
# Tests Score
# =============================================================================

class TestScoring:
    def test_perfect_score(self):
        """Sans findings, le score doit etre 100."""
        assert calculate_score([]) == 100

    def test_critical_reduces_score(self):
        """Un finding CRITICAL doit reduire le score de 15."""
        findings = [{"severity": "CRITICAL"}]
        assert calculate_score(findings) == 85

    def test_mixed_findings(self):
        """Tester le calcul avec plusieurs severites."""
        findings = [
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "MEDIUM"}
        ]
        # 100 - 15 - 10 - 5 = 70
        assert calculate_score(findings) == 70

    def test_score_minimum_is_zero(self):
        """Le score ne peut pas etre negatif."""
        findings = [{"severity": "CRITICAL"}] * 10
        assert calculate_score(findings) == 0
