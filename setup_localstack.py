"""
Script de setup pour creer des ressources volontairement misconfigures
dans LocalStack. Simule un environnement AWS non securise pour que
le scanner ait des choses a detecter.
"""

import json
import boto3
import os
import time


def wait_for_localstack(endpoint, retries=15, delay=3):
    """Attend que LocalStack soit pret avant de creer les ressources."""
    import urllib.request
    health_url = f"{endpoint}/_localstack/health"
    for i in range(retries):
        try:
            resp = urllib.request.urlopen(health_url, timeout=5)
            if resp.status == 200:
                print("[+] LocalStack is ready!")
                return True
        except Exception:
            print(f"[*] Waiting for LocalStack... ({i + 1}/{retries})")
            time.sleep(delay)
    raise RuntimeError("LocalStack did not start in time")


def setup_insecure_s3(s3_client):
    """Cree des buckets S3 avec des misconfigurations."""
    print("\n[+] Creating insecure S3 buckets...")

    # Bucket 1 : pas de chiffrement, pas de versioning
    s3_client.create_bucket(Bucket="data-dump-public")
    print("    - data-dump-public (no encryption, no versioning)")

    # Bucket 2 : avec versioning mais sans chiffrement
    s3_client.create_bucket(Bucket="logs-archive")
    s3_client.put_bucket_versioning(
        Bucket="logs-archive",
        VersioningConfiguration={"Status": "Enabled"}
    )
    print("    - logs-archive (versioning enabled, no encryption)")

    # Bucket 3 : correctement configure (pour montrer un PASS)
    s3_client.create_bucket(Bucket="secure-backup")
    s3_client.put_bucket_versioning(
        Bucket="secure-backup",
        VersioningConfiguration={"Status": "Enabled"}
    )
    s3_client.put_bucket_encryption(
        Bucket="secure-backup",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "AES256"
            }}]
        }
    )
    print("    - secure-backup (properly configured)")


def setup_insecure_iam(iam_client):
    """Cree des utilisateurs et policies IAM avec des misconfigurations."""
    print("\n[+] Creating insecure IAM resources...")

    # Utilisateur sans MFA
    iam_client.create_user(UserName="dev-intern")
    print("    - dev-intern (no MFA)")

    iam_client.create_user(UserName="admin-legacy")
    print("    - admin-legacy (no MFA)")

    # Policy trop permissive (wildcard)
    admin_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }]
    })
    iam_client.create_policy(
        PolicyName="full-admin-access",
        PolicyDocument=admin_policy
    )
    print("    - full-admin-access policy (Action: *)")

    # Policy correcte (pour montrer un PASS)
    s3_readonly = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": "arn:aws:s3:::secure-backup/*"
        }]
    })
    iam_client.create_policy(
        PolicyName="s3-readonly-policy",
        PolicyDocument=s3_readonly
    )
    print("    - s3-readonly-policy (properly scoped)")


def setup_insecure_security_groups(ec2_client):
    """Cree des Security Groups avec des regles dangereuses."""
    print("\n[+] Creating insecure Security Groups...")

    # SG avec SSH ouvert au monde
    sg1 = ec2_client.create_security_group(
        GroupName="web-server-sg",
        Description="Web server with SSH open to world"
    )
    ec2_client.authorize_security_group_ingress(
        GroupId=sg1["GroupId"],
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            },
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }
        ]
    )
    print(f"    - web-server-sg ({sg1['GroupId']}) : SSH + HTTPS open")

    # SG avec RDP ouvert au monde
    sg2 = ec2_client.create_security_group(
        GroupName="windows-server-sg",
        Description="Windows server with RDP open to world"
    )
    ec2_client.authorize_security_group_ingress(
        GroupId=sg2["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 3389,
            "ToPort": 3389,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
        }]
    )
    print(f"    - windows-server-sg ({sg2['GroupId']}) : RDP open")

    # SG correctement configure (pour montrer un PASS)
    sg3 = ec2_client.create_security_group(
        GroupName="internal-api-sg",
        Description="Internal API - restricted access"
    )
    ec2_client.authorize_security_group_ingress(
        GroupId=sg3["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 8080,
            "ToPort": 8080,
            "IpRanges": [{"CidrIp": "10.0.0.0/16"}]
        }]
    )
    print(f"    - internal-api-sg ({sg3['GroupId']}) : restricted")


def main():
    endpoint = os.getenv("LOCALSTACK_ENDPOINT", "http://localhost:4566")

    print("=" * 50)
    print("  LOCALSTACK SETUP - Creating insecure resources")
    print("=" * 50)

    wait_for_localstack(endpoint)

    session = boto3.Session(
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="us-east-1"
    )

    s3 = session.client("s3", endpoint_url=endpoint)
    iam = session.client("iam", endpoint_url=endpoint)
    ec2 = session.client("ec2", endpoint_url=endpoint)

    setup_insecure_s3(s3)
    setup_insecure_iam(iam)
    setup_insecure_security_groups(ec2)

    print("\n" + "=" * 50)
    print("  Setup complete! Ready to scan.")
    print("=" * 50)


if __name__ == "__main__":
    main()
