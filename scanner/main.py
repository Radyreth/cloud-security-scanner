"""
Cloud Security Scanner - Point d'entree principal.

Ce scanner analyse un environnement AWS (ou LocalStack) pour detecter
les misconfigurations de securite courantes sur S3, IAM et les Security Groups.
Il genere un rapport HTML avec les resultats et un score global.
"""

import argparse
import os
import sys
import boto3
from datetime import datetime

from scanner.checks.s3_checks import run_s3_checks
from scanner.checks.iam_checks import run_iam_checks
from scanner.checks.network_checks import run_network_checks
from scanner.report.generator import generate_html_report


def create_aws_session():
    """
    Cree une session AWS.
    Si LOCALSTACK_ENDPOINT est defini, on pointe vers LocalStack.
    Sinon, on utilise les credentials AWS classiques.
    """
    endpoint = os.getenv("LOCALSTACK_ENDPOINT", None)

    if endpoint:
        print(f"[*] Mode LocalStack detecte : {endpoint}")
        session = boto3.Session(
            aws_access_key_id="test",
            aws_secret_access_key="test",
            region_name=os.getenv("AWS_REGION", "us-east-1")
        )
        return session, endpoint
    else:
        print("[*] Mode AWS reel")
        session = boto3.Session(
            region_name=os.getenv("AWS_REGION", "us-east-1")
        )
        return session, None


def run_all_checks(session, endpoint):
    """
    Execute tous les modules de scan et collecte les resultats.
    Chaque module retourne une liste de findings (dict).
    """
    findings = []

    print("\n" + "=" * 60)
    print("  CLOUD SECURITY SCANNER")
    print("=" * 60)

    # --- Scan S3 ---
    print("\n[+] Scan des buckets S3...")
    s3_findings = run_s3_checks(session, endpoint)
    findings.extend(s3_findings)
    print(f"    {len(s3_findings)} finding(s) detecte(s)")

    # --- Scan IAM ---
    print("\n[+] Scan des utilisateurs et policies IAM...")
    iam_findings = run_iam_checks(session, endpoint)
    findings.extend(iam_findings)
    print(f"    {len(iam_findings)} finding(s) detecte(s)")

    # --- Scan Security Groups ---
    print("\n[+] Scan des Security Groups...")
    network_findings = run_network_checks(session, endpoint)
    findings.extend(network_findings)
    print(f"    {len(network_findings)} finding(s) detecte(s)")

    return findings


def calculate_score(findings):
    """
    Calcule un score de securite sur 100.
    Chaque finding reduit le score selon sa severite :
    - CRITICAL : -15 points
    - HIGH     : -10 points
    - MEDIUM   : -5 points
    - LOW      : -2 points
    Le score minimum est 0.
    """
    penalties = {
        "CRITICAL": 15,
        "HIGH": 10,
        "MEDIUM": 5,
        "LOW": 2
    }

    total_penalty = sum(
        penalties.get(f["severity"], 0) for f in findings
    )

    return max(0, 100 - total_penalty)


def parse_args():
    """Parse les arguments CLI."""
    parser = argparse.ArgumentParser(description="Cloud Security Scanner")
    parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default="CRITICAL",
        help="Minimum severity that triggers a non-zero exit code (default: CRITICAL)"
    )
    return parser.parse_args()


# Ordre de severite pour comparaison
SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def main():
    """Point d'entree principal du scanner."""
    args = parse_args()
    start_time = datetime.utcnow()

    # Creer la session AWS/LocalStack
    session, endpoint = create_aws_session()

    # Executer tous les checks
    findings = run_all_checks(session, endpoint)

    # Calculer le score
    score = calculate_score(findings)

    # Afficher le resume
    print("\n" + "=" * 60)
    critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in findings if f["severity"] == "LOW")

    print(f"  RESULTATS : {len(findings)} finding(s)")
    print(f"  Critical: {critical} | High: {high} | Medium: {medium} | Low: {low}")
    print(f"  Score de securite : {score}/100")
    print("=" * 60)

    # Generer le rapport HTML
    output_dir = os.getenv("REPORT_DIR", "reports")
    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, "security-report.html")

    generate_html_report(findings, score, start_time, report_path)
    print(f"\n[+] Rapport genere : {report_path}")

    # Code de sortie non-zero si findings >= seuil de severite
    threshold_idx = SEVERITY_ORDER.index(args.fail_on)
    failing_severities = SEVERITY_ORDER[threshold_idx:]
    failing_count = sum(
        1 for f in findings if f["severity"] in failing_severities
    )

    if failing_count > 0:
        print(f"\n[!] {failing_count} finding(s) >= {args.fail_on} - exit code 1")
        sys.exit(1)

    return findings, score


if __name__ == "__main__":
    main()
