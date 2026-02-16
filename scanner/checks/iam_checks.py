"""
Checks de securite pour AWS IAM.

Detecte les misconfigurations courantes :
- Utilisateurs sans MFA active (risque de compromission du compte)
- Policies avec des permissions wildcard (*) trop permissives
"""

import json


def get_iam_client(session, endpoint):
    """Cree un client IAM, pointant vers LocalStack si necessaire."""
    if endpoint:
        return session.client("iam", endpoint_url=endpoint)
    return session.client("iam")


def check_mfa_enabled(iam_client):
    """
    Verifie que chaque utilisateur IAM a le MFA active.

    Le MFA (Multi-Factor Authentication) est la premiere ligne de defense
    contre le vol de credentials. Sans MFA, un mot de passe vole ou fuite
    suffit pour compromettre le compte.

    Reference : CIS AWS Benchmark 1.10
    """
    findings = []

    try:
        users = iam_client.list_users().get("Users", [])
    except Exception as e:
        print(f"    [!] Erreur lors du listing IAM users : {e}")
        return findings

    for user in users:
        username = user["UserName"]

        try:
            mfa_devices = iam_client.list_mfa_devices(
                UserName=username
            ).get("MFADevices", [])

            if len(mfa_devices) == 0:
                findings.append({
                    "resource": f"iam:user/{username}",
                    "severity": "CRITICAL",
                    "check": "IAM MFA",
                    "description": (
                        f"L'utilisateur '{username}' n'a pas de MFA "
                        "active. En cas de fuite du mot de passe, "
                        "le compte est directement compromis."
                    ),
                    "recommendation": (
                        "Activer le MFA (virtual MFA ou hardware token) "
                        "pour cet utilisateur. Appliquer une policy "
                        "qui force le MFA pour toutes les actions."
                    )
                })
        except Exception:
            pass

    return findings


def check_wildcard_policies(iam_client):
    """
    Detecte les policies IAM avec des permissions wildcard (Action: *).

    Une policy avec Action: * donne un acces administrateur complet.
    C'est une violation du principe de moindre privilege.
    Si un attaquant compromet un role avec *, il controle tout le compte AWS.

    Reference : CIS AWS Benchmark 1.16
    """
    findings = []

    try:
        # Recuperer toutes les policies customer-managed
        paginator = iam_client.get_paginator("list_policies")
        pages = paginator.paginate(Scope="Local")
    except Exception as e:
        print(f"    [!] Erreur lors du listing des policies : {e}")
        return findings

    for page in pages:
        for policy in page.get("Policies", []):
            policy_arn = policy["Arn"]
            policy_name = policy["PolicyName"]

            try:
                # Recuperer la version active de la policy
                version_id = policy["DefaultVersionId"]
                policy_version = iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=version_id
                )

                document = policy_version["PolicyVersion"]["Document"]

                # Le document peut etre un string JSON ou un dict
                if isinstance(document, str):
                    document = json.loads(document)

                # Parcourir les statements pour chercher Action: *
                statements = document.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]

                for statement in statements:
                    if statement.get("Effect") != "Allow":
                        continue

                    actions = statement.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]

                    if "*" in actions:
                        findings.append({
                            "resource": f"iam:policy/{policy_name}",
                            "severity": "HIGH",
                            "check": "IAM Wildcard Policy",
                            "description": (
                                f"La policy '{policy_name}' contient "
                                "Action: * (permissions administrateur). "
                                "Cela viole le principe de moindre "
                                "privilege."
                            ),
                            "recommendation": (
                                "Remplacer Action: * par des permissions "
                                "specifiques. Utiliser IAM Access Analyzer "
                                "pour identifier les permissions reellement "
                                "utilisees."
                            )
                        })
                        break  # Un finding par policy suffit

            except Exception:
                pass

    return findings


def run_iam_checks(session, endpoint=None):
    """
    Execute tous les checks IAM.
    Retourne une liste de findings.
    """
    iam_client = get_iam_client(session, endpoint)
    findings = []

    # Check 1 : MFA
    findings.extend(check_mfa_enabled(iam_client))

    # Check 2 : Wildcard policies
    findings.extend(check_wildcard_policies(iam_client))

    return findings
