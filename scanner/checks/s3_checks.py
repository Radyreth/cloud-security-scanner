"""
Checks de securite pour Amazon S3.

Detecte les misconfigurations courantes :
- Buckets avec acces public (Block Public Access desactive)
- Buckets sans chiffrement cote serveur (SSE)
- Buckets sans versioning (risque de perte de donnees)
"""


def get_s3_client(session, endpoint):
    """Cree un client S3, pointant vers LocalStack si necessaire."""
    if endpoint:
        return session.client("s3", endpoint_url=endpoint)
    return session.client("s3")


def check_public_access(s3_client, bucket_name):
    """
    Verifie si le Block Public Access est active sur un bucket.

    AWS recommande de TOUJOURS activer Block Public Access sauf
    si le bucket doit explicitement servir du contenu public (site statique).
    Un bucket public peut exposer des donnees sensibles a tout internet.

    Reference : CIS AWS Benchmark 2.1.5
    """
    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        config = response["PublicAccessBlockConfiguration"]

        # Verifier que TOUS les flags sont actives
        all_blocked = all([
            config.get("BlockPublicAcls", False),
            config.get("IgnorePublicAcls", False),
            config.get("BlockPublicPolicy", False),
            config.get("RestrictPublicBuckets", False)
        ])

        if not all_blocked:
            return {
                "resource": f"s3://{bucket_name}",
                "severity": "CRITICAL",
                "check": "S3 Public Access",
                "description": (
                    f"Le bucket '{bucket_name}' n'a pas tous les flags "
                    "Block Public Access actives. Des donnees pourraient "
                    "etre exposees publiquement."
                ),
                "recommendation": (
                    "Activer tous les flags Block Public Access : "
                    "BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, "
                    "RestrictPublicBuckets."
                )
            }
    except s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
        # Pas de config = pas de protection = critique
        return {
            "resource": f"s3://{bucket_name}",
            "severity": "CRITICAL",
            "check": "S3 Public Access",
            "description": (
                f"Le bucket '{bucket_name}' n'a aucune configuration "
                "Block Public Access. Il est potentiellement accessible "
                "depuis internet."
            ),
            "recommendation": (
                "Configurer Block Public Access sur le bucket avec "
                "tous les flags actives."
            )
        }
    except Exception:
        pass

    return None


def check_encryption(s3_client, bucket_name):
    """
    Verifie si le chiffrement cote serveur (SSE) est active.

    Sans chiffrement, les donnees sont stockees en clair sur les disques AWS.
    En cas de fuite physique ou d'acces non autorise, les donnees
    sont lisibles sans dechiffrement.

    Reference : CIS AWS Benchmark 2.1.1
    """
    try:
        s3_client.get_bucket_encryption(Bucket=bucket_name)
        # Si pas d'exception, le chiffrement est configure
        return None
    except s3_client.exceptions.ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "ServerSideEncryptionConfigurationNotFoundError":
            return {
                "resource": f"s3://{bucket_name}",
                "severity": "HIGH",
                "check": "S3 Encryption",
                "description": (
                    f"Le bucket '{bucket_name}' n'a pas de chiffrement "
                    "cote serveur (SSE) active. Les donnees sont stockees "
                    "en clair."
                ),
                "recommendation": (
                    "Activer le chiffrement SSE-S3 (AES-256) ou "
                    "SSE-KMS sur le bucket."
                )
            }
    except Exception:
        pass

    return None


def check_versioning(s3_client, bucket_name):
    """
    Verifie si le versioning est active sur le bucket.

    Le versioning permet de conserver toutes les versions d'un objet.
    Sans versioning, un fichier supprime ou ecrase est perdu definitivement.
    C'est aussi une protection contre les ransomwares.

    Reference : CIS AWS Benchmark 2.1.3
    """
    try:
        response = s3_client.get_bucket_versioning(Bucket=bucket_name)
        status = response.get("Status", "Disabled")

        if status != "Enabled":
            return {
                "resource": f"s3://{bucket_name}",
                "severity": "MEDIUM",
                "check": "S3 Versioning",
                "description": (
                    f"Le bucket '{bucket_name}' n'a pas le versioning "
                    "active. Les donnees supprimees ou ecrasees ne "
                    "peuvent pas etre recuperees."
                ),
                "recommendation": (
                    "Activer le versioning sur le bucket pour proteger "
                    "contre les suppressions accidentelles et les "
                    "ransomwares."
                )
            }
    except Exception:
        pass

    return None


def run_s3_checks(session, endpoint=None):
    """
    Execute tous les checks S3 sur tous les buckets du compte.
    Retourne une liste de findings.
    """
    s3_client = get_s3_client(session, endpoint)
    findings = []

    try:
        response = s3_client.list_buckets()
        buckets = response.get("Buckets", [])
    except Exception as e:
        print(f"    [!] Erreur lors du listing S3 : {e}")
        return findings

    for bucket in buckets:
        name = bucket["Name"]

        # Check 1 : Acces public
        finding = check_public_access(s3_client, name)
        if finding:
            findings.append(finding)

        # Check 2 : Chiffrement
        finding = check_encryption(s3_client, name)
        if finding:
            findings.append(finding)

        # Check 3 : Versioning
        finding = check_versioning(s3_client, name)
        if finding:
            findings.append(finding)

    return findings
