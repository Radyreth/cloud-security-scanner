"""
Checks de securite pour les Security Groups AWS (EC2/VPC).

Detecte les misconfigurations courantes :
- Port SSH (22) ouvert sur 0.0.0.0/0 (acces depuis tout internet)
- Port RDP (3389) ouvert sur 0.0.0.0/0 (acces depuis tout internet)
- Tout le trafic (port -1) ouvert sur 0.0.0.0/0
"""

# Ports dangereux a surveiller et leur description
DANGEROUS_PORTS = {
    22: {
        "service": "SSH",
        "severity": "CRITICAL",
        "description": (
            "Le port SSH (22) est ouvert au monde entier. "
            "Un attaquant peut tenter du brute-force ou exploiter "
            "des vulnerabilites OpenSSH."
        ),
        "recommendation": (
            "Restreindre l'acces SSH a des IP specifiques (votre IP "
            "ou un bastion host). Utiliser AWS Systems Manager "
            "Session Manager comme alternative sans port ouvert."
        )
    },
    3389: {
        "service": "RDP",
        "severity": "CRITICAL",
        "description": (
            "Le port RDP (3389) est ouvert au monde entier. "
            "RDP est frequemment cible par les ransomwares et "
            "le brute-force de credentials Windows."
        ),
        "recommendation": (
            "Restreindre l'acces RDP a des IP specifiques. "
            "Utiliser un VPN ou AWS Systems Manager pour "
            "l'acces distant."
        )
    },
    -1: {
        "service": "ALL TRAFFIC",
        "severity": "CRITICAL",
        "description": (
            "TOUS les ports sont ouverts au monde entier. "
            "C'est la pire configuration possible : toute "
            "la surface d'attaque est exposee."
        ),
        "recommendation": (
            "Supprimer cette regle immediatement. Appliquer "
            "le principe de moindre privilege : ouvrir "
            "uniquement les ports necessaires aux IP autorisees."
        )
    }
}

# CIDR qui representent "tout internet"
PUBLIC_CIDRS = ["0.0.0.0/0", "::/0"]


def get_ec2_client(session, endpoint):
    """Cree un client EC2, pointant vers LocalStack si necessaire."""
    if endpoint:
        return session.client("ec2", endpoint_url=endpoint)
    return session.client("ec2")


def check_security_group(sg, ec2_client):
    """
    Analyse un Security Group pour detecter les regles dangereuses.

    On verifie chaque regle entrante (ingress) :
    - Est-ce qu'elle autorise un port dangereux (22, 3389, ou tous) ?
    - Est-ce qu'elle est ouverte a 0.0.0.0/0 ou ::/0 ?

    La combinaison port dangereux + acces public = finding critique.
    """
    findings = []
    sg_id = sg["GroupId"]
    sg_name = sg.get("GroupName", "unknown")

    for rule in sg.get("IpPermissions", []):
        from_port = rule.get("FromPort", -1)
        to_port = rule.get("ToPort", -1)
        protocol = rule.get("IpProtocol", "")

        # IpProtocol "-1" = tout le trafic
        if protocol == "-1":
            from_port = -1
            to_port = -1

        # Verifier les IP ranges IPv4
        for ip_range in rule.get("IpRanges", []):
            cidr = ip_range.get("CidrIp", "")
            if cidr in PUBLIC_CIDRS:
                finding = _evaluate_port_risk(
                    sg_id, sg_name, from_port, to_port, cidr
                )
                if finding:
                    findings.append(finding)

        # Verifier les IP ranges IPv6
        for ip_range in rule.get("Ipv6Ranges", []):
            cidr = ip_range.get("CidrIpv6", "")
            if cidr in PUBLIC_CIDRS:
                finding = _evaluate_port_risk(
                    sg_id, sg_name, from_port, to_port, cidr
                )
                if finding:
                    findings.append(finding)

    return findings


def _evaluate_port_risk(sg_id, sg_name, from_port, to_port, cidr):
    """
    Evalue le risque d'une regle basee sur le port et le CIDR.
    Retourne un finding si le port est dans la liste dangereuse,
    ou si c'est un range qui inclut un port dangereux.
    """
    # Cas 1 : tout le trafic (protocol -1)
    if from_port == -1 and to_port == -1:
        port_info = DANGEROUS_PORTS[-1]
        return _build_finding(sg_id, sg_name, -1, cidr, port_info)

    # Cas 2 : port specifique dans la liste
    for port, port_info in DANGEROUS_PORTS.items():
        if port == -1:
            continue
        # Verifier si le port dangereux est dans le range autorise
        if from_port <= port <= to_port:
            return _build_finding(sg_id, sg_name, port, cidr, port_info)

    return None


def _build_finding(sg_id, sg_name, port, cidr, port_info):
    """Construit un finding formate pour un port dangereux."""
    port_display = "ALL" if port == -1 else str(port)
    return {
        "resource": f"ec2:sg/{sg_id} ({sg_name})",
        "severity": port_info["severity"],
        "check": f"Security Group - Port {port_display}",
        "description": (
            f"Security Group '{sg_name}' ({sg_id}) : "
            f"{port_info['description']} "
            f"(ouvert sur {cidr})"
        ),
        "recommendation": port_info["recommendation"]
    }


def run_network_checks(session, endpoint=None):
    """
    Execute tous les checks reseau (Security Groups).
    Retourne une liste de findings.
    """
    ec2_client = get_ec2_client(session, endpoint)
    findings = []

    try:
        response = ec2_client.describe_security_groups()
        security_groups = response.get("SecurityGroups", [])
    except Exception as e:
        print(f"    [!] Erreur lors du listing des Security Groups : {e}")
        return findings

    for sg in security_groups:
        sg_findings = check_security_group(sg, ec2_client)
        findings.extend(sg_findings)

    return findings
