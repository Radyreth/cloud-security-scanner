# Cloud Security Scanner

![Security Scan](https://github.com/Radyreth/cloud-security-scanner/actions/workflows/security-scan.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11-blue.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![AWS](https://img.shields.io/badge/AWS-LocalStack-orange.svg)

> Outil de detection automatique des misconfigurations de securite AWS.
> Scanne S3, IAM et les Security Groups, puis genere un rapport HTML avec un score de securite.

---

## Architecture

```
+------------------+       +-------------------+       +------------------+
|                  |       |                   |       |                  |
|   GitHub Push    +------>+  GitHub Actions   +------>+  Security Report |
|                  |       |  CI Pipeline      |       |  (HTML Artifact) |
+------------------+       +--------+----------+       +------------------+
                                    |
                           +--------v----------+
                           |                   |
                           |    LocalStack     |
                           |  (AWS Simulator)  |
                           |                   |
                           +--------+----------+
                                    |
                  +-----------------+-----------------+
                  |                 |                 |
           +------v------+  +------v------+  +------v------+
           |             |  |             |  |             |
           |  S3 Checks  |  | IAM Checks  |  |  Network   |
           |             |  |             |  |  Checks    |
           |  - Public   |  |  - No MFA   |  |  - SSH 22  |
           |  - No SSE   |  |  - Action:* |  |  - RDP 3389|
           |  - No Ver.  |  |             |  |            |
           +------+------+  +------+------+  +------+-----+
                  |                 |                 |
                  +--------+--------+---------+------+
                           |
                    +------v------+
                    |             |
                    |   Report    |
                    |  Generator  |
                    |  (HTML)     |
                    +-------------+
```

## Misconfigurations detectees

| Check | Severite | Description |
|-------|----------|-------------|
| **S3 Public Access** | CRITICAL | Bucket sans Block Public Access - donnees exposees sur internet |
| **S3 Encryption** | HIGH | Bucket sans chiffrement SSE - donnees en clair sur disque |
| **S3 Versioning** | MEDIUM | Bucket sans versioning - pas de protection contre suppression |
| **IAM No MFA** | CRITICAL | Utilisateur sans MFA - vulnerable au vol de credentials |
| **IAM Wildcard** | HIGH | Policy avec Action: * - violation du moindre privilege |
| **SG SSH Open** | CRITICAL | Port 22 ouvert sur 0.0.0.0/0 - brute-force possible |
| **SG RDP Open** | CRITICAL | Port 3389 ouvert sur 0.0.0.0/0 - cible des ransomwares |

## Comment ca marche

### 1. Simulation AWS avec LocalStack
[LocalStack](https://localstack.cloud) simule les services AWS en local via Docker.
Le script `setup_localstack.py` cree des ressources **volontairement misconfigures** :
buckets S3 publics, utilisateurs sans MFA, security groups ouverts.

### 2. Execution des checks
Le scanner parcourt chaque service et compare la configuration aux bonnes pratiques :
- **CIS AWS Benchmark** pour les regles de securite
- **Principe de moindre privilege** pour IAM
- **Defense en profondeur** pour le chiffrement et le reseau

### 3. Scoring
Chaque finding reduit le score selon sa severite :
| Severite | Penalite |
|----------|----------|
| CRITICAL | -15 pts |
| HIGH | -10 pts |
| MEDIUM | -5 pts |
| LOW | -2 pts |

### 4. Rapport HTML
Un rapport visuel est genere avec un tableau de findings, des couleurs par severite,
et un score global. Il est sauvegarde comme artifact GitHub Actions.

## Quick start

### Avec Docker Compose (recommande)
```bash
# Lance LocalStack, cree les misconfigurations, et scanne
docker compose up --build

# Le rapport est dans ./reports/security-report.html
```

### Sans Docker
```bash
pip install -r requirements.txt

# Lancer les tests (mock AWS avec moto)
pytest tests/ -v

# Avec un LocalStack deja lance :
export LOCALSTACK_ENDPOINT=http://localhost:4566
python setup_localstack.py
python -m scanner.main
```

## Pipeline CI

Le workflow GitHub Actions execute a chaque push :
```
push to main
      |
      v
  [LINT] -----> flake8 (code quality)
      |
      v
  [TEST] -----> pytest + moto (15 tests, mock AWS)
      |
      v
  [SCAN] -----> LocalStack + full scan
      |
      v
  [ARTIFACT] -> rapport HTML telechargeable
```

## Exemple de rapport

Le rapport HTML genere ressemble a ceci :

```
+------------------------------------------+
|        Score de securite : 25/100        |
|              [CRITIQUE]                   |
+------------------------------------------+
|  CRITICAL: 4  |  HIGH: 2  |  MEDIUM: 1  |
+------------------------------------------+
|                                          |
|  s3://data-dump  | CRITICAL | No public  |
|  iam:user/admin  | CRITICAL | No MFA     |
|  ec2:sg/sg-xxx   | CRITICAL | SSH open   |
|  ...                                     |
+------------------------------------------+
```

## References securite

- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/)
- [OWASP Cloud Security](https://owasp.org/www-project-cloud-security/)

## Tech stack

| Outil | Role | Cout |
|-------|------|------|
| Python / boto3 | Scanner & AWS SDK | Free |
| LocalStack | Simulation AWS locale | Free |
| moto | Mock AWS pour les tests | Free |
| GitHub Actions | CI/CD pipeline | Free |
| Docker Compose | Orchestration locale | Free |

## License

MIT
