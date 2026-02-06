"""
Generateur de rapport HTML pour le Cloud Security Scanner.

Produit un rapport visuel avec :
- Score global de securite (jauge coloree)
- Tableau des findings avec couleurs par severite
- Statistiques par categorie
- Date et duree du scan
"""

from datetime import datetime


# Couleurs CSS par niveau de severite
SEVERITY_COLORS = {
    "CRITICAL": "#dc3545",   # Rouge
    "HIGH": "#fd7e14",       # Orange
    "MEDIUM": "#ffc107",     # Jaune
    "LOW": "#28a745"         # Vert
}


def _get_score_color(score):
    """Retourne une couleur CSS en fonction du score."""
    if score >= 80:
        return "#28a745"  # Vert
    elif score >= 60:
        return "#ffc107"  # Jaune
    elif score >= 40:
        return "#fd7e14"  # Orange
    else:
        return "#dc3545"  # Rouge


def _get_score_label(score):
    """Retourne un label textuel pour le score."""
    if score >= 80:
        return "BON"
    elif score >= 60:
        return "MOYEN"
    elif score >= 40:
        return "FAIBLE"
    else:
        return "CRITIQUE"


def generate_html_report(findings, score, start_time, output_path):
    """
    Genere un rapport HTML complet a partir des findings.

    Args:
        findings: Liste de dicts avec resource, severity, description, etc.
        score: Score de securite sur 100
        start_time: datetime du debut du scan
        output_path: Chemin du fichier HTML de sortie
    """
    end_time = datetime.utcnow()
    duration = (end_time - start_time).total_seconds()
    score_color = _get_score_color(score)
    score_label = _get_score_label(score)

    # Compter par severite
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW")
        counts[sev] = counts.get(sev, 0) + 1

    # Generer les lignes du tableau
    rows_html = ""
    for f in sorted(findings, key=lambda x: (
        ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(x["severity"])
    )):
        color = SEVERITY_COLORS.get(f["severity"], "#6c757d")
        rows_html += f"""
        <tr>
            <td><code>{f['resource']}</code></td>
            <td><span class="badge" style="background:{color}">
                {f['severity']}</span></td>
            <td>{f['check']}</td>
            <td>{f['description']}</td>
            <td>{f['recommendation']}</td>
        </tr>"""

    # Template HTML complet
    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloud Security Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI',
                         Roboto, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{
            color: #58a6ff;
            font-size: 1.8rem;
            margin-bottom: 0.5rem;
        }}
        .subtitle {{
            color: #8b949e;
            margin-bottom: 2rem;
        }}

        /* Score Card */
        .score-card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 2rem;
            text-align: center;
            margin-bottom: 2rem;
        }}
        .score-value {{
            font-size: 4rem;
            font-weight: bold;
            color: {score_color};
        }}
        .score-label {{
            font-size: 1.2rem;
            color: {score_color};
            margin-top: 0.5rem;
        }}

        /* Stats */
        .stats {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
        }}
        .stat-count {{
            font-size: 2rem;
            font-weight: bold;
        }}
        .stat-label {{
            color: #8b949e;
            margin-top: 0.3rem;
        }}

        /* Table */
        .findings-table {{
            width: 100%;
            border-collapse: collapse;
            background: #161b22;
            border-radius: 8px;
            overflow: hidden;
        }}
        .findings-table th {{
            background: #21262d;
            color: #58a6ff;
            padding: 12px 16px;
            text-align: left;
            font-weight: 600;
        }}
        .findings-table td {{
            padding: 12px 16px;
            border-top: 1px solid #30363d;
            vertical-align: top;
        }}
        .findings-table tr:hover {{
            background: #1c2128;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            color: white;
            font-weight: 600;
            font-size: 0.75rem;
        }}
        code {{
            background: #21262d;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.85rem;
            color: #f0883e;
        }}

        /* Footer */
        .footer {{
            text-align: center;
            color: #484f58;
            margin-top: 2rem;
            padding-top: 1rem;
            border-top: 1px solid #21262d;
        }}

        /* No findings */
        .no-findings {{
            text-align: center;
            padding: 3rem;
            color: #28a745;
            font-size: 1.2rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Cloud Security Scan Report</h1>
        <p class="subtitle">
            Scan effectue le {end_time.strftime('%d/%m/%Y a %H:%M:%S UTC')}
            | Duree : {duration:.1f}s
            | {len(findings)} finding(s)
        </p>

        <div class="score-card">
            <div class="score-value">{score}/100</div>
            <div class="score-label">Niveau de securite : {score_label}</div>
        </div>

        <div class="stats">
            <div class="stat-card">
                <div class="stat-count" style="color:{SEVERITY_COLORS['CRITICAL']}">
                    {counts['CRITICAL']}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-count" style="color:{SEVERITY_COLORS['HIGH']}">
                    {counts['HIGH']}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card">
                <div class="stat-count" style="color:{SEVERITY_COLORS['MEDIUM']}">
                    {counts['MEDIUM']}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card">
                <div class="stat-count" style="color:{SEVERITY_COLORS['LOW']}">
                    {counts['LOW']}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>

        {"<div class='no-findings'>Aucune misconfiguration detectee.</div>"
         if not findings else f'''
        <table class="findings-table">
            <thead>
                <tr>
                    <th>Ressource</th>
                    <th>Severite</th>
                    <th>Check</th>
                    <th>Description</th>
                    <th>Recommandation</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>
        '''}

        <div class="footer">
            Cloud Security Scanner v1.0 | Generated automatically
        </div>
    </div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
