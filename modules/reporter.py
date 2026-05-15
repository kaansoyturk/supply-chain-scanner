from datetime import datetime
import json
import os

COLORS = {
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "BLUE": "\033[94m",
    "CYAN": "\033[96m",
    "WHITE": "\033[97m",
    "RESET": "\033[0m",
    "BOLD": "\033[1m"
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

def generate_report(npm_results=None, pip_results=None, docker_results=None):
    c = COLORS

    all_vulnerabilities = []

    # NPM bulgular
    if npm_results:
        for pkg in npm_results.get("packages", []):
            for vuln in pkg.get("vulnerabilities", []):
                vuln["source"] = f"NPM: {pkg['package']}"
                all_vulnerabilities.append(vuln)

    # PIP bulgular
    if pip_results:
        for pkg in pip_results.get("packages", []):
            for vuln in pkg.get("vulnerabilities", []):
                vuln["source"] = f"PIP: {pkg['package']}"
                all_vulnerabilities.append(vuln)

    # Docker bulgular
    if docker_results:
        for vuln in docker_results.get("vulnerabilities", []):
            vuln["source"] = "Docker"
            all_vulnerabilities.append(vuln)

    # Severity'e göre sırala
    all_vulnerabilities.sort(
        key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 4)
    )

    # Risk skoru
    risk_score = 0
    for v in all_vulnerabilities:
        sev = v.get("severity", "INFO")
        if sev == "CRITICAL": risk_score += 30
        elif sev == "HIGH": risk_score += 20
        elif sev == "MEDIUM": risk_score += 10
        elif sev == "LOW": risk_score += 5
    risk_score = min(100, risk_score)

    if risk_score >= 70:
        risk_level = "CRITICAL"
        risk_color = c["RED"]
    elif risk_score >= 40:
        risk_level = "HIGH"
        risk_color = c["YELLOW"]
    elif risk_score >= 20:
        risk_level = "MEDIUM"
        risk_color = c["BLUE"]
    else:
        risk_level = "LOW"
        risk_color = c["GREEN"]

    critical = [v for v in all_vulnerabilities if v.get("severity") == "CRITICAL"]
    high = [v for v in all_vulnerabilities if v.get("severity") == "HIGH"]
    medium = [v for v in all_vulnerabilities if v.get("severity") == "MEDIUM"]
    low = [v for v in all_vulnerabilities if v.get("severity") == "LOW"]

    # Rapor başlığı
    print(f"\n{c['CYAN']}{'═' * 65}{c['RESET']}")
    print(f"{c['CYAN']}{c['BOLD']}  SUPPLY CHAIN SCANNER — GÜVENLİK RAPORU{c['RESET']}")
    print(f"{c['CYAN']}{'═' * 65}{c['RESET']}")
    print(f"  {c['WHITE']}Tarih    : {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}{c['RESET']}")
    print(f"  {risk_color}Risk     : {risk_score}/100 — {risk_level}{c['RESET']}")
    print(f"  {c['WHITE']}Bulgular : {len(all_vulnerabilities)}{c['RESET']}")
    print(f"\n  {c['RED']}Critical: {len(critical)}{c['RESET']}  "
          f"{c['YELLOW']}High: {len(high)}{c['RESET']}  "
          f"{c['BLUE']}Medium: {len(medium)}{c['RESET']}  "
          f"{c['GREEN']}Low: {len(low)}{c['RESET']}")
    print(f"{c['CYAN']}{'─' * 65}{c['RESET']}\n")

    if critical:
        print(f"  {c['RED']}{c['BOLD']}🔴 KRİTİK BULGULAR ({len(critical)}){c['RESET']}")
        print(f"  {'─' * 50}")
        for v in critical:
            print(f"  {c['RED']}  ✗ [{v.get('type')}] {v.get('source', '')}{c['RESET']}")
            print(f"    {c['WHITE']}{v.get('description', '')}{c['RESET']}")
        print()

    if high:
        print(f"  {c['YELLOW']}{c['BOLD']}🟠 YÜKSEK BULGULAR ({len(high)}){c['RESET']}")
        print(f"  {'─' * 50}")
        for v in high:
            print(f"  {c['YELLOW']}  ⚠ [{v.get('type')}] {v.get('source', '')}{c['RESET']}")
            print(f"    {c['WHITE']}{v.get('description', '')}{c['RESET']}")
        print()

    if medium:
        print(f"  {c['BLUE']}{c['BOLD']}🟡 ORTA BULGULAR ({len(medium)}){c['RESET']}")
        print(f"  {'─' * 50}")
        for v in medium:
            print(f"  {c['BLUE']}  ℹ [{v.get('type')}] {v.get('source', '')}{c['RESET']}")
            print(f"    {c['WHITE']}{v.get('description', '')}{c['RESET']}")
        print()

    # Öneriler
    print(f"  {c['GREEN']}{c['BOLD']}💡 ÖNERİLER{c['RESET']}")
    print(f"  {'─' * 50}")
    recommendations = [
        "Paketleri düzenli güncelleyin",
        "latest tag yerine spesifik versiyon kullanın",
        "Dockerfile'da USER direktifi ekleyin",
        "Bağımlılıkları lock file ile sabitleyin",
        "CI/CD pipeline'a supply chain taraması ekleyin",
        "Sadece official Docker image kullanın",
        "package-lock.json ve requirements.txt commit edin"
    ]
    for rec in recommendations:
        print(f"  {c['GREEN']}  • {rec}{c['RESET']}")

    print(f"\n{c['CYAN']}{'═' * 65}{c['RESET']}\n")

    # JSON kaydet
    os.makedirs("reports", exist_ok=True)
    report_data = {
        "timestamp": datetime.now().isoformat(),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "total_vulnerabilities": len(all_vulnerabilities),
        "summary": {
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
            "low": len(low)
        },
        "vulnerabilities": all_vulnerabilities,
        "npm": npm_results,
        "pip": pip_results,
        "docker": docker_results
    }

    report_path = f"reports/supply_chain_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_path, "w") as f:
        json.dump(report_data, f, indent=2, default=str)

    print(f"  {c['GREEN']}📄 Rapor kaydedildi: {report_path}{c['RESET']}\n")
    return report_data