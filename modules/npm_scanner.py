import requests
import json
from datetime import datetime

COLORS = {
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "CYAN": "\033[96m",
    "WHITE": "\033[97m",
    "RESET": "\033[0m"
}

SUSPICIOUS_KEYWORDS = [
    "postinstall", "preinstall", "install",
    "curl", "wget", "exec", "eval",
    "base64", "crypto", "keylogger",
    "password", "passwd", "credential"
]

def scan_npm_package(package_name, version=None):
    """NPM paketini güvenlik açısından tara"""
    results = {
        "package": package_name,
        "version": version or "latest",
        "vulnerabilities": [],
        "suspicious_scripts": [],
        "typosquatting_risk": False,
        "risk_score": 0,
        "risk_level": "LOW"
    }

    c = COLORS
    print(f"  {c['CYAN']}[NPM] {package_name} taranıyor...{c['RESET']}")

    # NPM registry'den paket bilgisi al
    try:
        url = f"https://registry.npmjs.org/{package_name}"
        response = requests.get(url, timeout=10)

        if response.status_code == 404:
            results["vulnerabilities"].append({
                "type": "NOT_FOUND",
                "severity": "INFO",
                "description": f"Paket bulunamadı: {package_name}"
            })
            return results

        data = response.json()
        latest = data.get("dist-tags", {}).get("latest", "")
        version_to_check = version or latest

        results["version"] = version_to_check
        results["latest_version"] = latest
        results["description"] = data.get("description", "")
        results["author"] = data.get("author", {}).get("name", "") if isinstance(data.get("author"), dict) else str(data.get("author", ""))
        results["created"] = data.get("time", {}).get("created", "")[:10]
        results["downloads"] = 0

        # Eski versiyon kontrolü
        if version and version != latest:
            results["vulnerabilities"].append({
                "type": "OUTDATED",
                "severity": "MEDIUM",
                "description": f"Eski versiyon: {version} (güncel: {latest})"
            })
            results["risk_score"] += 10

        # Paket yaşı kontrolü
        created = data.get("time", {}).get("created", "")
        if created:
            created_date = datetime.fromisoformat(created[:10])
            age_days = (datetime.now() - created_date).days
            if age_days < 30:
                results["vulnerabilities"].append({
                    "type": "NEW_PACKAGE",
                    "severity": "MEDIUM",
                    "description": f"Yeni paket: {age_days} gün önce oluşturulmuş — supply chain saldırısı riski!"
                })
                results["risk_score"] += 20
                print(f"  {c['YELLOW']}⚠ YENİ PAKET  : {package_name} — {age_days} gün önce{c['RESET']}")

        # Script analizi
        version_data = data.get("versions", {}).get(version_to_check, {})
        scripts = version_data.get("scripts", {})

        for script_name, script_content in scripts.items():
            script_lower = script_content.lower()
            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword in script_lower:
                    results["suspicious_scripts"].append({
                        "script": script_name,
                        "content": script_content[:100],
                        "keyword": keyword
                    })
                    results["vulnerabilities"].append({
                        "type": "SUSPICIOUS_SCRIPT",
                        "severity": "HIGH",
                        "description": f"Şüpheli script: {script_name} içinde '{keyword}' bulundu"
                    })
                    results["risk_score"] += 25
                    print(f"  {c['RED']}🎯 ŞÜPHELİ    : {package_name} → {script_name}: {keyword}{c['RESET']}")
                    break

        # Typosquatting kontrolü
        popular_packages = [
            "react", "lodash", "express", "axios", "moment",
            "webpack", "babel", "eslint", "typescript", "vue"
        ]
        for popular in popular_packages:
            if _is_typosquatting(package_name, popular):
                results["typosquatting_risk"] = True
                results["vulnerabilities"].append({
                    "type": "TYPOSQUATTING",
                    "severity": "CRITICAL",
                    "description": f"Typosquatting riski: '{package_name}' → '{popular}' benzeri!"
                })
                results["risk_score"] += 50
                print(f"  {c['RED']}🎯 TYPOSQUATT  : {package_name} → {popular}{c['RESET']}")

        # NPM audit
        audit = _check_npm_audit(package_name, version_to_check)
        if audit:
            results["vulnerabilities"].extend(audit)
            results["risk_score"] += len(audit) * 15

    except Exception as e:
        results["vulnerabilities"].append({
            "type": "ERROR",
            "severity": "INFO",
            "description": f"Tarama hatası: {str(e)[:50]}"
        })

    # Risk seviyesi
    results["risk_score"] = min(100, results["risk_score"])
    if results["risk_score"] >= 70:
        results["risk_level"] = "CRITICAL"
        print(f"  {c['RED']}🔴 KRİTİK      : {package_name} — {results['risk_score']}/100{c['RESET']}")
    elif results["risk_score"] >= 40:
        results["risk_level"] = "HIGH"
        print(f"  {c['YELLOW']}🟠 YÜKSEK      : {package_name} — {results['risk_score']}/100{c['RESET']}")
    elif results["risk_score"] >= 20:
        results["risk_level"] = "MEDIUM"
        print(f"  {c['YELLOW']}🟡 ORTA        : {package_name} — {results['risk_score']}/100{c['RESET']}")
    else:
        results["risk_level"] = "LOW"
        print(f"  {c['GREEN']}✓ GÜVENLİ     : {package_name}{c['RESET']}")

    return results


def scan_package_json(file_path="package.json"):
    """package.json dosyasını tara"""
    results = {
        "file": file_path,
        "packages": [],
        "total": 0,
        "critical": 0,
        "high": 0,
        "medium": 0
    }

    c = COLORS
    print(f"\n{c['CYAN']}  [NPM] package.json taranıyor: {file_path}{c['RESET']}")
    print(f"  {'─' * 50}")

    try:
        with open(file_path, "r") as f:
            data = json.load(f)

        dependencies = {}
        dependencies.update(data.get("dependencies", {}))
        dependencies.update(data.get("devDependencies", {}))

        results["total"] = len(dependencies)
        print(f"  {c['WHITE']}Toplam paket: {len(dependencies)}{c['RESET']}\n")

        for package, version in dependencies.items():
            version = version.lstrip("^~>=")
            result = scan_npm_package(package, version)
            results["packages"].append(result)

            if result["risk_level"] == "CRITICAL":
                results["critical"] += 1
            elif result["risk_level"] == "HIGH":
                results["high"] += 1
            elif result["risk_level"] == "MEDIUM":
                results["medium"] += 1

    except FileNotFoundError:
        print(f"  {c['YELLOW']}⚠ Dosya bulunamadı: {file_path}{c['RESET']}")
    except Exception as e:
        print(f"  {c['RED']}✗ Hata: {e}{c['RESET']}")

    return results


def _is_typosquatting(name, popular):
    """Basit typosquatting kontrolü"""
    if name == popular:
        return False
    if len(name) < 3:
        return False

    # Edit distance kontrolü (basit)
    if abs(len(name) - len(popular)) > 2:
        return False

    differences = sum(1 for a, b in zip(name, popular) if a != b)
    return differences == 1 and len(name) == len(popular)


def _check_npm_audit(package, version):
    """NPM güvenlik açığı kontrolü"""
    vulnerabilities = []
    try:
        url = f"https://registry.npmjs.org/-/npm/v1/security/advisories/bulk"
        response = requests.post(
            url,
            json={package: [version]},
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            for pkg, advisories in data.items():
                for advisory in advisories:
                    vulnerabilities.append({
                        "type": "CVE",
                        "severity": advisory.get("severity", "MEDIUM").upper(),
                        "description": advisory.get("title", ""),
                        "cve": advisory.get("cves", [])
                    })
    except:
        pass
    return vulnerabilities