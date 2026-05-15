import requests
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
    "os.system", "subprocess", "eval(", "exec(",
    "base64", "socket", "reverse_shell",
    "keylog", "password", "credential",
    "__import__", "compile("
]

def scan_pip_package(package_name, version=None):
    """PyPI paketini güvenlik açısından tara"""
    results = {
        "package": package_name,
        "version": version or "latest",
        "vulnerabilities": [],
        "suspicious_code": [],
        "typosquatting_risk": False,
        "risk_score": 0,
        "risk_level": "LOW"
    }

    c = COLORS
    print(f"  {c['CYAN']}[PIP] {package_name} taranıyor...{c['RESET']}")

    try:
        # PyPI API
        url = f"https://pypi.org/pypi/{package_name}/json"
        response = requests.get(url, timeout=10)

        if response.status_code == 404:
            results["vulnerabilities"].append({
                "type": "NOT_FOUND",
                "severity": "INFO",
                "description": f"Paket bulunamadı: {package_name}"
            })
            return results

        data = response.json()
        info = data.get("info", {})
        latest = info.get("version", "")
        version_to_check = version or latest

        results["version"] = version_to_check
        results["latest_version"] = latest
        results["description"] = info.get("summary", "")
        results["author"] = info.get("author", "")
        results["home_page"] = info.get("home_page", "")

        # Eski versiyon kontrolü
        if version and version != latest:
            results["vulnerabilities"].append({
                "type": "OUTDATED",
                "severity": "MEDIUM",
                "description": f"Eski versiyon: {version} (güncel: {latest})"
            })
            results["risk_score"] += 10

        # Paket yaşı kontrolü
        releases = data.get("releases", {})
        if version_to_check in releases and releases[version_to_check]:
            upload_time = releases[version_to_check][0].get("upload_time", "")
            if upload_time:
                upload_date = datetime.fromisoformat(upload_time[:10])
                age_days = (datetime.now() - upload_date).days
                if age_days < 30:
                    results["vulnerabilities"].append({
                        "type": "NEW_PACKAGE",
                        "severity": "MEDIUM",
                        "description": f"Yeni paket: {age_days} gün önce yüklendi"
                    })
                    results["risk_score"] += 20
                    print(f"  {c['YELLOW']}⚠ YENİ PAKET  : {package_name} — {age_days} gün{c['RESET']}")

        # Maintainer kontrolü
        maintainers = info.get("maintainer", "")
        if not maintainers and not info.get("author"):
            results["vulnerabilities"].append({
                "type": "NO_MAINTAINER",
                "severity": "MEDIUM",
                "description": "Aktif maintainer yok"
            })
            results["risk_score"] += 10

        # Typosquatting kontrolü
        popular_packages = [
            "numpy", "pandas", "requests", "flask", "django",
            "boto3", "tensorflow", "pytorch", "scipy", "sklearn"
        ]
        for popular in popular_packages:
            if _is_typosquatting(package_name, popular):
                results["typosquatting_risk"] = True
                results["vulnerabilities"].append({
                    "type": "TYPOSQUATTING",
                    "severity": "CRITICAL",
                    "description": f"Typosquatting riski: '{package_name}' → '{popular}'"
                })
                results["risk_score"] += 50
                print(f"  {c['RED']}🎯 TYPOSQUATT  : {package_name} → {popular}{c['RESET']}")

        # OSV veritabanından CVE kontrolü
        vulns = _check_osv(package_name, version_to_check)
        for vuln in vulns:
            results["vulnerabilities"].append(vuln)
            results["risk_score"] += 20
            print(f"  {c['RED']}🎯 CVE         : {package_name} — {vuln['description'][:50]}{c['RESET']}")

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


def scan_requirements_txt(file_path="requirements.txt"):
    """requirements.txt dosyasını tara"""
    results = {
        "file": file_path,
        "packages": [],
        "total": 0,
        "critical": 0,
        "high": 0,
        "medium": 0
    }

    c = COLORS
    print(f"\n{c['CYAN']}  [PIP] requirements.txt taranıyor: {file_path}{c['RESET']}")
    print(f"  {'─' * 50}")

    try:
        with open(file_path, "r") as f:
            lines = f.readlines()

        packages = {}
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "==" in line:
                name, version = line.split("==", 1)
                packages[name.strip()] = version.strip()
            elif ">=" in line:
                name, version = line.split(">=", 1)
                packages[name.strip()] = version.strip()
            else:
                packages[line.strip()] = None

        results["total"] = len(packages)
        print(f"  {c['WHITE']}Toplam paket: {len(packages)}{c['RESET']}\n")

        for package, version in packages.items():
            result = scan_pip_package(package, version)
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
    if name == popular:
        return False
    if len(name) < 3:
        return False
    if abs(len(name) - len(popular)) > 2:
        return False
    differences = sum(1 for a, b in zip(name, popular) if a != b)
    return differences == 1 and len(name) == len(popular)


def _check_osv(package, version):
    """OSV veritabanından güvenlik açığı kontrolü"""
    vulnerabilities = []
    try:
        response = requests.post(
            "https://api.osv.dev/v1/query",
            json={
                "version": version,
                "package": {
                    "name": package,
                    "ecosystem": "PyPI"
                }
            },
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            for vuln in data.get("vulns", [])[:3]:
                severity = "HIGH"
                if vuln.get("database_specific", {}).get("severity"):
                    severity = vuln["database_specific"]["severity"].upper()

                vulnerabilities.append({
                    "type": "CVE",
                    "severity": severity,
                    "description": vuln.get("summary", "")[:100],
                    "id": vuln.get("id", "")
                })
    except:
        pass
    return vulnerabilities