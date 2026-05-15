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

SUSPICIOUS_BASE_IMAGES = [
    "scratch", "alpine", "ubuntu", "debian",
    "centos", "fedora", "archlinux"
]

OFFICIAL_IMAGES = [
    "nginx", "python", "node", "postgres", "mysql",
    "redis", "mongo", "elasticsearch", "kibana",
    "jenkins", "wordpress", "php", "ruby", "golang"
]

def scan_docker_image(image_name, tag="latest"):
    """Docker Hub'dan image güvenliğini kontrol et"""
    results = {
        "image": f"{image_name}:{tag}",
        "vulnerabilities": [],
        "risk_score": 0,
        "risk_level": "LOW",
        "is_official": False,
        "pull_count": 0,
        "star_count": 0
    }

    c = COLORS
    print(f"  {c['CYAN']}[DOCKER] {image_name}:{tag} taranıyor...{c['RESET']}")

    try:
        # Docker Hub API
        # Official image kontrolü
        official_url = f"https://hub.docker.com/v2/repositories/library/{image_name}/"
        response = requests.get(official_url, timeout=10)

        if response.status_code == 200:
            data = response.json()
            results["is_official"] = True
            results["pull_count"] = data.get("pull_count", 0)
            results["star_count"] = data.get("star_count", 0)
            results["description"] = data.get("description", "")
            print(f"  {c['GREEN']}✓ OFFİCİAL    : {image_name} ({results['pull_count']:,} pull){c['RESET']}")
        else:
            # Kullanıcı image'ı
            parts = image_name.split("/")
            if len(parts) == 2:
                user_url = f"https://hub.docker.com/v2/repositories/{image_name}/"
                response = requests.get(user_url, timeout=10)

                if response.status_code == 200:
                    data = response.json()
                    results["pull_count"] = data.get("pull_count", 0)
                    results["star_count"] = data.get("star_count", 0)

                    # Düşük pull count kontrolü
                    if results["pull_count"] < 1000:
                        results["vulnerabilities"].append({
                            "type": "LOW_PULLS",
                            "severity": "MEDIUM",
                            "description": f"Az indirilen image: {results['pull_count']} pull — güvenilirlik düşük"
                        })
                        results["risk_score"] += 15
                        print(f"  {c['YELLOW']}⚠ AZ PULL     : {image_name} — {results['pull_count']} pull{c['RESET']}")
                else:
                    results["vulnerabilities"].append({
                        "type": "NOT_FOUND",
                        "severity": "HIGH",
                        "description": f"Docker Hub'da bulunamadı: {image_name}"
                    })
                    results["risk_score"] += 30
                    print(f"  {c['RED']}🎯 BULUNAMADI  : {image_name}{c['RESET']}")
            else:
                results["vulnerabilities"].append({
                    "type": "UNOFFICIAL",
                    "severity": "MEDIUM",
                    "description": f"Official olmayan image: {image_name}"
                })
                results["risk_score"] += 20
                print(f"  {c['YELLOW']}⚠ UNOFFİCİAL  : {image_name}{c['RESET']}")

        # Tag kontrolü
        if tag == "latest":
            results["vulnerabilities"].append({
                "type": "LATEST_TAG",
                "severity": "LOW",
                "description": "latest tag kullanımı — spesifik versiyon önerilir"
            })
            results["risk_score"] += 5

        # Typosquatting kontrolü
        for official in OFFICIAL_IMAGES:
            if _is_typosquatting(image_name.split("/")[-1], official):
                results["vulnerabilities"].append({
                    "type": "TYPOSQUATTING",
                    "severity": "CRITICAL",
                    "description": f"Typosquatting riski: '{image_name}' → '{official}'"
                })
                results["risk_score"] += 50
                print(f"  {c['RED']}🎯 TYPOSQUATT  : {image_name} → {official}{c['RESET']}")

        # Tag versiyonu kontrolü
        tags = _get_image_tags(image_name)
        if tags:
            results["available_tags"] = tags[:5]

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
        print(f"  {c['RED']}🔴 KRİTİK      : {image_name} — {results['risk_score']}/100{c['RESET']}")
    elif results["risk_score"] >= 40:
        results["risk_level"] = "HIGH"
        print(f"  {c['YELLOW']}🟠 YÜKSEK      : {image_name} — {results['risk_score']}/100{c['RESET']}")
    elif results["risk_score"] >= 20:
        results["risk_level"] = "MEDIUM"
        print(f"  {c['YELLOW']}🟡 ORTA        : {image_name} — {results['risk_score']}/100{c['RESET']}")
    else:
        results["risk_level"] = "LOW"
        print(f"  {c['GREEN']}✓ GÜVENLİ     : {image_name}{c['RESET']}")

    return results


def scan_dockerfile(file_path="Dockerfile"):
    """Dockerfile güvenlik analizi"""
    results = {
        "file": file_path,
        "vulnerabilities": [],
        "risk_score": 0,
        "risk_level": "LOW"
    }

    c = COLORS
    print(f"\n{c['CYAN']}  [DOCKER] Dockerfile taranıyor: {file_path}{c['RESET']}")
    print(f"  {'─' * 50}")

    try:
        with open(file_path, "r") as f:
            lines = f.readlines()

        has_user = False
        has_healthcheck = False
        base_image = ""

        for i, line in enumerate(lines):
            line = line.strip()

            # FROM kontrolü
            if line.startswith("FROM"):
                base_image = line.split()[-1]
                if "latest" in base_image:
                    results["vulnerabilities"].append({
                        "type": "LATEST_TAG",
                        "severity": "MEDIUM",
                        "description": f"latest tag: {base_image} — spesifik versiyon kullan"
                    })
                    results["risk_score"] += 10
                    print(f"  {c['YELLOW']}⚠ LATEST TAG  : {base_image}{c['RESET']}")

            # USER kontrolü
            if line.startswith("USER"):
                has_user = True
                user = line.split()[-1]
                if user == "root" or user == "0":
                    results["vulnerabilities"].append({
                        "type": "ROOT_USER",
                        "severity": "HIGH",
                        "description": "Root kullanıcı olarak çalışıyor!"
                    })
                    results["risk_score"] += 30
                    print(f"  {c['RED']}🎯 ROOT USER  : Dockerfile root kullanıyor{c['RESET']}")

            # HEALTHCHECK
            if line.startswith("HEALTHCHECK"):
                has_healthcheck = True

            # Şüpheli komutlar
            suspicious_cmds = ["curl | bash", "wget | sh", "eval", "base64 -d"]
            for cmd in suspicious_cmds:
                if cmd in line.lower():
                    results["vulnerabilities"].append({
                        "type": "SUSPICIOUS_CMD",
                        "severity": "CRITICAL",
                        "description": f"Şüpheli komut (satır {i+1}): {cmd}"
                    })
                    results["risk_score"] += 40
                    print(f"  {c['RED']}🎯 ŞÜPHELİ CMD: satır {i+1} — {cmd}{c['RESET']}")

            # ADD yerine COPY
            if line.startswith("ADD ") and not line.startswith("ADD http"):
                results["vulnerabilities"].append({
                    "type": "ADD_INSTEAD_COPY",
                    "severity": "LOW",
                    "description": f"ADD yerine COPY kullan (satır {i+1})"
                })
                results["risk_score"] += 5

        # USER tanımlanmamış
        if not has_user:
            results["vulnerabilities"].append({
                "type": "NO_USER",
                "severity": "HIGH",
                "description": "USER tanımlanmamış — container root olarak çalışır!"
            })
            results["risk_score"] += 25
            print(f"  {c['RED']}🎯 NO USER    : USER direktifi eksik{c['RESET']}")

        # HEALTHCHECK yok
        if not has_healthcheck:
            results["vulnerabilities"].append({
                "type": "NO_HEALTHCHECK",
                "severity": "LOW",
                "description": "HEALTHCHECK tanımlanmamış"
            })
            results["risk_score"] += 5

    except FileNotFoundError:
        print(f"  {c['YELLOW']}⚠ Dosya bulunamadı: {file_path}{c['RESET']}")
    except Exception as e:
        print(f"  {c['RED']}✗ Hata: {e}{c['RESET']}")

    results["risk_score"] = min(100, results["risk_score"])
    if results["risk_score"] >= 70:
        results["risk_level"] = "CRITICAL"
    elif results["risk_score"] >= 40:
        results["risk_level"] = "HIGH"
    elif results["risk_score"] >= 20:
        results["risk_level"] = "MEDIUM"

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


def _get_image_tags(image_name):
    try:
        if "/" not in image_name:
            url = f"https://hub.docker.com/v2/repositories/library/{image_name}/tags?page_size=5"
        else:
            url = f"https://hub.docker.com/v2/repositories/{image_name}/tags?page_size=5"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return [t["name"] for t in data.get("results", [])]
    except:
        pass
    return []