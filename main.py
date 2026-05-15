import sys
from modules.npm_scanner import scan_npm_package, scan_package_json
from modules.pip_scanner import scan_pip_package, scan_requirements_txt
from modules.docker_scanner import scan_docker_image, scan_dockerfile
from modules.reporter import generate_report

COLORS = {
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "CYAN": "\033[96m",
    "WHITE": "\033[97m",
    "RESET": "\033[0m",
    "BOLD": "\033[1m"
}

def banner():
    c = COLORS
    print(f"""
{c['GREEN']}{c['BOLD']}
  ███████╗██╗   ██╗██████╗ ██████╗ ██╗  ██╗   ██╗
  ██╔════╝██║   ██║██╔══██╗██╔══██╗██║  ╚██╗ ██╔╝
  ███████╗██║   ██║██████╔╝██████╔╝██║   ╚████╔╝
  ╚════██║██║   ██║██╔═══╝ ██╔═══╝ ██║    ╚██╔╝
  ███████║╚██████╔╝██║     ██║     ███████╗██║
  ╚══════╝ ╚═════╝ ╚═╝     ╚═╝     ╚══════╝╚═╝
{c['RESET']}
{c['WHITE']}  Supply Chain Security Scanner{c['RESET']}
{c['CYAN']}  github.com/kaansoyturk{c['RESET']}
""")

def print_phase(phase, total, name, description):
    c = COLORS
    print(f"\n{c['GREEN']}{'▓' * 65}{c['RESET']}")
    print(f"{c['GREEN']}{c['BOLD']}  PHASE {phase}/{total}: {name}{c['RESET']}")
    print(f"  {c['WHITE']}{description}{c['RESET']}")
    print(f"{c['GREEN']}{'▓' * 65}{c['RESET']}")

def run_scan(mode="demo"):
    banner()
    c = COLORS

    npm_results = None
    pip_results = None
    docker_results = None

    if mode == "demo":
        # Demo mod — popüler paketleri tara
        print(f"  {c['YELLOW']}Mod: Demo — popüler paketler taranıyor{c['RESET']}\n")

        # NPM tarama
        print_phase(1, 3, "NPM PACKAGES", "Node.js bağımlılıkları taranıyor")
        npm_packages = ["lodash", "axios", "express", "react", "webpack"]
        npm_results = {"packages": [], "total": len(npm_packages), "critical": 0, "high": 0, "medium": 0}

        for pkg in npm_packages:
            result = scan_npm_package(pkg)
            npm_results["packages"].append(result)
            if result["risk_level"] == "CRITICAL": npm_results["critical"] += 1
            elif result["risk_level"] == "HIGH": npm_results["high"] += 1
            elif result["risk_level"] == "MEDIUM": npm_results["medium"] += 1

        # PIP tarama
        print_phase(2, 3, "PIP PACKAGES", "Python bağımlılıkları taranıyor")
        pip_packages = ["requests", "flask", "boto3", "numpy", "django"]
        pip_results = {"packages": [], "total": len(pip_packages), "critical": 0, "high": 0, "medium": 0}

        for pkg in pip_packages:
            result = scan_pip_package(pkg)
            pip_results["packages"].append(result)
            if result["risk_level"] == "CRITICAL": pip_results["critical"] += 1
            elif result["risk_level"] == "HIGH": pip_results["high"] += 1
            elif result["risk_level"] == "MEDIUM": pip_results["medium"] += 1

        # Docker tarama
        print_phase(3, 3, "DOCKER IMAGES", "Docker image'ları taranıyor")
        docker_images = ["nginx", "python", "node", "postgres", "redis"]
        docker_results = {"packages": [], "vulnerabilities": [], "risk_score": 0, "risk_level": "LOW"}

        for img in docker_images:
            result = scan_docker_image(img)
            docker_results["packages"].append(result)
            docker_results["vulnerabilities"].extend(result.get("vulnerabilities", []))

    elif mode == "files":
        # Dosya modu
        print_phase(1, 3, "NPM PACKAGES", "package.json taranıyor")
        npm_results = scan_package_json("package.json")

        print_phase(2, 3, "PIP PACKAGES", "requirements.txt taranıyor")
        pip_results = scan_requirements_txt("requirements.txt")

        print_phase(3, 3, "DOCKER", "Dockerfile taranıyor")
        docker_results = scan_dockerfile("Dockerfile")

    # Rapor
    print(f"\n{c['CYAN']}{'▓' * 65}{c['RESET']}")
    print(f"{c['CYAN']}{c['BOLD']}  RAPOR OLUŞTURULUYOR...{c['RESET']}")
    print(f"{c['CYAN']}{'▓' * 65}{c['RESET']}")

    report = generate_report(npm_results, pip_results, docker_results)
    return report

if __name__ == "__main__":
    mode = "demo"
    if "--files" in sys.argv:
        mode = "files"

    run_scan(mode=mode)