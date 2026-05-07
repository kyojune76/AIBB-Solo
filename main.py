#!/usr/bin/env python3
"""
AIBB (AI BunkerBuster) - Main Controller (Blind Mode)
LLM이 Scanner 결과만 보고 자율적으로 공격
"""
import sys
import json
from pathlib import Path
from dotenv import load_dotenv

# Load .env (ANTHROPIC_API_KEY)
load_dotenv()

# Module imports
from modules.docker_manager import DockerManager
from modules.scanner import execute_full_scan
from modules.autonomous_attack_bot import AutonomousAttackBot

class AIBB:
    def __init__(self):
        print("[*] AIBB (AI BunkerBuster) Initializing")
        self.docker_mgr = DockerManager()
        self.attack_bot = AutonomousAttackBot()
        self.targets = []
        self.results = {}

    def run(self):
        """Main execution function"""
        print("\n" + "="*50)
        print("AIBB Automated Penetration Testing Started")
        print("="*50 + "\n")

        # 1. Load targets
        self.load_targets()

        # 2. Attack each target
        for target in self.targets:
            self.attack_target(target)

        # 3. Generate final report
        self.generate_report()

    def load_targets(self):
        """Load attack targets (CVE 정보 없음 - 블라인드 모드)"""
        self.targets = [
            {
                "name": "shellshock",
                "path": "./targets/shellshock",
                "port": 8080,
                "url": "http://localhost:8080"
            }
        ]
        print(f"[*] {len(self.targets)} target(s) loaded")

    def attack_target(self, target):
        """Attack individual target"""
        print(f"\n{'='*50}")
        print(f"[Target] {target['name']}")
        print(f"{'='*50}")

        # Step 1: Start Docker
        print(f"\n[Step 1] Starting Docker container")
        if not self.docker_mgr.start_container(target['path']):
            print("[ERROR] Failed to start Docker")
            return

        # Step 2: Run Scanner (Nmap + Nuclei)
        print(f"\n[Step 2] Scanning (Nmap + Nuclei)")
        scan_data = None
        try:
            scan_result = execute_full_scan("127.0.0.1", target['port'])
            scan_data = json.loads(scan_result)

            # 스캔 결과 요약 출력
            print(f"\n[Scan Summary]")
            print(f"  Target: {scan_data['reconnaissance']['target_ip']}")
            print(f"  Status: {scan_data['reconnaissance']['host_status']}")
            print(f"  Open Ports: {len(scan_data['reconnaissance']['open_ports'])}")

            for port in scan_data['reconnaissance']['open_ports']:
                print(f"    - Port {port['port']}: {port['service_name']} {port['version']}")

            vuln_count = len(scan_data['vulnerability_assessment']['vulnerabilities'])
            print(f"\n  Vulnerabilities: {vuln_count} found")

            for vuln in scan_data['vulnerability_assessment']['vulnerabilities']:
                print(f"    - {vuln['vulnerability_name']} ({vuln['severity']})")

            print(f"\n[OK] Scan completed")

        except Exception as e:
            print(f"[ERROR] Scanner failed: {e}")
            self.docker_mgr.stop_container(target['path'])
            return

        # Step 3: Autonomous AI Attack (Blind Mode)
        print(f"\n[Step 3] AI Autonomous Attack (Blind Mode)")
        try:
            # ⭐ 블라인드 모드: scan_data만 넘김. CVE/타입 정보 절대 안 줌
            attack_result = self.attack_bot.autonomous_attack(
                target_url=target['url'],
                scan_data=scan_data
            )

            self.results[target['name']] = attack_result

        except Exception as e:
            print(f"[ERROR] Attack failed: {e}")
            import traceback
            traceback.print_exc()
            self.results[target['name']] = {
                "success": False,
                "error": str(e)
            }

        # Step 4: Docker cleanup
        print(f"\n[Step 4] Docker cleanup")
        self.docker_mgr.stop_container(target['path'])

    def generate_report(self):
        """Generate final report"""
        print("\n" + "="*50)
        print("[Report] Final Results")
        print("="*50)

        for name, result in self.results.items():
            if result.get('success'):
                print(f"\n{name}: [SUCCESS]")
                print(f"  Flag: {result['flag']}")
                print(f"  Phase: {result['phase']}")
                print(f"  Attempts: {result['attempts']}")
                if 'payload' in result:
                    reasoning = result['payload'].get('reasoning', 'N/A')
                    print(f"  Reasoning: {reasoning[:150]}")
            else:
                print(f"\n{name}: [FAIL]")
                if 'total_attempts' in result:
                    print(f"  Total attempts: {result['total_attempts']}")
                if 'error' in result:
                    print(f"  Error: {result['error']}")

def main():
    try:
        aibb = AIBB()
        aibb.run()
    except KeyboardInterrupt:
        print("\n\n[!] User interrupted")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
