#!/usr/bin/env python3
"""
AIBB (AI BunkerBuster) - Main Controller
"""
import sys
import time
import json
from pathlib import Path

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
        """Load attack targets"""
        self.targets = [
            {
                "name": "shellshock",
                "cve": "CVE-2014-6271",
                "type": "shellshock",
                "path": "./targets/shellshock",
                "port": 8080,
                "url": "http://localhost:8080"
            }
        ]
        print(f"[*] {len(self.targets)} target(s) loaded")
    
    def attack_target(self, target):
        """Attack individual target"""
        print(f"\n{'='*50}")
        print(f"[Target] {target['name']} ({target['cve']})")
        print(f"{'='*50}")
        
        # Step 1: Start Docker
        print(f"\n[Step 1] Starting Docker container")
        if not self.docker_mgr.start_container(target['path']):
            print("[ERROR] Failed to start Docker")
            return
        
        # Step 2: Run Scanner (Nmap + Nuclei)
        print(f"\n[Step 2] Scanning (Nmap + Nuclei)")
        try:
            scan_result = execute_full_scan("127.0.0.1", target['port'])
            print(f"[OK] Scan completed")
        except Exception as e:
            print(f"[ERROR] Scanner failed: {e}")
        
        # Step 3: Autonomous AI Attack
        print(f"\n[Step 3] AI Autonomous Attack")
        try:
            cve_info = {
                "cve": target['cve'],
                "type": target['type'],
                "service": "Apache 2.4.10"
            }
            
            attack_result = self.attack_bot.autonomous_attack(
                target_url=target['url'],
                cve_info=cve_info
            )
            
            self.results[target['name']] = attack_result
            
        except Exception as e:
            print(f"[ERROR] Attack failed: {e}")
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
            else:
                print(f"\n{name}: [FAIL]")
                if 'total_attempts' in result:
                    print(f"  Total attempts: {result['total_attempts']}")

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
