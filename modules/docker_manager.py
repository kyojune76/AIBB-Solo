"""
Docker Manager Module
"""
import subprocess
import time

class DockerManager:
    def __init__(self):
        self.active_containers = []
    
    def start_container(self, target_path):
        """Start Docker container"""
        print(f"  -> Running docker-compose in {target_path}")
        
        try:
            subprocess.run(
                ["docker", "compose", "up", "-d"],
                cwd=target_path,
                check=True,
                capture_output=True
            )
            print(f"  [OK] Container started")
            time.sleep(5)
            return True
        except subprocess.CalledProcessError as e:
            print(f"  [ERROR] Docker start failed: {e}")
            return False
    
    def stop_container(self, target_path):
        """Stop Docker container"""
        print(f"  -> Stopping docker-compose in {target_path}")
        
        try:
            subprocess.run(
                ["docker", "compose", "down"],
                cwd=target_path,
                check=True,
                capture_output=True
            )
            print(f"  [OK] Container stopped")
            time.sleep(2)
            return True
        except subprocess.CalledProcessError as e:
            print(f"  [ERROR] Docker stop failed: {e}")
            return False
