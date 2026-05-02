import nmap
import json
import subprocess

def run_nmap_scan(target_ip, port_range="1-1000"):
    print(f"[*] Nmap 스캔 시작: {target_ip} (포트: {port_range})")
    nm = nmap.PortScanner()
    try:
        nm.scan(target_ip, port_range, arguments='-sV -T4')
        scan_results = {
            "target_ip": target_ip,
            "host_status": "down",
            "open_ports": [],
            "error": None
        }
        for host in nm.all_hosts():
            scan_results["host_status"] = nm[host].state()
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    port_data = nm[host][proto][port]
                    if port_data['state'] == 'open':
                        scan_results["open_ports"].append({
                            "port": port,
                            "protocol": proto,
                            "service_name": port_data['name'],
                            "version": port_data.get('version', 'unknown')
                        })
        return scan_results
    except Exception as e:
        return {"target_ip": target_ip, "error": str(e)}

def run_nuclei_scan(target_url):
    """
    Nuclei를 실행하여 타겟 URL의 취약점을 스캔하고 JSON 형태로 파싱합니다.
    """
    print(f"[*] Nuclei 스캔 시작: {target_url}")
    
    cmd = ["nuclei", "-u", target_url, "-silent", "-jsonl"]
    
    found_vulnerabilities = []
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        for line in result.stdout.strip().split('\n'):
            if line:
                try:
                    data = json.loads(line)
                    vuln_info = {
                        "vulnerability_name": data.get("info", {}).get("name", "Unknown"),
                        "severity": data.get("info", {}).get("severity", "Unknown"),
                        "cve_id": data.get("info", {}).get("classification", {}).get("cve-id", []),
                        "description": data.get("info", {}).get("description", "No description")
                    }
                    found_vulnerabilities.append(vuln_info)
                except json.JSONDecodeError:
                    continue
                    
        return {"target_url": target_url, "vulnerabilities": found_vulnerabilities, "error": None}
        
    except Exception as e:
        return {"target_url": target_url, "error": str(e)}

def execute_full_scan(target_ip, target_port):
    """
    [Main.py에서 호출할 최종 함수]
    Nmap과 Nuclei 결과를 합쳐서 하나의 완벽한 JSON 보고서로 만듭니다.
    """
    # 1. Nmap 실행
    nmap_result = run_nmap_scan(target_ip, port_range=str(target_port))
    
    # 2. Nuclei 실행 (웹 서비스 취약점용 URL 조립)
    target_url = f"http://{target_ip}:{target_port}"
    nuclei_result = run_nuclei_scan(target_url)
    
    # 3. 결과 병합
    final_report = {
        "reconnaissance": nmap_result,
        "vulnerability_assessment": nuclei_result
    }
    
    return json.dumps(final_report, indent=4, ensure_ascii=False)

if __name__ == "__main__":
    test_target = "127.0.0.1" 
    test_port = "8080" # Shellshock 컨테이너 포트
    
    print("=== AIBB Scanner Module Test (Nmap + Nuclei) ===")
    final_json = execute_full_scan(test_target, test_port)
    
    print("\n[LLM 전달용 최종 통합 데이터]")
    print(final_json)
