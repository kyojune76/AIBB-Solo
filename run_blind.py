#!/usr/bin/env python3
"""
블라인드 Tool Use 봇 실행 엔트리 (비대화형).

사용법:
  python run_blind.py [target_id]
    target_id : 중립 ID (기본 t1)

  L0→L1→L2→L3 까지 자동 승급(각 레벨 5회 시도). 풀면 그 레벨에서 멈추고
  '몇 레벨에서 풀었나'를 보고한다.

전제: 타겟 컨테이너가 8080에, 공격자 컨테이너(aibb-attacker)가 떠 있어야 함.
주의: 블라인드 유지를 위해 nuclei(취약점 이름 노출)는 돌리지 않고 nmap 신호만 사용.
"""
import sys
import json
from dotenv import load_dotenv

load_dotenv()

from modules.scanner import run_nmap_scan
from modules.tool_use_attack_bot import ToolUseAttackBot

TARGET_URL = "http://host.docker.internal:8080"


def main():
    target_id = sys.argv[1] if len(sys.argv) > 1 else "t1"

    print(f"[run_blind] target_id={target_id}  url={TARGET_URL}  (ladder L0→L3)")

    try:
        nmap = run_nmap_scan("127.0.0.1", "8080")
    except Exception as e:
        print(f"[!] nmap 실패, 최소 정보로 fallback: {e}")
        nmap = {"open_ports": [{"port": 8080, "service_name": "http", "version": "unknown"}]}

    scan_data = {"reconnaissance": nmap, "vulnerability_assessment": {"vulnerabilities": []}}

    bot = ToolUseAttackBot()
    result = bot.run_ladder(target_id, TARGET_URL, scan_data,
                            start_level=0, max_level=3, per_level=5)

    print("\n=== RESULT ===")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
