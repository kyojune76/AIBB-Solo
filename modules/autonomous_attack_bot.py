"""
Autonomous Attack Bot - Blind LLM-based Penetration Testing
Scanner 결과만 보고 LLM이 추론해서 공격 (토큰 최적화 버전)
"""
import os
import json
import re
import time
import requests
from anthropic import Anthropic


class AutonomousAttackBot:
    """LLM-powered autonomous penetration testing bot (blind mode)"""

    def __init__(self):
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable is not set")

        self.client = Anthropic(api_key=api_key)
        self.history = []

        # 실험 모드: Phase 1만, 시도 3번 (토큰 절약)
        self.max_attempts = 3

    def _summarize_scan(self, scan_data):
        """Scanner 결과에서 핵심만 추출 (토큰 절약)"""
        summary = {
            "target_ip": scan_data.get("reconnaissance", {}).get("target_ip"),
            "open_ports": scan_data.get("reconnaissance", {}).get("open_ports", []),
            "vulnerabilities": []
        }

        # 취약점 중복 제거 (이름 기준)
        seen = set()
        for vuln in scan_data.get("vulnerability_assessment", {}).get("vulnerabilities", []):
            name = vuln.get("vulnerability_name")
            if name and name not in seen:
                seen.add(name)
                summary["vulnerabilities"].append({
                    "name": name,
                    "severity": vuln.get("severity")
                })

        return summary

    def generate_payload(self, target_url, scan_summary):
        """Scanner 결과만 보고 LLM이 공격 추론"""

        # 최근 실패 2개만 (토큰 절약)
        recent = self.history[-2:] if self.history else []

        prompt = f"""You are an autonomous penetration testing AI in a controlled lab.

[Target] {target_url}
[Scan Result] {json.dumps(scan_summary)}
[Previous Attempts] {json.dumps(recent) if recent else "None"}

Based ONLY on the scan data, infer what vulnerability exists and craft an HTTP attack to find a flag (look for "FLAG{{...}}" pattern).

Return ONLY valid JSON, no markdown:
{{"reasoning": "brief why", "method": "GET", "url_path": "/path", "headers": {{}}, "data": ""}}"""

        try:
            response = self.client.messages.create(
                model="claude-sonnet-4-5",
                max_tokens=600,
                temperature=0.7,
                messages=[{"role": "user", "content": prompt}]
            )

            response_text = response.content[0].text.strip()

            # 마크다운 코드블록 제거
            if response_text.startswith("```"):
                response_text = re.sub(r'^```(?:json)?\n?', '', response_text)
                response_text = re.sub(r'\n?```$', '', response_text)

            return json.loads(response_text.strip())

        except Exception as e:
            print(f"  [ERROR] Payload generation failed: {e}")
            return None

    def execute_attack(self, base_url, payload):
        """공격 실행"""
        url = base_url + payload.get('url_path', '/')

        try:
            response = requests.request(
                method=payload.get('method', 'GET'),
                url=url,
                headers=payload.get('headers', {}),
                data=payload.get('data', ''),
                timeout=10
            )
            return {
                "status": response.status_code,
                "text": response.text[:500]  # 응답 짧게 자름
            }
        except requests.Timeout:
            return {"error": "timeout"}
        except Exception as e:
            return {"error": str(e)[:100]}

    def check_success(self, response):
        """FLAG 발견 체크"""
        if "text" not in response:
            return False, None
        match = re.search(r'FLAG\{[^}]+\}', response["text"])
        if match:
            return True, match.group(0)
        return False, None

    def autonomous_attack(self, target_url, scan_data):
        """메인 자율 공격 루프 (간소화 버전)"""
        print(f"\n[Autonomous Attack] Starting (Blind Mode, Test Run)")
        print(f"[Target] {target_url}")
        print(f"[Max Attempts] {self.max_attempts}")

        self.history = []
        scan_summary = self._summarize_scan(scan_data)

        print(f"[Scan Summary for LLM] {len(scan_summary['vulnerabilities'])} unique vulns, "
              f"{len(scan_summary['open_ports'])} open ports")

        for attempt in range(1, self.max_attempts + 1):
            print(f"\n{'='*50}")
            print(f"[Attempt {attempt}/{self.max_attempts}]")
            print(f"{'='*50}")

            # 1. LLM이 페이로드 생성
            print("  -> Generating attack via LLM...")
            payload = self.generate_payload(target_url, scan_summary)

            if not payload:
                print("  -> Skipped (generation failed)")
                continue

            print(f"  -> Reasoning: {payload.get('reasoning', 'N/A')}")
            print(f"  -> {payload.get('method')} {payload.get('url_path')}")
            if payload.get('headers'):
                print(f"  -> Headers: {payload.get('headers')}")

            # 2. 실행
            print("  -> Executing...")
            response = self.execute_attack(target_url, payload)

            # 3. 성공 체크
            success, flag = self.check_success(response)

            if success:
                print(f"\n[SUCCESS] Flag found!")
                print(f"[FLAG] {flag}")
                return {
                    "success": True,
                    "flag": flag,
                    "attempts": attempt,
                    "payload": payload
                }

            # 4. 피드백 저장 (다음 시도가 참고)
            print(f"  -> Failed: status={response.get('status', 'error')}")
            self.history.append({
                "attempt": attempt,
                "payload": {
                    "path": payload.get('url_path'),
                    "headers": payload.get('headers'),
                },
                "result_status": response.get("status"),
                "response_preview": str(response.get("text", response.get("error", "")))[:150]
            })

            time.sleep(1)

        print(f"\n[FAILED] No flag in {self.max_attempts} attempts")
        return {
            "success": False,
            "flag": None,
            "total_attempts": len(self.history)
        }
