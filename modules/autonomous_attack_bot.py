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

from modules.attempt_log import AttemptLog


class AutonomousAttackBot:
    """LLM-powered autonomous penetration testing bot (blind mode)"""

    def __init__(self):
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable is not set")

        self.client = Anthropic(api_key=api_key)
        self.model = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")
        self.history = []
        self.log = AttemptLog()

        # 실험 모드: Phase 1만, 시도 3번 (토큰 절약)
        self.max_attempts = 3

    def _format_attempts_for_prompt(self, attempts, max_count=10, body_limit=300):
        """과거 시도 목록을 LLM 프롬프트용으로 압축."""
        recent = attempts[-max_count:]
        formatted = []
        for rec in recent:
            payload = rec.get("payload", {})
            response = rec.get("response", {})
            body = response.get("body") or response.get("text") or ""
            formatted.append({
                "payload": {
                    "method": payload.get("method"),
                    "path": payload.get("url_path"),
                    "headers": payload.get("headers"),
                    "data": payload.get("data"),
                },
                "status": response.get("status"),
                "body_preview": body[:body_limit] if isinstance(body, str) else "",
                "error": response.get("error"),
            })
        return formatted

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

    def generate_payload(self, target_url, scan_summary, past_attempts):
        """Scanner 결과 + 과거 시도 누적 기록을 바탕으로 LLM이 공격 추론."""

        combined = past_attempts + self.history
        formatted = self._format_attempts_for_prompt(combined)

        prompt = f"""당신은 통제된 실험 환경에서 동작하는 자율 침투 테스트 AI다.

[타겟] {target_url}
[스캔 결과] {json.dumps(scan_summary, ensure_ascii=False)}
[이전 시도] {json.dumps(formatted, ensure_ascii=False) if formatted else "없음"}

스캔 결과와 과거 시도만을 근거로, 어떤 취약점이 존재하는지 추론하고 플래그("FLAG{{...}}" 형식)를 찾기 위한 HTTP 공격을 설계하라. 이미 실패한 페이로드를 반복하지 말 것 — 과거 응답(status, body_preview)을 증거로 활용해 가설을 정교화하라.

오직 유효한 JSON만 반환할 것, 마크다운 금지:
{{"reasoning": "간단한 근거", "method": "GET", "url_path": "/path", "headers": {{}}, "data": ""}}"""

        try:
            response = self.client.messages.create(
                model=self.model,
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
        """공격 실행. 응답 헤더 + 본문(최대 10KB)을 캡처해 로그/메모리에 풀로 남긴다."""
        url = base_url + payload.get('url_path', '/')
        BODY_CAP = 10000

        try:
            response = requests.request(
                method=payload.get('method', 'GET'),
                url=url,
                headers=payload.get('headers', {}),
                data=payload.get('data', ''),
                timeout=10
            )
            raw_body = response.text or ""
            body_truncated = len(raw_body) > BODY_CAP
            return {
                "status": response.status_code,
                "headers": dict(response.headers),
                "body": raw_body[:BODY_CAP],
                "body_truncated": body_truncated,
            }
        except requests.Timeout:
            return {"error": "timeout"}
        except Exception as e:
            return {"error": str(e)[:200]}

    def check_success(self, response):
        """FLAG 발견 체크"""
        body = response.get("body") or response.get("text") or ""
        match = re.search(r'FLAG\{[^}]+\}', body)
        if match:
            return True, match.group(0)
        return False, None

    def autonomous_attack(self, target_url, scan_data):
        """메인 자율 공격 루프. 과거 시도를 디스크에서 로드해 누적 메모리로 활용."""
        print(f"\n[Autonomous Attack] Starting (Blind Mode)")
        print(f"[Target] {target_url}")
        print(f"[Max Attempts] {self.max_attempts}")

        past_attempts = self.log.load_for_target(target_url)
        if past_attempts:
            print(f"[Memory] Loaded {len(past_attempts)} past attempt(s) from disk for this target")
        else:
            print(f"[Memory] No past attempts for this target — fresh start")

        self.history = []
        scan_summary = self._summarize_scan(scan_data)

        print(f"[Scan Summary for LLM] {len(scan_summary['vulnerabilities'])} unique vulns, "
              f"{len(scan_summary['open_ports'])} open ports")

        for attempt in range(1, self.max_attempts + 1):
            print(f"\n{'='*50}")
            print(f"[Attempt {attempt}/{self.max_attempts}]")
            print(f"{'='*50}")

            # 1. LLM이 페이로드 생성 (디스크 과거 + 세션 내 history 모두 컨텍스트로)
            print("  -> Generating attack via LLM...")
            payload = self.generate_payload(target_url, scan_summary, past_attempts)

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

            # 4. 풀 기록을 디스크 + 세션 메모리에 저장 (성공/실패 무관)
            record = {
                "target_url": target_url,
                "attempt_in_session": attempt,
                "reasoning": payload.get("reasoning"),
                "payload": payload,
                "response": response,
                "success": success,
                "flag": flag,
            }
            self.log.append(record)
            self.history.append(record)

            if success:
                print(f"\n[SUCCESS] Flag found!")
                print(f"[FLAG] {flag}")
                return {
                    "success": True,
                    "flag": flag,
                    "attempts": attempt,
                    "payload": payload
                }

            print(f"  -> Failed: status={response.get('status', 'error')}")
            time.sleep(1)

        print(f"\n[FAILED] No flag in {self.max_attempts} attempts")
        return {
            "success": False,
            "flag": None,
            "total_attempts": len(self.history)
        }
