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
        self.log = None  # autonomous_attack() 호출 시 target_name으로 초기화

        self.max_attempts = 5

    def _extract_tried_keys(self, attempts):
        """모든 시도에서 (method, path) 조합을 중복 없이 추출."""
        seen = set()
        tried = []
        for rec in attempts:
            payload = rec.get("payload", {})
            method = payload.get("method", "GET")
            path = payload.get("url_path", "/")
            key = f"{method}:{path}"
            if key not in seen:
                seen.add(key)
                tried.append({
                    "method": method,
                    "path": path,
                    "status": rec.get("response", {}).get("status"),
                })
        return tried

    def _format_attempts_for_prompt(self, attempts, max_count=10, body_limit=300):
        """과거 시도 목록을 LLM 프롬프트용으로 압축 (최근 N개, 응답 미리보기 포함)."""
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

    def _generate_probe(self, target_url, scan_summary, observations):
        """L1: LLM이 다음에 탐색할 경로를 결정. done=true면 정찰 종료 신호."""
        probed_paths = [o["probe"].get("url_path") for o in observations]

        prompt = f"""당신은 통제된 실험 환경의 자율 침투 테스트 AI다. 지금은 공격 전 정찰(reconnaissance) 단계다.

[타겟] {target_url}
[스캔 결과] {json.dumps(scan_summary, ensure_ascii=False)}
[이미 탐색한 경로] {json.dumps(probed_paths, ensure_ascii=False) if probed_paths else "없음"}
[탐색 결과 누적] {json.dumps(observations, ensure_ascii=False) if observations else "없음"}

목표: 공격에 앞서 실제로 존재하는 경로/엔드포인트를 파악하라.
- 이미 탐색한 경로는 반복하지 말 것
- 200/403 응답은 경로가 존재한다는 신호다
- 충분히 파악했다면 done=true로 정찰 종료

오직 유효한 JSON만 반환할 것, 마크다운 금지:
{{"reasoning": "간단한 근거", "method": "GET", "url_path": "/path", "headers": {{}}, "done": false}}"""

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=400,
                messages=[{"role": "user", "content": prompt}]
            )
            text_block = next((b for b in response.content if b.type == "text"), None)
            if not text_block:
                raise ValueError("No text block in response")
            text = text_block.text.strip()
            if text.startswith("```"):
                text = re.sub(r'^```(?:json)?\n?', '', text)
                text = re.sub(r'\n?```$', '', text)
            return json.loads(text.strip())
        except Exception as e:
            print(f"  [ERROR] Probe generation failed: {e}")
            return None

    def _l1_recon(self, target_url, scan_summary, max_probes=6):
        """L1 정찰 루프: LLM이 직접 경로를 골라 curl 탐색, 결과를 누적 반환."""
        print(f"\n[L1 Recon] Starting active reconnaissance (max {max_probes} probes)")
        observations = []

        for i in range(1, max_probes + 1):
            probe = self._generate_probe(target_url, scan_summary, observations)
            if not probe:
                break

            path = probe.get("url_path", "/")
            method = probe.get("method", "GET")

            # 중복 경로 스킵
            if path in [o["probe"].get("url_path") for o in observations]:
                print(f"  [L1 #{i}] SKIP duplicate: {path}")
                continue

            print(f"  [L1 #{i}] {method} {path}")
            result = self.execute_attack(target_url, probe)

            status = result.get("status", result.get("error", "?"))
            body_preview = (result.get("body") or "")[:300]
            print(f"           -> status={status}")

            observations.append({
                "probe": {"method": method, "url_path": path, "headers": probe.get("headers", {})},
                "status": status,
                "body_preview": body_preview,
            })

            if probe.get("done"):
                print(f"  [L1] LLM signaled recon complete")
                break

        print(f"[L1 Recon] Done — {len(observations)} paths probed")
        return observations

    def generate_payload(self, target_url, scan_summary, past_attempts, recon_observations=None):
        """Scanner 결과 + L1 정찰 + 과거 시도 누적 기록을 바탕으로 LLM이 공격 추론."""

        combined = past_attempts + self.history
        tried = self._extract_tried_keys(combined)
        formatted = self._format_attempts_for_prompt(combined)

        recon_section = ""
        if recon_observations:
            recon_section = f"\n[L1 정찰 결과 — 실제 존재 확인된 경로]\n{json.dumps(recon_observations, ensure_ascii=False)}\n"

        prompt = f"""당신은 통제된 실험 환경에서 동작하는 자율 침투 테스트 AI다.

[타겟] {target_url}
[스캔 결과] {json.dumps(scan_summary, ensure_ascii=False)}
{recon_section}
[★ 절대 금지 — 이미 시도한 (method, path) 전체 목록 ★]
{json.dumps(tried, ensure_ascii=False)}
위 목록에 있는 method+path 조합은 어떤 이유로도 반복하지 말 것. 완전히 새로운 경로 또는 완전히 다른 헤더/method 조합으로만 시도하라.

[최근 시도 상세 (응답 참고용)] {json.dumps(formatted, ensure_ascii=False) if formatted else "없음"}

L1 정찰 결과를 근거로 실제 존재하는 경로에 공격을 집중하라. 플래그는 "FLAG{{...}}" 형식이다.

오직 유효한 JSON만 반환할 것, 마크다운 금지:
{{"reasoning": "간단한 근거", "method": "GET", "url_path": "/path", "headers": {{}}, "data": ""}}"""

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=600,
                messages=[{"role": "user", "content": prompt}]
            )

            text_block = next((b for b in response.content if b.type == "text"), None)
            if not text_block:
                raise ValueError("No text block in response")
            response_text = text_block.text.strip()

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

    def autonomous_attack(self, target_url, scan_data, target_name="default"):
        """메인 자율 공격 루프. 과거 시도를 디스크에서 로드해 누적 메모리로 활용."""
        self.log = AttemptLog(target_name)

        print(f"\n[Autonomous Attack] Starting (Blind Mode)")
        print(f"[Target] {target_url}  [{target_name}]")
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

        # L1 정찰 단계
        recon_observations = self._l1_recon(target_url, scan_summary)

        for attempt in range(1, self.max_attempts + 1):
            print(f"\n{'='*50}")
            print(f"[Attempt {attempt}/{self.max_attempts}]")
            print(f"{'='*50}")

            # 1. LLM이 페이로드 생성 (디스크 과거 + 세션 내 history 모두 컨텍스트로)
            print("  -> Generating attack via LLM...")
            payload = self.generate_payload(target_url, scan_summary, past_attempts, recon_observations)

            if not payload:
                print("  -> Skipped (generation failed)")
                continue

            # 중복 페이로드 코드 레벨 거부
            combined_all = past_attempts + self.history
            tried_keys = {
                f"{r.get('payload',{}).get('method')}:{r.get('payload',{}).get('url_path')}"
                for r in combined_all
            }
            new_key = f"{payload.get('method')}:{payload.get('url_path')}"
            if new_key in tried_keys:
                print(f"  -> [BLOCKED] 중복 페이로드 거부: {new_key} (이미 시도됨)")
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
