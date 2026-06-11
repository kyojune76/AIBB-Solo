"""
Attacker Box - 격리된 공격자 컨테이너(aibb-attacker) 제어.

LLM의 bash/http_request 툴은 호스트(네 PC)가 아니라 이 컨테이너 안에서 실행된다.
타겟은 컨테이너 안에서 http://host.docker.internal:8080 으로 접근한다.
호스트 파일시스템과 격리되므로 LLM이 무슨 명령을 내려도 PC 자체는 안전하다.
"""
import subprocess

ATTACKER_CONTAINER = "aibb-attacker"


class AttackerBox:
    def __init__(self, container=ATTACKER_CONTAINER):
        self.container = container

    def is_up(self):
        """공격자 컨테이너가 running 상태인지 확인."""
        try:
            p = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", self.container],
                capture_output=True, text=True, timeout=10,
            )
            return p.returncode == 0 and p.stdout.strip() == "true"
        except Exception:
            return False

    def run_shell(self, command, timeout=60):
        """bash -lc 로 임의 셸 명령 실행 (bash 툴용). 풀 파워."""
        return self._exec(["bash", "-lc", command], timeout)

    def run_argv(self, argv, timeout=30):
        """argv 그대로 실행 (http_request의 curl 등 — 셸 인용 문제 회피)."""
        return self._exec(argv, timeout)

    def _exec(self, inner_argv, timeout):
        try:
            p = subprocess.run(
                ["docker", "exec", self.container] + inner_argv,
                capture_output=True, text=True, timeout=timeout,
            )
            return {"stdout": p.stdout, "stderr": p.stderr, "exit_code": p.returncode}
        except subprocess.TimeoutExpired:
            return {"stdout": "", "stderr": f"timeout after {timeout}s", "exit_code": 124}
        except Exception as e:
            return {"stdout": "", "stderr": str(e)[:300], "exit_code": -1}
