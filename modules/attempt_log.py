"""
Attempt Log - Persistent memory of autonomous attack attempts.

매 시도(성공/실패 무관)를 JSONL로 영구 저장한다. 다음 실행 시
같은 타겟의 과거 기록을 로드해 LLM 컨텍스트에 주입함으로써
매번 처음부터 추론하는 토큰 낭비를 막고, 실패한 경로를 반복하지 않게 한다.
"""
import json
import time
from pathlib import Path


class AttemptLog:
    def __init__(self, log_path="results/attempts.jsonl"):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, record):
        """단일 시도 기록을 append (JSONL 한 줄)."""
        record.setdefault("timestamp", time.time())
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    def load_for_target(self, target_url):
        """주어진 target_url의 과거 시도 전체를 시간순으로 반환."""
        if not self.log_path.exists():
            return []
        attempts = []
        with self.log_path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    if rec.get("target_url") == target_url:
                        attempts.append(rec)
                except json.JSONDecodeError:
                    continue
        return attempts
