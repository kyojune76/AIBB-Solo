# AIBB-Solo Project Context

## Overview
AI-based Autonomous Penetration Testing System (개인 연구판).
LLM이 스캔 결과만 보고 자율적으로 CVE 취약점을 탐지/공격하는 시스템.

## 환경 및 안전 범위 (CRITICAL)
- 로컬 vulhub 도커 격리 환경 전용
- 허용 타겟: 127.0.0.1, localhost, ::1, 도커 내부망만
- 외부 시스템 대상 공격 절대 금지
- 모든 새 코드에 타겟 화이트리스트 체크 포함 권장

## 아키텍처 철학: "블라인드 모드"
- LLM에 CVE 라벨/타입 정보를 주지 않음
- scan_data (Nmap + Nuclei 결과)만 제공
- LLM이 스스로 추론해서 공격 페이로드 생성
- Phase별 전략: Basic → Encoding → Advanced → Creative

## 현재 구조
- main.py — AIBB 컨트롤러 (블라인드 모드)
- modules/docker_manager.py — 도커 타겟 기동/정지
- modules/scanner.py — Nmap + Nuclei 통합
- modules/autonomous_attack_bot.py — LLM 자율 공격
- targets/shellshock/ — vulhub Shellshock 도커
- full_project.txt — 프로젝트 소스 통합 (LLM 컨텍스트용?)

## 알려진 한계점
URL만으로는 타겟별 특수 사실(예: /tmp/FLAG{Shellshock} 위치)을
LLM이 추론하기 어려움. 컨텍스트 부족 문제.

## 통합 계획 (팀 저장소: 2026_DAST_TEAM/dev)
영주님 저장소(https://github.com/12wndud05/AI-agent)의 vuln_db JSON과 합칠 예정.

### "Hint Ladder" 구조 (블라인드 철학 보존)
- hint_level 0: 순수 블라인드 (현재 AIBB 그대로)
- hint_level 1: 취약점 카테고리만 공개 (예: "명령어 주입류")
- hint_level 2: 주입 surface 공개 (예: "HTTP 헤더")
- hint_level 3: full playbook fallback (영주님 결정론적 agent.py)

각 단계에서 N번 시도 후 실패하면 다음 레벨로 승급.
연구 가치 = "LLM이 몇 단계 힌트에서 풀 수 있나"의 측정.

## 작업 원칙
- 모든 코드 변경 전 git commit으로 백업
- 타겟 화이트리스트 가드를 우회하는 코드 작성 금지
- API 키는 절대 코드에 하드코딩 X, .env 사용
- requirements.txt 항상 최신 유지

## 관련 저장소
- 본 저장소 (개인): https://github.com/kyojune76/AIBB-Solo
- 팀원(영주) vuln_db: https://github.com/12wndud05/AI-agent
