# AIBB-Solo

AI-based Autonomous Penetration Testing System (Personal Research Version)

## Overview

LLM 기반 자율 침투 테스트 시스템. 
CVE 취약점을 AI가 스스로 탐지하고 공격하는 완전 자동화 도구.

## Features

-  Docker 기반 격리 환경
-  Nmap + Nuclei 통합 스캐너
-  LLM 기반 페이로드 생성 (Claude)
-  피드백 루프 기반 학습
-  Phase별 공격 전략 (Basic → Encoding → Advanced → Creative)

## Architecture

## Tech Stack

- Python 3.11+
- Docker & Docker Compose
- Nmap, Nuclei
- Claude API
- WSL2 Ubuntu 24.04

## System Dependencies

이 프로젝트는 pip 패키지 외에 아래 외부 도구가 시스템에 설치돼 있어야 합니다.
(requirements.txt 만으로는 실행되지 않습니다.)

| 도구 | 용도 | 설치 |
|------|------|------|
| Python 3.11+ | 런타임 | `sudo apt install python3 python3-venv python3-pip` |
| Nmap | 포트/서비스 스캔 | `sudo apt install nmap` |
| Nuclei | 취약점 스캔 | 아래 참고 |
| Docker + Compose v2 | 타겟 컨테이너 기동 | 아래 참고 |

### Nuclei

Go 기반 도구입니다. Go가 설치돼 있다면:

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

또는 릴리스 바이너리를 직접 받아 PATH에 추가:

```bash
# 예시 (버전/아키텍처는 환경에 맞게)
curl -sL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip -o nuclei.zip
unzip nuclei.zip && sudo mv nuclei /usr/local/bin/
nuclei -version
```

### Docker + Compose v2

```bash
# Docker Engine 설치 후 compose v2 플러그인 확인
docker compose version   # v2 는 'docker compose' (하이픈 없음)
```

> 이 프로젝트는 `docker compose` (v2) 명령을 사용합니다. 구버전 `docker-compose` (v1) 가 아닙니다.

## Setup

```bash
# 1. 저장소 클론
git clone https://github.com/kyojune76/AIBB-Solo.git
cd AIBB-Solo

# 2. 가상환경 생성 및 활성화
python3 -m venv .venv
source .venv/bin/activate

# 3. Python 의존성 설치
pip install -r requirements.txt

# 4. 환경변수 설정 (.env.example 복사 후 API 키 입력)
cp .env.example .env
#   .env 를 열어 ANTHROPIC_API_KEY 값을 채워주세요

# 5. 공격자 박스 + 타겟 컨테이너 기동
docker compose -f attacker/docker-compose.yml up -d        # 공격자 박스(aibb-attacker)
docker compose -f targets/shellshock/docker-compose.yml up -d   # 타겟 예: t1

# 6. 실행 (능력 래더 L0~L3 자동 승급)
python run_blind.py t1     # t1=Shellshock, t2=Spring4Shell
```

> 안전 범위: 로컬 vulhub 도커 격리 환경 전용. 허용 타겟은 127.0.0.1 / localhost / 도커 내부망뿐입니다. 외부 시스템 대상 공격 금지.

## Current Status

✅ Nmap Scanner Integration
✅ Blind-mode Attack Bot (ReAct 루프 + 능력 래더 L0~L3)
✅ 타겟 화이트리스트 가드 (http_request + bash 채널)
 Multi-CVE Support (In Progress)

## Targets

- CVE-2014-6271 (Shellshock) ✅
- CVE-2017-5638 (Struts2) 
- CVE-2021-44228 (Log4Shell) 

## Personal Notes

이 버전은 개인 연구용입니다.
팀 프로젝트 버전: https://github.com/Hyeon2550/2026_DAST_TEAM

## Author

교준 (Kyojune Lee)
