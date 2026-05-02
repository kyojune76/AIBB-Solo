# AIBB-Solo

AI-based Autonomous Penetration Testing System (Personal Research Version)

## Overview

LLM 기반 자율 침투 테스트 시스템. 
CVE 취약점을 AI가 스스로 탐지하고 공격하는 완전 자동화 도구.

## Features

-  Docker 기반 격리 환경
-  Nmap + Nuclei 통합 스캐너
-  LLM 기반 페이로드 생성 (Gemini/Claude)
-  피드백 루프 기반 학습
-  Phase별 공격 전략 (Basic → Encoding → Advanced → Creative)

## Architecture

## Tech Stack

- Python 3.11+
- Docker & Docker Compose
- Nmap, Nuclei
- Gemini API / Claude API
- WSL2 Ubuntu 24.04

## Current Status

✅ Docker Manager
✅ Scanner Integration
✅ Main Pipeline
 Autonomous Attack Bot (In Progress)
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
