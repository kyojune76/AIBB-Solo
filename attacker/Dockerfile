# AIBB 공격자 박스 (attacker box)
# LLM의 bash 툴이 여기 안에서 실행된다. 호스트(네 PC)와 격리됨.
# 웹쉘 파일 작성 -> 타겟 업로드 -> 호출, 리버스 셸 캐치 등을 수행.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget ca-certificates \
    netcat-openbsd \
    python3 \
    nmap \
    dnsutils iputils-ping \
    jq vim-tiny \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
