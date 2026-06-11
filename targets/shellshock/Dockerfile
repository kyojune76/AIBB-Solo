FROM vulhub/bash:4.3.0-with-httpd

# Flag 삽입
RUN echo "FLAG{shellshock_rce_2024}" > /tmp/flag.txt && \
    chmod 644 /tmp/flag.txt

# CGI 스크립트 복사
# Debian Apache 기본 ScriptAlias(/cgi-bin/ -> /usr/lib/cgi-bin/)에 평범한 이름으로 배치.
# 봇이 워드리스트 정찰로 발견 가능하게 함 (블라인드 발견 채널 = 현실의 디폴트 CGI 경로).
#   victim.cgi(취약) -> /cgi-bin/test.cgi
#   safe.cgi(안전)   -> /cgi-bin/info.cgi  (대조군)
COPY victim.cgi /usr/lib/cgi-bin/test.cgi
COPY safe.cgi /usr/lib/cgi-bin/info.cgi
RUN chmod +x /usr/lib/cgi-bin/test.cgi /usr/lib/cgi-bin/info.cgi
