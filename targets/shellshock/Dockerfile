FROM vulhub/bash:4.3.0-with-httpd

# Flag 삽입
RUN echo "FLAG{shellshock_rce_2024}" > /tmp/flag.txt && \
    chmod 644 /tmp/flag.txt

# CGI 스크립트 복사
COPY safe.cgi /var/www/html/safe.cgi
COPY victim.cgi /var/www/html/victim.cgi
RUN chmod +x /var/www/html/*.cgi
