FROM docker.io/alpine:latest
RUN apk add --no-cache openssl bash
COPY generate.sh /generate.sh
RUN chmod +x /generate.sh
ENTRYPOINT ["/generate.sh"]