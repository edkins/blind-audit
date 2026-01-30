FROM alpine:3.19

RUN apk add --no-cache openssl bash dos2unix

COPY setup-pki.sh /setup-pki.sh
RUN dos2unix /setup-pki.sh
RUN chmod +x /setup-pki.sh

ENTRYPOINT ["/setup-pki.sh"]