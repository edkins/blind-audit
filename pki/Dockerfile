FROM alpine:3.19

RUN apk add --no-cache openssl bash

COPY setup-pki.sh /setup-pki.sh
RUN chmod +x /setup-pki.sh

ENTRYPOINT ["/setup-pki.sh"]