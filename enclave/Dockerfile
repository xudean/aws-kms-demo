FROM scratch

COPY rootfs /

ENV AWS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    LD_LIBRARY_PATH=/opt/enclave/lib \
    RUST_BACKTRACE=1

WORKDIR /app

ENTRYPOINT ["/app/decrypt-server-tee"]
