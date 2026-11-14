FROM debian:bookworm-20261104-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

LABEL org.opencontainers.image.description="software TPM root -- not hardware-backed"
RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf automake build-essential ca-certificates curl libtool pkg-config \
    libssl-dev libglib2.0-dev libjson-glib-dev libseccomp-dev libgmp-dev \
    libtasn1-6-dev gawk socat && rm -rf /var/lib/apt/lists/*
WORKDIR /build
RUN curl --fail --location --max-time 120 -o libtpms.tar.gz \
      https://codeload.github.com/stefanberger/libtpms/tar.gz/refs/tags/v0.10.2 && \
    echo 'edac03680f8a4a1c5c1d609a10e3f41e1a129e38ff5158f0c8deaedc719fb127  libtpms.tar.gz' | sha256sum -c - && \
    tar xzf libtpms.tar.gz && cd libtpms-0.10.2 && \
    ./autogen.sh --with-openssl --without-tpm1 --with-tpm2 --prefix=/usr/local && \
    make -j2 && make install && ldconfig
RUN curl --fail --location --max-time 120 -o swtpm.tar.gz \
      https://codeload.github.com/stefanberger/swtpm/tar.gz/refs/tags/v0.10.2 && \
    echo 'f61cf6f1e9bbcb4cefb30b70cafaf1c4df54c6961e65cfa63830e8ad0e220134  swtpm.tar.gz' | sha256sum -c - && \
    tar xzf swtpm.tar.gz && cd swtpm-0.10.2 && \
    ./autogen.sh --with-openssl --without-gnutls --without-cuse --without-selinux --disable-tests --prefix=/usr/local && \
    make -j2 && make install && ldconfig && swtpm --version
WORKDIR /state
RUN chown 65532:65532 /state && chmod 0700 /state
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/swtpm", "socket", "--tpm2", "--tpmstate", "dir=/state,mode=0600", "--server", "type=tcp,port=2321,bindaddr=0.0.0.0", "--ctrl", "type=tcp,port=2322,bindaddr=127.0.0.1", "--flags", "not-need-init,startup-clear"]
