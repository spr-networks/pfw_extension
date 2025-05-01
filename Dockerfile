FROM ubuntu:24.04 as builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get install -y nftables iproute2 inetutils-ping net-tools nano ca-certificates git curl
RUN mkdir /code
WORKDIR /code
ARG TARGETARCH
RUN curl -O https://dl.google.com/go/go1.20.linux-${TARGETARCH}.tar.gz
RUN rm -rf /usr/local/go && tar -C /usr/local -xzf go1.20.linux-${TARGETARCH}.tar.gz
ENV PATH="/usr/local/go/bin:$PATH"
COPY code/ /code/

RUN --mount=type=tmpfs,target=/root/go/ (go build -ldflags "-s -w" -o /pfw /code/)


FROM ghcr.io/spr-networks/container_template:latest
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends wireguard-tools iw jc && rm -rf /var/lib/apt/lists/*
COPY scripts /scripts/
COPY --from=builder /pfw /
RUN mkdir -p /root/.local/share/jc/jcparsers
COPY scripts/iw*.py /root/.local/share/jc/jcparsers
ENTRYPOINT ["/scripts/startup.sh"]
