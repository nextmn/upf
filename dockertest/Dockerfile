FROM debian:bullseye-slim
RUN apt-get update -q && DEBIAN_FRONTEND=non-interactive apt-get install -qy --no-install-recommends --no-install-suggests \
    iproute2 iputils-ping tshark iptables build-essential bash-completion \
    && rm -rf /var/lib/apt/lists/*
