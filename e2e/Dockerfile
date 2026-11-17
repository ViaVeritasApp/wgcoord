# Test image for the e2e suite: wgcoord plus the tools it drives (wg, ip, nft)
# and socat for the fake services the scenarios connect to.
FROM alpine:3.20
RUN apk add --no-cache wireguard-tools iproute2 nftables socat curl bash iputils procps
COPY wgcoord /usr/local/bin/wgcoord
CMD ["sleep", "infinity"]
