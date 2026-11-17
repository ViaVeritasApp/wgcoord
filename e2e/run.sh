#!/usr/bin/env bash
# End-to-end tests for wgcoord in Docker: a coordinator, two k3s-like nodes
# with emulated pod ranges and services, two hub-only developers, and a
# database in a private network only the coordinator can reach.
#
#   ./e2e/run.sh          build, run every scenario, tear down
#   KEEP=1 ./e2e/run.sh   leave the containers running afterwards
#
# Needs Docker with a kernel that has WireGuard and nftables (Docker Desktop
# and any recent Linux do).
set -uo pipefail
cd "$(dirname "$0")"

PASS=0
FAIL=0
FAILED=()

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
pass() { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); FAILED+=("$*"); printf '  \033[31mFAIL\033[0m %s\n' "$*"; }

# Containers are named wgcoord-e2e-<host>; scenarios use the bare host name.
# dx is `docker exec` with that prefix added.
dx() {
	local opts=()
	while [[ "$1" == -* ]]; do opts+=("$1"); shift; done
	local c=$1; shift
	docker exec "${opts[@]}" "wgcoord-e2e-$c" "$@"
}
# x <host> <shell>: run a shell snippet on a host.
x() { dx "$1" sh -c "$2"; }
# W <host> <wgcoord args...>
W() { local c=$1; shift; dx "$c" wgcoord "$@"; }

# expect / refuse <desc> <cmd...>: pass when the command succeeds / fails.
expect() { local d=$1; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d"; fi; }
refuse() { local d=$1; shift; if "$@" >/dev/null 2>&1; then fail "$d"; else pass "$d"; fi; }

# eventually <secs> <desc> <cmd...>: pass once the command succeeds.
eventually() {
	local t=$1 d=$2; shift 2
	local end=$((SECONDS + t))
	while ((SECONDS < end)); do
		if "$@" >/dev/null 2>&1; then pass "$d"; return 0; fi
		sleep 1
	done
	fail "$d (still failing after ${t}s)"
}

# open <container> <ip> <port>: a TCP connection gets the service's banner.
open() {
	local out
	out=$(dx "$1" sh -c "socat -T2 - TCP:$2:$3,connect-timeout=2 </dev/null 2>/dev/null")
	[[ "$out" == *":$3"* || "$out" == clouddb* ]]
}
closed() { ! open "$@"; }
pingable() { x "$1" "ping -c1 -W2 $2"; }
# peers <host> <n>: the host's wg0 holds exactly n peers.
peers() { [[ "$(x "$1" 'wg show wg0 peers | wc -l')" -eq "$2" ]]; }
# stop <host> <coordinator|client>: kill wgcoord's daemon. The pattern is
# anchored so it can't match the `sh -c` running pkill itself.
stop() { x "$1" "pkill -f '^wgcoord $2 run'"; }

# errs <desc> <expected substring> <container> <wgcoord args...>: the command
# must fail with an error mentioning the substring.
errs() {
	local d=$1 want=$2 c=$3; shift 3
	local out
	if out=$(dx "$c" wgcoord "$@" 2>&1); then
		fail "$d (succeeded: $out)"
	elif [[ "$out" == *"$want"* ]]; then
		pass "$d"
	else
		fail "$d (got: $out)"
	fi
}

token_of() { awk '/token:/ {print $2; exit}'; }

cleanup() {
	if [[ "${KEEP:-0}" == "1" ]]; then
		echo "KEEP=1: containers left running (docker compose -f e2e/compose.yaml down to remove)"
	else
		docker compose down -v --remove-orphans >/dev/null 2>&1
	fi
}

# ---------------------------------------------------------------------------
step "Build and start"
case "$(docker info --format '{{.Architecture}}')" in
aarch64 | arm64) GOARCH=arm64 ;;
*) GOARCH=amd64 ;;
esac
(cd .. && CGO_ENABLED=0 GOOS=linux GOARCH=$GOARCH go build -o e2e/wgcoord ./cmd/wgcoord) || exit 1
docker build -q -t wgcoord-e2e:latest . >/dev/null || exit 1
docker compose down -v --remove-orphans >/dev/null 2>&1
docker compose up -d >/dev/null || exit 1
trap cleanup EXIT

# Fake services. Every listener answers with "<host>:<port>" (socat needs the
# colon escaped, or it reads it as an address separator).
for spec in coordinator:10.42.0.10 node1:10.42.1.10 node2:10.42.2.10; do
	h=${spec%%:*} pod=${spec#*:}
	x "$h" "ip link add pods type dummy && ip addr add $pod/24 dev pods && ip link set pods up"
	for p in 15432 16379 25432 26379 35432 8080 9090 9999; do
		dx -d "$h" socat TCP-LISTEN:$p,fork,reuseaddr SYSTEM:"echo $h\\:$p"
	done
done
x node2 "ip link add lan type dummy && ip addr add 192.168.60.10/24 dev lan && ip addr add 192.168.61.10/24 dev lan && ip link set lan up"
for h in alice bob; do dx -d "$h" socat TCP-LISTEN:7000,fork,reuseaddr SYSTEM:"echo $h\\:7000"; done
dx -d clouddb sh -c 'socat TCP4-LISTEN:5432,fork,reuseaddr SYSTEM:"echo clouddb saw \$SOCAT_PEERADDR"'
pass "containers and fake services up"

# ---------------------------------------------------------------------------
step "Coordinator, mesh nodes and groups"
W coordinator coordinator init --public-ip 172.28.0.10 --address 10.8.0.1 >/dev/null
TOK_N1=$(W coordinator coordinator client add node1 --address 10.8.0.11 | token_of)
TOK_N2=$(W coordinator coordinator client add node2 --address 10.8.0.12 | token_of)
W coordinator coordinator route add coordinator 10.42.0.0/24 >/dev/null
W coordinator coordinator route add node1 10.42.1.0/24 >/dev/null
W coordinator coordinator route add node2 10.42.2.0/24 >/dev/null
W coordinator coordinator group create development 10.8.0.0/28 --port tcp/15432 --port tcp/16379 >/dev/null
W coordinator coordinator group create staging 10.8.0.0/28 --port tcp/25432 --port tcp/26379 >/dev/null
W coordinator coordinator group create production 10.8.0.0/28 --port tcp/35432 >/dev/null
W coordinator coordinator group create lan2 192.168.60.0/24 >/dev/null
W coordinator coordinator route add node2 lan2 >/dev/null
TOK_AL=$(W coordinator coordinator client add alice --hub-only --address 10.8.0.101 --grant development --grant staging | token_of)
TOK_BO=$(W coordinator coordinator client add bob --hub-only --address 10.8.0.102 --grant all | token_of)
[[ -n "$TOK_N1" && -n "$TOK_N2" && -n "$TOK_AL" && -n "$TOK_BO" ]] && pass "clients created" || fail "clients created"

dx -d coordinator sh -c 'wgcoord coordinator run >/var/log/wgcoord.log 2>&1'
sleep 1
join() { # <host> <token> [public-ip]
	local pub=()
	[[ -n "${3:-}" ]] && pub=(--public-ip "$3")
	W "$1" client join --server http://172.28.0.10:51821 --token "$2" --heartbeat 3 "${pub[@]}" >/dev/null &&
		dx -d "$1" sh -c 'wgcoord client run >/var/log/wgcoord.log 2>&1'
}
join node1 "$TOK_N1" 172.28.0.21 && join node2 "$TOK_N2" 172.28.0.22 && join alice "$TOK_AL" && join bob "$TOK_BO"
expect "every client joined" true
# Stand-in for the CNI: mesh nodes route the other nodes' pod ranges into wg0.
x node1 "ip route add 10.42.0.0/24 dev wg0; ip route add 10.42.2.0/24 dev wg0"
x node2 "ip route add 10.42.0.0/24 dev wg0; ip route add 10.42.1.0/24 dev wg0"

# ---------------------------------------------------------------------------
step "Mesh baseline (unchanged behaviour)"
# The coordinator adds newly registered peers at its next reconcile (≤15s).
eventually 30 "the coordinator holds all four clients" peers coordinator 4
eventually 30 "node1 → node2 over the mesh" pingable node1 10.8.0.12
eventually 10 "node1 → node2 pod" open node1 10.42.2.10 8080
eventually 10 "node2 → coordinator pod" open node2 10.42.0.10 9090
expect "node2 → node1 group-free route" open node2 10.42.1.10 9090
expect "node1 holds no hub-only peers" peers node1 2
expect "node1 routes alice and bob via the coordinator" sh -c "docker exec wgcoord-e2e-node1 wg show wg0 allowed-ips | grep -q '10.8.0.101/32.*10.8.0.102/32\|10.8.0.102/32.*10.8.0.101/32'"

# ---------------------------------------------------------------------------
step "alice: hub-only with development + staging"
eventually 30 "alice reaches the coordinator" pingable alice 10.8.0.1
expect "alice holds exactly one peer" peers alice 1
expect "alice status says hub-only" sh -c "docker exec wgcoord-e2e-alice wgcoord client status | grep -q 'mode hub-only'"
expect "alice's coordinator AllowedIPs are just the mesh" sh -c "docker exec wgcoord-e2e-alice wg show wg0 allowed-ips | grep -q '10.8.0.0/24\$'"
expect "alice installed no extra routes (grants are inside the mesh)" test -z "$(x alice 'ip route show proto 211')"
eventually 20 "alice → node1 dev postgres (15432)" open alice 10.8.0.11 15432
expect "alice → node2 dev redis (16379)" open alice 10.8.0.12 16379
expect "alice → node2 staging postgres (25432)" open alice 10.8.0.12 25432
expect "alice → coordinator's own staging redis (26379)" open alice 10.8.0.1 26379
refuse "alice ✗ node1 production (35432)" open alice 10.8.0.11 35432
refuse "alice ✗ node1 other port (8080)" open alice 10.8.0.11 8080
refuse "alice ✗ coordinator private service (9999)" open alice 10.8.0.1 9999
refuse "alice ✗ node1 pod" open alice 10.42.1.10 8080
refuse "alice ✗ bob" open alice 10.8.0.102 7000
refuse "alice ✗ ping node1" pingable alice 10.8.0.11
expect "alice → coordinator control plane over the mesh" x alice "curl -sf -m3 http://10.8.0.1:51821/healthz"
eventually 10 "node1 → alice (replies route back through the coordinator)" open node1 10.8.0.101 7000

# ---------------------------------------------------------------------------
step "alice edits her own WireGuard config (spoofing a grant)"
HUBKEY=$(x alice "wg show wg0 peers")
stop alice client
x alice "wg set wg0 peer $HUBKEY allowed-ips 10.8.0.0/24,10.42.0.0/16 && ip route replace 10.42.0.0/16 dev wg0"
before=$(x coordinator "nft list table inet wgcoord | grep -A20 'comment \"alice\"' >/dev/null; nft list chain inet wgcoord client_0 | awk '/counter/ {print \$3}'")
refuse "alice ✗ node1 pod even with forged AllowedIPs" open alice 10.42.1.10 8080
refuse "alice ✗ node1 production even with forged AllowedIPs" open alice 10.8.0.11 35432
after=$(x coordinator "nft list chain inet wgcoord client_0 | awk '/counter/ {print \$3}'")
expect "the coordinator's firewall dropped those packets (counter $before → $after)" test "${after:-0}" -gt "${before:-0}"
x alice "ip route del 10.42.0.0/16 dev wg0"
dx -d alice sh -c 'wgcoord client run >>/var/log/wgcoord.log 2>&1'
eventually 15 "alice's client restores its AllowedIPs on the next beat" sh -c "docker exec wgcoord-e2e-alice wg show wg0 allowed-ips | grep -q '10.8.0.0/24\$'"

# ---------------------------------------------------------------------------
step "bob: hub-only with all"
eventually 30 "bob → node1 pod" open bob 10.42.1.10 8080
expect "bob → node2 pod" open bob 10.42.2.10 9090
expect "bob → coordinator pod" open bob 10.42.0.10 9999
expect "bob → node1 production" open bob 10.8.0.11 35432
expect "bob → coordinator private service" open bob 10.8.0.1 9999
expect "bob → node2 LAN via the lan2 group route" open bob 192.168.60.10 8080
expect "bob → alice (alice's reply goes back via the coordinator)" open bob 10.8.0.101 7000
expect "bob has kernel routes for the pod ranges" sh -c "docker exec wgcoord-e2e-bob ip route show proto 211 | grep -q 10.42.1.0/24"

# ---------------------------------------------------------------------------
step "Group used as a route follows edits"
W coordinator coordinator group add lan2 192.168.61.0/24 >/dev/null
eventually 30 "bob → 192.168.61.10 after adding it to lan2" open bob 192.168.61.10 8080
W coordinator coordinator group remove lan2 192.168.61.0/24 >/dev/null
eventually 30 "bob ✗ 192.168.61.10 after removing it" closed bob 192.168.61.10 8080

# ---------------------------------------------------------------------------
step "Live grant and group changes"
W coordinator coordinator grant add alice 10.42.0.0/16 --port tcp/8080 >/dev/null
eventually 30 "alice → node1 pod :8080 after grant" open alice 10.42.1.10 8080
expect "alice → coordinator pod :8080" open alice 10.42.0.10 8080
refuse "alice ✗ node1 pod :9090 (not granted)" open alice 10.42.1.10 9090
expect "alice now routes the pod ranges" sh -c "docker exec wgcoord-e2e-alice ip route show proto 211 | grep -c 10.42 | grep -qx 3"
W coordinator coordinator group add development 10.8.0.0/28 --port tcp/9090 >/dev/null
eventually 30 "alice → node2 :9090 after adding it to development" open alice 10.8.0.12 9090
W coordinator coordinator grant remove alice 10.42.0.0/16 >/dev/null
eventually 30 "alice ✗ node1 pod after revoke" closed alice 10.42.1.10 8080
eventually 15 "alice's pod routes are removed" test -z "$(x alice 'ip route show proto 211')"

# ---------------------------------------------------------------------------
step "Revoking while the client is offline"
stop alice client
W coordinator coordinator grant remove alice staging >/dev/null
eventually 30 "alice ✗ staging though her client never heard about it" closed alice 10.8.0.12 25432
expect "alice → development still works" open alice 10.8.0.11 15432
W coordinator coordinator grant add alice staging >/dev/null
dx -d alice sh -c 'wgcoord client run >>/var/log/wgcoord.log 2>&1'
eventually 30 "alice → staging again after re-grant" open alice 10.8.0.12 25432

# ---------------------------------------------------------------------------
step "NAT route to a network next to the coordinator"
refuse "alice ✗ clouddb before any route" open alice 172.30.0.5 5432
errs "a grant nothing routes is refused" "reaches nothing the mesh routes" coordinator coordinator grant add alice 172.30.0.5/32
W coordinator coordinator group create cloud-net 172.30.0.0/24 >/dev/null
W coordinator coordinator route add coordinator cloud-net --nat >/dev/null
W coordinator coordinator grant add alice 172.30.0.5/32 --port tcp/5432 >/dev/null
eventually 30 "alice → clouddb:5432 through NAT" open alice 172.30.0.5 5432
expect "clouddb sees the coordinator's address, not alice's" sh -c "docker exec wgcoord-e2e-alice socat -T2 - TCP:172.30.0.5:5432 </dev/null | grep -q 'saw 172.30.0.2'"
expect "alice routes only the granted /32" sh -c "docker exec wgcoord-e2e-alice ip route show proto 211 | grep -q '^172.30.0.5 dev wg0 scope link metric 1000'"
eventually 30 "bob (all) → clouddb too" open bob 172.30.0.5 5432
# Mesh clients get AllowedIPs only; the kernel route is the operator's (or CNI's).
x node1 "ip route add 172.30.0.0/24 dev wg0"
eventually 10 "node1 (mesh) → clouddb via the coordinator's NAT route" open node1 172.30.0.5 5432

# ---------------------------------------------------------------------------
step "Blacklisting a hub-only client"
W coordinator coordinator blacklist alice >/dev/null
eventually 30 "blacklisted alice ✗ development" closed alice 10.8.0.11 15432
eventually 15 "alice's /32 leaves node1's view of the coordinator" sh -c "! docker exec wgcoord-e2e-node1 wg show wg0 allowed-ips | grep -q 10.8.0.101"
W coordinator coordinator blacklist remove alice >/dev/null
eventually 40 "alice → development after unblacklisting" open alice 10.8.0.11 15432

# ---------------------------------------------------------------------------
step "Switching alice to mesh and back"
errs "mesh switch with grants needs --clear-grants" "--clear-grants" coordinator coordinator client mode alice mesh
W coordinator coordinator client mode alice mesh --clear-grants >/dev/null
eventually 30 "alice holds every node as a peer" peers alice 3
eventually 30 "alice (mesh) → node1 production directly" open alice 10.8.0.11 35432
expect "alice status says mesh" sh -c "docker exec wgcoord-e2e-alice wgcoord client status | grep -q 'mode mesh'"
W coordinator coordinator client mode alice hub-only >/dev/null
W coordinator coordinator grant add alice development >/dev/null
eventually 30 "alice is back to one peer" peers alice 1
eventually 30 "node1 dropped alice as a peer" peers node1 2
eventually 30 "alice → development again" open alice 10.8.0.11 15432
# Mesh → hub-only narrows access at the coordinator's next reconcile (≤15s),
# like any revoke; until then alice keeps the access she had as a mesh client.
eventually 30 "alice ✗ production again" closed alice 10.8.0.11 35432

# ---------------------------------------------------------------------------
step "Failing closed when the firewall can't be applied"
x coordinator "mv /usr/sbin/nft /usr/sbin/nft.off"
eventually 30 "hub-only peers are taken off the coordinator" peers coordinator 2
refuse "alice ✗ development while unenforced" open alice 10.8.0.11 15432
expect "the coordinator logged why" sh -c "docker exec wgcoord-e2e-coordinator grep -q 'left off wg0' /var/log/wgcoord.log"
expect "mesh traffic is unaffected" open node1 10.42.2.10 8080
x coordinator "mv /usr/sbin/nft.off /usr/sbin/nft"
eventually 30 "alice → development once enforcement is back" open alice 10.8.0.11 15432

# ---------------------------------------------------------------------------
step "Coordinator restart (firewall and interface gone, as after a reboot)"
stop coordinator coordinator
x coordinator "nft delete table inet wgcoord; ip link del wg0"
refuse "nothing works while it is down" open alice 10.8.0.11 15432
dx -d coordinator sh -c 'wgcoord coordinator run >>/var/log/wgcoord.log 2>&1'
eventually 40 "alice → development after restart" open alice 10.8.0.11 15432
refuse "alice ✗ production after restart" open alice 10.8.0.11 35432
expect "the firewall table is back" x coordinator "nft list table inet wgcoord"
eventually 30 "bob → node2 pod after restart" open bob 10.42.2.10 8080

# ---------------------------------------------------------------------------
step "CLI refusals"
errs "--grant without --hub-only" "--grant needs --hub-only" coordinator coordinator client add carol --grant development
errs "grant on a mesh client" "mesh client" coordinator coordinator grant add node1 all
errs "deleting a group in use" "still used by" coordinator coordinator group delete development
errs "port-limited group as a route" "can't be used as a route" coordinator coordinator route add node1 staging
errs "prefix routed by two nodes" "routed by both" coordinator coordinator route add node2 10.42.1.0/24
errs "--nat on a client" "--nat is only valid" coordinator coordinator route add node1 10.99.0.0/16 --nat
errs "route inside the mesh range" "inside the mesh range" coordinator coordinator route add node1 10.8.0.128/25
errs "routes on a hub-only client" "can't carry routes" coordinator coordinator route add alice 10.70.0.0/24
errs "reserved group name" "reserved" coordinator coordinator group create all
errs "mistyped CIDR" "not a valid CIDR or group name" coordinator coordinator grant add alice 10.42.1.0/33
errs "bad port" "invalid port" coordinator coordinator grant add alice 10.42.0.0/24 --port http/80

# ---------------------------------------------------------------------------
printf '\n\033[1m%d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
if ((FAIL > 0)); then
	printf '  - %s\n' "${FAILED[@]}"
	echo
	echo "Logs: docker exec wgcoord-e2e-<host> cat /var/log/wgcoord.log  (rerun with KEEP=1 to keep the containers)"
	exit 1
fi
