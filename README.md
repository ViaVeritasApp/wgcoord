# wgcoord

A small CLI that coordinates a **full-mesh WireGuard** network. One host runs as
the **coordinator** (the control-plane hub); every other host is a **client**
that authenticates with its own token, exchanges public keys through the hub,
and heartbeats to stay in sync.

- Two modes: `wgcoord coordinator …` (alias `coord`) and `wgcoord client …`.
- Full mesh: every client peers with the hub **and** with every other client.
  The hub does not relay client-to-client traffic.
- Hub-only clients (laptops, contractors, CI runners) peer with the hub alone.
  The hub forwards their traffic and its firewall limits it to the ranges and
  ports they were granted. See [Restricting access](#restricting-access-hub-only-clients).
- No database, no UI. All state is one `config.json`, written `0600`.
- Live apply on **Linux** (kernel WireGuard, `wg syncconf` + `ip`) and **macOS**
  (wireguard-go via `wg-quick`). Elsewhere a `wg-quick` `.conf` is written to
  bring up by hand.

## How it works

```
                 control plane (TCP :51821)             WireGuard (UDP :51820)
   ┌────────────┐  register / heartbeat   ┌────────────┐        full mesh
   │  client A  │ ──────────────────────▶ │ coordinator│◀── udp ──▶ client A
   │            │ ◀── missing peers ───── │   (hub)    │◀── udp ──▶ client B
   └────────────┘                         └────────────┘             ▲   ▲
        ▲  ▲                                                         │   │
        └──┴──────────────── client A ◀── udp ──▶ client B ──────────┘   │
                             (peers exchanged via the coordinator)       │
```

- `POST /register` — the client sends its public key and endpoint, and gets a
  mesh IP plus the current peer set.
- `POST /heartbeat` — the client lists the peers it holds; the hub answers with
  the ones it is missing and the ones to remove.
- Both need `Authorization: Bearer <token>`. The hub reconciles its own
  interface from the registry every ~15s.
- A peer's advertised endpoint is its `--public-ip` plus its **own** WireGuard
  listen port. A client joined without `--public-ip` has none and is dial-out only.

**The control plane moves inside the mesh once the tunnel is up.** `register`
always uses the public URL, since no tunnel exists yet. Every response carries
the hub's in-mesh URL (e.g. `http://10.8.0.1:51821`), and heartbeats prefer it.
On a transport failure (dial error, timeout, 5xx) the client uses the public URL
for 5 minutes; a `401`/`403` is not retried, since it proves the mesh path works.
`register` carries the token in the clear, so serve the control plane over
[HTTPS](#https).

## Install

Requires Go ≥ 1.25.

```bash
make build            # -> ./wgcoord
sudo make install     # -> /usr/local/bin/wgcoord
```

Live apply also needs root and wireguard-tools:

```bash
sudo apt install wireguard-tools iproute2          # Linux
brew install wireguard-tools wireguard-go          # macOS (userspace, utun device)
```

## Quick start

```bash
# on the hub
sudo wgcoord coordinator init --public-ip 203.0.113.1
sudo wgcoord coordinator client add laptop          # prints the token and the join command
sudo wgcoord coordinator run

# on the client
sudo wgcoord client join --server http://203.0.113.1:51821 --token <TOKEN>
sudo wgcoord client run
```

For anything long-lived, run both under [systemd](#running-as-a-service-systemd).

## Configuration file

Resolved in order: `--config <path>` (any command), `$WGCOORD_CONFIG`,
`/etc/wgcoord/config.json` as root, else `~/.config/wgcoord/config.json`. It
holds private keys and, on clients, the token.

Root and your own user resolve **different files**. Run every command as the
daemon's user, which means `sudo`:

```bash
sudo wgcoord coordinator status                             # /etc/wgcoord/config.json
wgcoord --config /etc/wgcoord/config.json coordinator status  # same file, explicitly
```

## Coordinator

Management commands edit `config.json` under a file lock; a running
`coordinator run` picks the change up within ~15s.

| Command | What it does | Example |
|---|---|---|
| `coordinator init` | Make this host the hub: write config, generate its keypair. | `wgcoord coordinator init --public-ip 203.0.113.1` |
| `coordinator run` | Serve the control plane and manage the hub interface (alias `serve`). | `wgcoord coordinator run` |
| `coordinator status` | Show the hub and every client. | `wgcoord coordinator status` |
| `coordinator client add <name>` | Create a client; prints its token and join command. | `wgcoord coordinator client add laptop` |
| `coordinator client remove <name>` | Delete a client (aliases `rm`, `delete`). | `wgcoord coordinator client remove laptop` |
| `coordinator client rename <old> <new>` | Rename a client. | `wgcoord coordinator client rename laptop workstation` |
| `coordinator client mode <name> mesh\|hub-only` | Switch a client's mode. Leaving hub-only with grants needs `--clear-grants`. | `wgcoord coordinator client mode laptop hub-only` |
| `coordinator route add <node> <cidr\|group>…` | Add routes a node carries. `<node>` is a client or `coordinator`; `--nat` marks a network next to the coordinator. | `wgcoord coordinator route add node1 10.12.1.0/24` |
| `coordinator route remove <node> <cidr\|group>…` | Drop routes (aliases `rm`, `delete`). | `wgcoord coordinator route remove node1 10.12.1.0/24` |
| `coordinator route list [<node>]` | Show one node's routes, or all. | `wgcoord coordinator route list` |
| `coordinator group create <name> [<cidr>…]` | Create a named group of CIDRs; `--port` limits the CIDRs given with it. | `wgcoord coordinator group create staging 10.8.0.0/28 --port tcp/25432` |
| `coordinator group add\|remove <name> <cidr>…` | Edit a group; every grant and route using it follows. | `wgcoord coordinator group add staging 10.8.0.0/28 --port tcp/26379` |
| `coordinator group delete <name>` | Delete a group nothing uses. | `wgcoord coordinator group delete staging` |
| `coordinator group list`, `group show <name>` | Show groups and what uses them. | `wgcoord coordinator group show staging` |
| `coordinator grant add <client> <cidr\|group\|all>…` | Let a hub-only client reach it; `--port` narrows it. | `wgcoord coordinator grant add laptop staging` |
| `coordinator grant remove <client> <cidr\|group\|all>…` | Revoke (aliases `rm`, `revoke`); enforced within ~15s. | `wgcoord coordinator grant remove laptop staging` |
| `coordinator grant list [<client>]` | Show grants and what they resolve to. | `wgcoord coordinator grant list laptop` |
| `coordinator token regenerate <name>` | Rotate a token; the old one stops working at once (aliases `regen`, `new`). | `wgcoord coordinator token regenerate laptop` |
| `coordinator blacklist <name>` | Refuse a client (`403`), drop it from the hub, and from every peer on their next heartbeat. | `wgcoord coordinator blacklist laptop` |
| `coordinator blacklist remove <name>` | Lift it; the client rejoins on its next heartbeat. | `wgcoord coordinator blacklist remove laptop` |

**`coordinator init` flags**

| Flag | Default | Description |
|---|---|---|
| `--public-ip` | (none) | IP/host clients dial. Clients can't join until one is set. |
| `--control-port` | `51821` | Control-plane TCP port. |
| `--wg-port` | `51820` | Hub WireGuard UDP port. |
| `--client-wg-port` | `51820` | Default WireGuard port advertised for clients. |
| `--ip-range` | `10.8.0.0/24` | Mesh address pool. |
| `--address` | first host | Hub's own mesh IP. |
| `--interface` | `wg0` | Interface name. |
| `--tls-cert`, `--tls-key` | (none) | Serve the control plane over HTTPS. |
| `--route` | (none) | CIDR the hub carries. Repeatable. |
| `--force` | `false` | Overwrite an existing config — **generates a new hub keypair**. |

**`coordinator client add` flags:** `--address` pins a mesh IP (default: lowest
free); `--route` adds a CIDR or group the client carries (repeatable);
`--hub-only` makes it a hub-only client; `--grant` gives a hub-only client a CIDR,
group or `all` (repeatable, port-free; use `grant add --port` for ports).

```bash
sudo wgcoord coordinator init \
  --public-ip 203.0.113.1 \
  --control-port 51821 \
  --wg-port 51820 \
  --ip-range 10.8.0.0/24 \
  --route 10.12.0.0/24
sudo wgcoord coordinator client add server-a --address 10.8.0.20 --route 10.12.1.0/24
```

## Client

| Command | What it does | Example |
|---|---|---|
| `client join` | Register with a token, write config, apply the first peer set. | `wgcoord client join --server http://203.0.113.1:51821 --token <TOKEN>` |
| `client run` | Heartbeat and keep the interface in sync (foreground). | `wgcoord client run` |
| `client sync` | One heartbeat, then re-apply. | `wgcoord client sync` |
| `client up` | Apply the cached peer set without calling the hub. | `wgcoord client up` |
| `client down` | Tear the interface down. | `wgcoord client down` |
| `client status` | This node, and each peer's name, AllowedIPs, key and endpoint. | `wgcoord client status` |
| `client endpoint set <peer> <host[:port]>` | Pin the address this node dials for a peer. | `wgcoord client endpoint set node2 192.168.1.52` |
| `client endpoint clear <peer>` | Back to the advertised endpoint (aliases `unset`, `rm`). | `wgcoord client endpoint clear node2` |
| `client endpoint list` | Show this node's overrides (alias `ls`). | `wgcoord client endpoint list` |

**`client join` flags**

| Flag | Default | Description |
|---|---|---|
| `--server` | (required) | Control-plane URL. |
| `--token` | (required) | Token from `coordinator client add`. |
| `--public-ip` | (none) | This node's public IP/host. Omit behind NAT to be dial-out only. |
| `--address` | auto | Request a mesh IP (granted if free). |
| `--interface` | `wg0` | Interface name. |
| `--wg-port` | `51820` | Local WireGuard UDP port — also the port peers dial. |
| `--keepalive` | `25` | Persistent keepalive, seconds. |
| `--heartbeat` | `25` | Heartbeat interval, seconds. |
| `--peer-endpoint` | (none) | `<peer>=<host[:port]>` override, set before the first handshake. Repeatable. |

```bash
# reachable from outside: the router forwards 51822/udp to this host's 51822
sudo wgcoord client join --server http://203.0.113.1:51821 --token <TOKEN> \
  --public-ip 198.51.100.7 --wg-port 51822

# behind NAT with nothing forwarded: dial-out only, kept open by keepalive
sudo wgcoord client join --server http://203.0.113.1:51821 --token <TOKEN>
```

### Endpoint overrides

The hub advertises each peer's **public** endpoint, which is unreachable for two
peers behind the same NAT (see [One pair of nodes can't reach each
other](#one-pair-of-nodes-cant-reach-each-other)). An override pins the address
**this** node dials for a peer. It is never sent to the hub, and heartbeats
don't undo it.

```bash
# at join time
sudo wgcoord client join --server http://203.0.113.1:51821 --token <TOKEN> \
  --peer-endpoint node2=192.168.1.52

# or later — re-applies the interface immediately
sudo wgcoord client endpoint set node2 192.168.1.52
sudo wgcoord client endpoint set node2 '[2001:db8::2]:51822'   # explicit port; bracket IPv6
sudo wgcoord client endpoint set node2 -                       # no endpoint: dial-out only
sudo wgcoord client endpoint list
sudo wgcoord client endpoint clear node2
```

- Name a peer by name or id; the hub is `coordinator`. An override for a peer
  that hasn't joined yet waits for it.
- A bare host keeps the peer's advertised port, which is always its listen port.
- **Set it on both nodes.** One side can work at first, because WireGuard learns
  the working address from the handshake, but that is lost whenever the other
  node re-applies (a reboot, a peer joining or leaving).
- **The address must not move.** Reserve it in DHCP or configure it statically.
- **Overrides live in the client config, so a re-join loses them.** Pass them
  again with `--peer-endpoint`.

## Routing extra subnets

Each peer's `AllowedIPs` is its mesh `/32`, and `AllowedIPs` is also a firewall:
traffic for any other subnet — a Kubernetes pod CIDR, a LAN behind a node — is
**dropped** until that subnet is a route on the node that owns it. Routes are set
on the hub and reach every peer on its next heartbeat.

```bash
sudo wgcoord coordinator route add coordinator 10.12.0.0/24
sudo wgcoord coordinator route add node1       10.12.1.0/24
sudo wgcoord coordinator route add node2       10.12.2.0/24
sudo wgcoord coordinator route list
```

- **One CIDR per owning node**, never a shared cluster CIDR on all of them:
  `AllowedIPs` must map each destination to exactly one peer. `route add`
  refuses a prefix another node already routes, and a route inside the mesh
  range.
- CIDRs are normalized (`10.12.1.5/24` → `10.12.1.0/24`); a single host needs `/32`.
- A route can be a [group](docs/access-control.md#groups) with no ports. Editing
  the group updates the node's `AllowedIPs` on every peer.
- wgcoord sets `AllowedIPs` only. In Kubernetes the CNI adds the kernel route; for
  a plain LAN add it yourself on each peer:

```bash
sudo ip route add 192.168.50.0/24 dev wg0
```

A network next to the coordinator that is not part of the mesh, such as the
cloud VPC it runs in, is a coordinator route with `--nat`. The coordinator
forwards mesh traffic into it and masquerades it, so hosts there need no route
back:

```bash
sudo wgcoord coordinator route add coordinator 172.31.0.0/16 --nat
```

## Restricting access (hub-only clients)

A mesh client reaches everything the mesh routes. A hub-only client peers with
the coordinator alone, never learns another node's key or endpoint, and can open
only what it was granted. The coordinator enforces grants with its own nftables
table, so a client that edits its WireGuard config gains nothing.

```bash
# named groups of addresses, optionally limited to ports
sudo wgcoord coordinator group create development 10.8.0.0/28 --port tcp/15432 --port tcp/16379
sudo wgcoord coordinator group create staging     10.8.0.0/28 --port tcp/25432 --port tcp/26379

# alice may use dev and staging; bob may reach everything
sudo wgcoord coordinator client add alice --hub-only --grant development --grant staging
sudo wgcoord coordinator client add bob   --hub-only --grant all

# later
sudo wgcoord coordinator grant add alice 10.42.0.0/16 --port tcp/8080
sudo wgcoord coordinator grant remove alice staging
sudo wgcoord coordinator grant list
```

The laptops join with the usual `client join` and no `--public-ip`.

- Ports: `tcp/5432`, `udp/53`, `tcp/8000-8100`, or `tcp`/`udp` for the whole
  protocol. No `--port` means every port and protocol. When a group entry and the
  grant both have ports, traffic must match both.
- `all` is the mesh range plus every route, and follows routes as they change.
- A grant is cut down to what the mesh routes; one that overlaps nothing routed
  is refused, and one that is only partly routed gets a warning.
- `--grant` without `--hub-only` is an error: a mesh client reaches every node
  directly, so nothing could enforce it.
- Grants and group edits take effect at the coordinator's next reconcile (≤15s),
  online or not. Hub-only clients can always reach the coordinator's control
  port and ping it.
- The coordinator must run Linux with `nft` installed. If the firewall can't be
  applied, hub-only clients are left off its interface until it can, and the
  reason is logged.

[docs/access-control.md](docs/access-control.md) covers how enforcement works
and walks through four setups: a contractor reaching one service, k3s with one
server, two agents and two developers, a coordinator in a cloud VPC with an
office LAN, and a platform team on a Kubernetes cluster with node pools.

## HTTPS

The hub logs a warning while the control plane is plain HTTP. To terminate TLS on
the hub:

```bash
sudo wgcoord coordinator init --public-ip coordinator.example.com \
  --tls-cert /etc/wgcoord/tls.crt --tls-key /etc/wgcoord/tls.key
sudo wgcoord client join --server https://coordinator.example.com:51821 --token <TOKEN>
```

The in-mesh URL becomes `https://<hub mesh IP>:51821`, so the certificate must
cover that address too, or clients stay on the public URL.

Behind a reverse proxy, leave the TLS flags off and give clients the proxy's URL
as `--server`.

## Running as a service (systemd)

`run` needs an existing config, so `init` or `join` first.

```bash
sudo tee /etc/systemd/system/wgcoord-client.service >/dev/null <<'EOF'
[Unit]
Description=wgcoord client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wgcoord client run
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now wgcoord-client
sudo journalctl -u wgcoord-client -f
```

For the hub, use `wgcoord-coordinator.service` with
`ExecStart=/usr/local/bin/wgcoord coordinator run`. Both run as root, to manage
the interface and read `/etc/wgcoord/config.json`.

## Troubleshooting

Most problems show up in these reads:

```bash
sudo wgcoord coordinator status              # hub: every client, its endpoint, last seen
sudo wgcoord client status                   # node: peer names next to keys and endpoints
sudo wg show wg0 latest-handshakes           # node: unix time per peer key, 0 = never
date +%s                                     # a live peer handshaked within ~2 minutes
sudo journalctl -u wgcoord-client -n 50      # node: heartbeat and apply errors
```

### `sudo: wgcoord: command not found`

`sudo` resets `PATH`, so a binary outside `secure_path` isn't found.

```bash
sudo make install                            # -> /usr/local/bin/wgcoord
sudo ./wgcoord client status                 # or call it by path
```

### A management command has no effect

It edited a different config. Without `sudo`, the CLI uses
`~/.config/wgcoord/config.json`; the daemon reads `/etc/wgcoord/config.json`.

```bash
sudo wgcoord coordinator status              # what the daemon sees
sudo wgcoord coordinator client add laptop   # redo it as root
```

### `config already exists … — remove it to re-join`

`join` won't overwrite a config. Removing it deletes the client's overrides as
well, so note them first:

```bash
sudo wgcoord client endpoint list
sudo wgcoord client down
sudo rm /etc/wgcoord/config.json
sudo wgcoord coordinator token regenerate node2   # on the hub, if the token is lost
sudo wgcoord client join --server http://203.0.113.1:51821 --token <TOKEN> \
  --peer-endpoint node5=192.168.1.55
```

On the hub, `coordinator init --force` replaces the hub keypair. Avoid it on a
live mesh.

### Heartbeat fails: `invalid or missing auth token` / `client is blacklisted`

`401` means the token was regenerated. A client can't take a new token in place,
so re-join as above. `403` means it is blacklisted:

```bash
sudo wgcoord coordinator blacklist remove node2  # on the hub
```

### `live apply unavailable on this host; wrote …`

`wg` or `ip` is missing, or the OS has no live apply. Install the tools, or bring
up the written file by hand:

```bash
sudo apt install wireguard-tools iproute2
sudo wg-quick up /etc/wgcoord/wg0.conf
```

### `control plane: … over the mesh failed … using <url> for the next 5m0s`

Heartbeats still work over the public URL. Either the tunnel to the hub is down,
or the hub's TLS certificate doesn't cover its mesh address.

```bash
sudo wgcoord client status                       # the coordinator row's key
sudo wg show wg0 latest-handshakes               # that key: 0 or stale means the tunnel is down
curl -sv http://10.8.0.1:51821/ -o /dev/null     # any HTTP answer means the mesh path works
```

### No handshake with any peer

The node's WireGuard port isn't reachable. Peers dial `--public-ip` on the node's
**own** listen port, so the router must forward that same UDP port (external
51822 → internal 51822), and the firewall must allow it.

```bash
sudo wg show wg0 listen-port                     # the port to open and forward
sudo ss -ulpn | grep 51822                       # something is listening on it
sudo nft list ruleset | grep 51822               # and nothing drops it
sudo wgcoord coordinator status                  # hub: the advertised endpoint is the real public IP
```

Two dial-out-only clients (`ENDPOINT -` in `coordinator status`) can never
handshake with each other, because neither has an address the other can dial.
Give one a `--public-ip` and a forwarded port.

### One pair of nodes can't reach each other

**Hairpin NAT.** Every other pair works, and both nodes look healthy on their
own. The two sit behind the **same public IP**, so each dials the other's public
address. The packet would have to leave through the router and come straight
back in, and most home routers, Proxmox hosts and cloud NAT gateways drop it.

In Kubernetes this looks like a Service timing out from one node's pods only,
while the node stays `Ready` and the CNI route looks correct:

```bash
kubectl run nettest --rm -i --restart=Never --image=busybox:1.36 \
  --overrides='{"spec":{"nodeSelector":{"kubernetes.io/hostname":"node5"}}}' \
  -- nc -zv -w5 mongodb 27017                    # times out; "open" from any other node
ip route get 10.12.2.84                          # on node5: via flannel.1, yet nothing arrives
```

Confirm:

```bash
sudo wgcoord coordinator status                  # hub: both clients, SAME endpoint IP, different ports
sudo wg show wg0 latest-handshakes               # node5: node2's key reads 0, and vice versa on node2
sudo wgcoord client endpoint list                # both: no override
```

Find each node's LAN address, then check the two can reach each other directly:

```bash
ip -4 route get 1.1.1.1                          # on each node: "src" is its LAN address
ping -c3 192.168.1.52                            # from node5, node2's LAN address
```

Fix it with an override on **both** nodes. A bare host keeps each peer's listen
port:

```bash
sudo wgcoord client endpoint set node2 192.168.1.52   # on node5
sudo wgcoord client endpoint set node5 192.168.1.55   # on node2
```

Verify from node5:

```bash
sleep 30
sudo wgcoord client status                       # node2's endpoint: 192.168.1.52:<port> (override)
sudo wg show wg0 latest-handshakes               # node2's key is no longer 0
ping -c3 10.8.0.3                                # node2's mesh IP
```

Then reserve both LAN addresses in DHCP: if one moves, the pair goes silent
again with nothing logged. If the ping between LAN addresses fails, no override
can help, because the hub won't relay. Give one of the nodes its own public
address.

### Mesh IPs answer but a subnet doesn't

The subnet is missing from its owner's `AllowedIPs`, or the kernel has no route
for it.

```bash
sudo wg show wg0 allowed-ips                     # the subnet appears on exactly one peer
sudo wgcoord coordinator route list              # on the hub
ip route get 10.12.2.84                          # the kernel sends it to wg0 (or flannel.1)
sudo wgcoord coordinator route add node2 10.12.2.0/24
```

In Kubernetes, read each node's pod CIDR rather than assuming it. It is assigned
at registration and never reused from a removed node:

```bash
kubectl get nodes -o custom-columns=NAME:.metadata.name,CIDR:.spec.podCIDR
```

### Kubernetes: cross-node pod traffic vanishes while nodes stay `Ready`

Flannel is bound to the public NIC instead of `wg0`, so its VXLAN bypasses the
mesh.

```bash
ip -d link show flannel.1 | grep -o 'dev [a-z0-9]*'   # must print "dev wg0"
```

On k3s, set `flannel-iface: wg0` in `/etc/rancher/k3s/config.yaml` on every node
and restart:

```bash
echo 'flannel-iface: wg0' | sudo tee -a /etc/rancher/k3s/config.yaml
sudo systemctl restart k3s-agent                 # `k3s` on the server node
```

### A hub-only client reaches nothing

The coordinator couldn't apply its firewall, so it left hub-only clients off its
interface:

```bash
sudo journalctl -u wgcoord-coordinator | grep 'left off'   # on the coordinator
sudo apt install nftables                                  # then wait ~15s
```

If the coordinator answers but one service doesn't, compare
`sudo wgcoord coordinator grant list <client>` with
`sudo nft list table inet wgcoord`. More cases are in
[docs/access-control.md](docs/access-control.md#troubleshooting).

## Limits

- **One coordinator.** The registry is a single locked JSON file — safe for the
  daemon and CLI on the same host, but not HA.
- **Keys never leave the node.** Only public keys are exchanged; tokens are stored
  on the hub as SHA-256 hashes.
- **Hub-only clients depend on the coordinator.** All their traffic crosses it,
  and enforcing their grants needs a Linux coordinator with nftables.

## Development

```bash
make test        # unit tests
make e2e         # end-to-end suite in Docker (needs WireGuard and nftables in the kernel)
```

`make e2e` runs [e2e/run.sh](e2e/run.sh): a coordinator, two k3s-like nodes with
emulated pod ranges, two hub-only clients and a database reachable only through
a NAT route, checked across grants, group edits, revokes, blacklisting, mode
switches, a missing `nft` and a coordinator restart. `KEEP=1 make e2e` leaves the
containers running.
