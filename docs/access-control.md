# Access control: hub-only clients, groups and grants

A mesh client peers with every node and reaches every route in the mesh. That
suits servers. It does not suit a developer laptop that should reach two
databases and nothing else.

A hub-only client peers with the coordinator alone. The coordinator forwards its
traffic into the mesh, and an nftables table on the coordinator drops anything
the client was not granted. The laptop never receives another node's public key
or endpoint, and blocking it only takes a change on the coordinator.

```
             mesh clients (servers)                    hub-only clients (laptops)

   node1 ◀──── udp ────▶ node2                        alice ──┐
     ▲                     ▲                                  │ one tunnel each,
     │                     │                                  │ to the coordinator
     └──── udp ────▶ coordinator ◀──── udp ───────────────────┘
                     ┌───────────────────────────────┐
                     │ nftables "inet wgcoord":      │
                     │ alice may open 10.8.0.0/28    │
                     │ on tcp/15432 and tcp/25432;   │
                     │ everything else is dropped    │
                     └───────────────────────────────┘
```

Contents:

- [Concepts](#concepts)
- [Example 1: a contractor reaches one service](#example-1-a-contractor-reaches-one-service)
- [Example 2: k3s with one server, two agents and two developers](#example-2-k3s-with-one-server-two-agents-and-two-developers)
- [Example 3: a coordinator in a cloud VPC and an office LAN](#example-3-a-coordinator-in-a-cloud-vpc-and-an-office-lan)
- [Example 4: a Kubernetes platform team](#example-4-a-kubernetes-platform-team)
- [Day-to-day operations](#day-to-day-operations)
- [How enforcement works](#how-enforcement-works)
- [Troubleshooting](#troubleshooting)
- [Limits](#limits)

## Concepts

### Modes

| Mode | Peers with | Can reach | Created with |
|---|---|---|---|
| mesh (default) | every node | everything the mesh routes | `coordinator client add <name>` |
| hub-only | the coordinator only | its grants, plus the coordinator's control port and a ping to the coordinator | `coordinator client add <name> --hub-only` |

The token decides the mode, so `client join` is the same command for both. Switch
an existing client with `coordinator client mode <name> mesh|hub-only`.

Leaving hub-only widens access to everything, so it is refused while the client
still has grants. Pass `--clear-grants` to do it anyway. A client that carries
routes can't become hub-only until its routes are removed.

### Groups

A group is a named list of CIDRs. Each entry can be limited to ports:

```bash
sudo wgcoord coordinator group create staging 10.8.0.0/28 --port tcp/25432 --port tcp/26379
sudo wgcoord coordinator group add staging 10.42.0.0/16 --port tcp/8080
sudo wgcoord coordinator group show staging
```

`--port` applies to the CIDRs given in the same command. Accepted forms:

| Form | Meaning |
|---|---|
| `tcp/5432` | one TCP port |
| `udp/53` | one UDP port |
| `tcp/8000-8100` | a range, inclusive |
| `tcp`, `udp` | every port of the protocol |
| no `--port` | every port and every protocol, ICMP included |

Group names start with a letter and contain only letters, digits, `-` and `_`,
up to 63 characters. `all`, `coordinator` and `hub` are reserved. A name can
never look like an address, so commands take a CIDR or a group name in the same
argument with no prefix.

A group is used by reference. Editing it changes every grant and route that uses
it, and `group delete` is refused while anything still does (`group list` shows
what).

### Grants

A grant is something a hub-only client may open:

```bash
sudo wgcoord coordinator grant add alice staging                       # a group
sudo wgcoord coordinator grant add alice 10.42.0.0/16 --port tcp/8080  # a CIDR, on one port
sudo wgcoord coordinator grant add ops all                             # the mesh range and every route
sudo wgcoord coordinator grant list alice
sudo wgcoord coordinator grant remove alice staging
```

- When a group entry has ports and the grant has ports too, traffic must match
  both. `grant add alice staging --port tcp/25432` allows tcp/25432 only, and
  `--port udp/53` on the same group is refused because it would allow nothing.
- `all` follows the mesh: a route added next week is reachable without a new grant.
- A grant is cut down to what the mesh routes: the mesh range and every route of
  the coordinator and the mesh clients. `10.42.0.0/16` becomes the three node pod
  ranges inside it, and `grant add` warns that the rest of the /16 is not routed.
  A grant that overlaps nothing routed is refused with a pointer to `route add`.
- `grant remove` drops every grant on that target, whatever its ports.
- `client add <name> --hub-only --grant <target>` adds port-free grants at
  creation. `--grant` without `--hub-only` is an error, because a mesh client
  reaches every node directly and nothing could enforce the grant.

### Routes, groups and NAT

`route add` takes groups as well as CIDRs. A group used as a route must have no
ports, since a route carries a whole range. These are refused:

- the same prefix routed by two nodes (WireGuard would hand it to whichever peer
  it configured last), including through a group;
- a route inside the mesh range;
- a route on a hub-only client.

A nested prefix on another node is allowed. WireGuard and the kernel both pick
the most specific match, so `10.0.0.0/8` on the coordinator and `10.42.1.0/24`
on node1 work together.

`--nat` marks a coordinator route as a network next to the coordinator, such as
the cloud network it runs in:

```bash
sudo wgcoord coordinator route add coordinator 172.30.0.0/24 --nat
```

The coordinator forwards mesh traffic for that range out of its own interfaces
and masquerades it as its own address. Hosts in that network need no route back
to the mesh, and they see the coordinator as the source. `--nat` is only valid on
`coordinator`.

## Example 1: a contractor reaches one service

Two servers on a mesh. A contractor needs the staging admin UI on `app1`, port
8443, for two weeks, and nothing else.

| Host | Role | Public IP | Mesh IP |
|---|---|---|---|
| hub | coordinator | 203.0.113.10 | 10.8.0.1 |
| app1 | mesh client | 198.51.100.21 | 10.8.0.11 |
| db1 | mesh client | 198.51.100.22 | 10.8.0.12 |
| sam's laptop | hub-only | none | 10.8.0.50 |

```bash
# hub
sudo wgcoord coordinator init --public-ip 203.0.113.10
sudo wgcoord coordinator client add app1 --address 10.8.0.11
sudo wgcoord coordinator client add db1 --address 10.8.0.12
sudo systemctl enable --now wgcoord-coordinator

sudo wgcoord coordinator client add sam --hub-only --address 10.8.0.50
sudo wgcoord coordinator grant add sam 10.8.0.11/32 --port tcp/8443
```

```bash
# app1 and db1 (each with its own token and public IP)
sudo wgcoord client join --server http://203.0.113.10:51821 --token <TOKEN> --public-ip 198.51.100.21
sudo systemctl enable --now wgcoord-client

# sam's laptop: no --public-ip, it only dials out
sudo wgcoord client join --server http://203.0.113.10:51821 --token <TOKEN>
sudo wgcoord client run
```

From the laptop, `https://10.8.0.11:8443` answers, `ssh 10.8.0.11` times out, and
`10.8.0.12` answers nothing. `wgcoord client status` shows one peer, the
coordinator. When the work ends:

```bash
sudo wgcoord coordinator client remove sam
```

The coordinator drops the peer and its firewall rules on the next reconcile,
within 15 seconds.

## Example 2: k3s with one server, two agents and two developers

alice may use the dev and staging databases. bob runs the platform and may reach
everything.

| Host | Role | Public IP | Mesh IP |
|---|---|---|---|
| master | coordinator + k3s server | 203.0.113.10 | 10.8.0.1 |
| node1 | mesh client + k3s agent | 198.51.100.21 | 10.8.0.11 |
| node2 | mesh client + k3s agent | 198.51.100.22 | 10.8.0.12 |
| alice's laptop | hub-only: development, staging | none | 10.8.0.101 |
| bob's laptop | hub-only: all | none | 10.8.0.102 |

The servers are pinned inside `10.8.0.0/28`, so that one CIDR means "any node".

### 1. The mesh

```bash
# master
sudo wgcoord coordinator init --public-ip 203.0.113.10 --address 10.8.0.1
sudo wgcoord coordinator client add node1 --address 10.8.0.11
sudo wgcoord coordinator client add node2 --address 10.8.0.12
sudo systemctl enable --now wgcoord-coordinator

# node1 (node2: its own token, 198.51.100.22)
sudo wgcoord client join --server http://203.0.113.10:51821 --token <TOKEN> --public-ip 198.51.100.21
sudo systemctl enable --now wgcoord-client
```

### 2. k3s over the mesh

Flannel must use `wg0`, and every node advertises its mesh IP:

```bash
# master
curl -sfL https://get.k3s.io | sh -s - server \
  --node-ip 10.8.0.1 --node-external-ip 203.0.113.10 --flannel-iface wg0

# node1 (node2: --node-ip 10.8.0.12)
curl -sfL https://get.k3s.io | K3S_URL=https://10.8.0.1:6443 \
  K3S_TOKEN=<contents of /var/lib/rancher/k3s/server/node-token on master> \
  sh -s - agent --node-ip 10.8.0.11 --flannel-iface wg0
```

### 3. Pod routes

Read each node's pod range, then route it through its owner:

```bash
kubectl get nodes -o custom-columns=NAME:.metadata.name,CIDR:.spec.podCIDR
sudo wgcoord coordinator route add coordinator 10.42.0.0/24
sudo wgcoord coordinator route add node1       10.42.1.0/24
sudo wgcoord coordinator route add node2       10.42.2.0/24
```

Hub-only clients need these even where flannel would carry node-to-node traffic
without them: the coordinator uses them to know which node owns a pod address.

### 4. Environments as groups

Namespaces share the pod range: dev, staging and production pods all sit in
`10.42.0.0/16`, on any node. An environment can't be described by an address
alone, so here each environment's databases are `LoadBalancer` services on their
own ports. The k3s built-in load balancer (ServiceLB) listens on every node's
addresses, the mesh IP included.

```yaml
# staging/postgres-lb.yaml: reachable on port 25432 of every node
apiVersion: v1
kind: Service
metadata:
  name: postgres-lb
  namespace: staging
spec:
  type: LoadBalancer
  selector: { app: postgres }
  ports: [{ port: 25432, targetPort: 5432 }]
```

```bash
sudo wgcoord coordinator group create development 10.8.0.0/28 --port tcp/15432 --port tcp/16379
sudo wgcoord coordinator group create staging     10.8.0.0/28 --port tcp/25432 --port tcp/26379
sudo wgcoord coordinator group create production  10.8.0.0/28 --port tcp/35432 --port tcp/36379
```

### 5. The developers

```bash
# master
sudo wgcoord coordinator client add alice --hub-only --address 10.8.0.101 --grant development --grant staging
sudo wgcoord coordinator client add bob   --hub-only --address 10.8.0.102 --grant all

# each laptop
sudo wgcoord client join --server http://203.0.113.10:51821 --token <TOKEN>
sudo wgcoord client run
```

### 6. Check

```bash
sudo wgcoord coordinator status           # alice, bob: MODE hub-only, with their grants
sudo wgcoord coordinator grant list       # what each grant resolves to

# alice's laptop
psql -h 10.8.0.11 -p 15432 -U app         # dev postgres
psql -h 10.8.0.12 -p 25432 -U app         # staging postgres
nc -zv -w3 10.8.0.11 35432                # production: times out
```

Postgres and Redis run on one node at a time, but ServiceLB answers on all three,
so any node IP works.

## Example 3: a coordinator in a cloud VPC and an office LAN

The coordinator is a small VM in a cloud VPC (`172.31.0.0/16`), next to a managed
Postgres at `172.31.5.20`. An office LAN (`192.168.10.0/24`) sits behind
`office-gw`, a mesh client in the office. Engineers get the database. The finance
team gets the office file server only.

| Host | Role | Public IP | Mesh IP |
|---|---|---|---|
| vpc-hub | coordinator, in the VPC | 203.0.113.10 | 10.8.0.1 |
| office-gw | mesh client, routes the office LAN | 198.51.100.40 | 10.8.0.2 |
| engineers | hub-only | none | 10.8.0.100 and up |
| finance | hub-only | none | 10.8.0.200 and up |

```bash
sudo wgcoord coordinator init --public-ip 203.0.113.10 --ip-range 10.8.0.0/24
sudo wgcoord coordinator client add office-gw --address 10.8.0.2
sudo wgcoord coordinator route add office-gw 192.168.10.0/24

# The VPC is outside the mesh: mark it NAT so the database needs no route back.
sudo wgcoord coordinator group create vpc 172.31.0.0/16
sudo wgcoord coordinator route add coordinator vpc --nat

# Services as groups.
sudo wgcoord coordinator group create prod-db   172.31.5.20/32 --port tcp/5432
sudo wgcoord coordinator group create fileshare 192.168.10.5/32 --port tcp/445
sudo wgcoord coordinator group create office-printers 192.168.10.30/31 --port tcp/9100 --port tcp/631

sudo wgcoord coordinator client add eng-maria   --hub-only --address 10.8.0.100 --grant prod-db
sudo wgcoord coordinator client add eng-tom     --hub-only --address 10.8.0.101 --grant prod-db
sudo wgcoord coordinator client add fin-anna    --hub-only --address 10.8.0.200 --grant fileshare --grant office-printers
```

`office-gw` must forward between `wg0` and the LAN, and the LAN must send replies
for `10.8.0.0/24` back to it: add that route on the office router, or masquerade
on `office-gw` (`iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE`).
wgcoord only masquerades on the coordinator.

The managed Postgres sees connections from `vpc-hub`'s VPC address. Allow that
address in the database's security group, not the engineers' laptops.

A new engineer is one `client add … --grant prod-db`. A second database is one
`group add prod-db <cidr> --port tcp/5432`, and every engineer can reach it
within 15 seconds.

## Example 4: a Kubernetes platform team

A k3s cluster of six agents in two node pools, with a coordinator outside the
cluster. Production workloads are pinned to `pool-prod` with a `nodeSelector`
and a taint; everything else runs on `pool-shared`.

| Host | Role | Mesh IP | Pod range |
|---|---|---|---|
| hub | coordinator, not in the cluster | 10.8.0.1 | none |
| k3s-server | mesh client | 10.8.0.10 | 10.42.0.0/24 |
| shared-1…3 | mesh clients, pool-shared | 10.8.0.11–13 | 10.42.1.0/24–10.42.3.0/24 |
| prod-1…3 | mesh clients, pool-prod | 10.8.0.21–23 | 10.42.4.0/24–10.42.6.0/24 |

### Pod ranges as groups

With environments pinned to pools, a pool's pod ranges describe an environment.
Port-free groups work as routes and as grants:

```bash
sudo wgcoord coordinator route add k3s-server 10.42.0.0/24
for i in 1 2 3; do sudo wgcoord coordinator route add shared-$i 10.42.$i.0/24; done
for i in 1 2 3; do sudo wgcoord coordinator route add prod-$i 10.42.$((i+3)).0/24; done

sudo wgcoord coordinator group create pool-shared-pods 10.42.1.0/24 10.42.2.0/24 10.42.3.0/24
sudo wgcoord coordinator group create pool-prod-pods   10.42.4.0/24 10.42.5.0/24 10.42.6.0/24
sudo wgcoord coordinator group create k3s-api 10.8.0.10/32 --port tcp/6443
```

Each node keeps its own CIDR route. A group used as a route belongs to one node,
so a pool-wide group stays a grant target.

### Who gets what

```bash
# Application developers: any port on non-production pods, the API server for kubectl.
sudo wgcoord coordinator client add dev-lena --hub-only --grant pool-shared-pods --grant k3s-api

# On-call: production databases and metrics only.
sudo wgcoord coordinator client add oncall-1 --hub-only --grant k3s-api
sudo wgcoord coordinator grant add oncall-1 pool-prod-pods --port tcp/5432 --port tcp/9090

# CI runner: pushes to the in-cluster registry, deploys through the API.
sudo wgcoord coordinator client add ci-runner --hub-only --grant k3s-api
sudo wgcoord coordinator grant add ci-runner pool-shared-pods --port tcp/5000

# Platform team: everything.
sudo wgcoord coordinator client add platform-ivan --hub-only --grant all
```

The cluster's Service range (`10.43.0.0/16` on k3s) holds virtual addresses that
only exist inside each node's kube-proxy rules, and no node owns it. Reach
services through pod addresses, ServiceLB or NodePorts as above.

With the API server granted, kubeconfigs point at `https://10.8.0.10:6443`. The
server certificate must list that address: add `--tls-san 10.8.0.10` to the k3s
server.

### Scaling the pool

A new production node is a mesh client with its own route, plus one group edit:

```bash
sudo wgcoord coordinator client add prod-4 --address 10.8.0.24 --route 10.42.7.0/24
sudo wgcoord coordinator group add pool-prod-pods 10.42.7.0/24
```

On-call can reach the new node's pods within 15 seconds. Grants on `all` pick up
the new route without the second command.

## Day-to-day operations

| Task | Command |
|---|---|
| What can alice reach? | `coordinator grant list alice` |
| Who uses a group? | `coordinator group show <name>` |
| Revoke one grant | `coordinator grant remove alice staging` |
| Block a client now | `coordinator blacklist alice` |
| Offboard | `coordinator client remove alice` |
| Promote to a full mesh member | `coordinator client mode alice mesh --clear-grants` |
| Move a server to hub-only | `coordinator route remove <name> …`, then `coordinator client mode <name> hub-only` |

A revoke takes effect at the coordinator's next reconcile, within 15 seconds,
whether or not the client is online. So does moving a mesh client to hub-only:
until that reconcile, it keeps the full access it had as a mesh client. The client's own WireGuard config catches up
on its next heartbeat, but nothing depends on that.

To see what the firewall dropped:

```bash
sudo nft list table inet wgcoord          # one chain per hub-only client, named in a comment
```

The `counter drop` line at the end of a client's chain counts blocked packets.

## How enforcement works

- The coordinator owns one nftables table, `inet wgcoord`. Each reconcile
  replaces it in a single `nft -f` transaction, and wgcoord never touches other
  tables.
- Hub-only traffic is filtered in `prerouting` at priority -110, before any DNAT.
  A rule matches the address and port the client asked for, whether the
  coordinator delivers the packet itself or forwards it, and whatever kube-proxy
  or ServiceLB later rewrites it to.
- Replies (`ct state established,related`) always pass, so a mesh node can open a
  connection to a hub-only client and get answers.
- Forwarding: when hub-only clients or NAT routes exist, the coordinator sets
  `net.ipv4.ip_forward=1` (and IPv6 forwarding for IPv6 ranges). It never turns
  forwarding off, because Kubernetes or Docker may depend on it.
- Kernel routes: while hub-only clients exist, the coordinator routes each mesh
  client's routes into `wg0`, tagged `proto 211` at metric 1000. A CNI route for
  the same prefix (metric 0) wins where one exists.
- A hub-only client sends the whole mesh range to the coordinator, plus its
  granted ranges outside the mesh. On Linux it routes those ranges itself
  (`proto 211`); on macOS it adds and removes them with `route`.
- Mesh clients see each hub-only client's /32 on the coordinator peer, so their
  replies go back through the coordinator.
- Failing closed: if the table can't be applied (no `nft`, an apply error, a
  coordinator that isn't Linux), hub-only clients are left off the coordinator's
  interface and the reason is logged once. Forwarding may already be on, so
  passing their traffic unfiltered is not an option.

## Troubleshooting

### A hub-only client reaches nothing, not even the coordinator

```bash
sudo journalctl -u wgcoord-coordinator | grep -i 'left off'   # on the coordinator
sudo wg show wg0 peers                                        # is the client's key there?
which nft
```

"left off" means the firewall could not be applied. Install nftables
(`apt install nftables`) and the clients return within 15 seconds.

### The coordinator answers but a granted service doesn't

```bash
sudo wgcoord coordinator grant list alice          # does the grant resolve to the address you expect?
sudo nft list table inet wgcoord                   # is there an accept rule for it?
ip route get 10.42.1.10                            # on the coordinator: which interface?
```

A grant that resolves to "nothing routed right now" needs a route on the node
that owns the range. If `ip route get` on the coordinator does not say `dev wg0`
(or `flannel.1` on a cluster node), another route on the coordinator is taking
the traffic.

### A NAT route works from the coordinator but not from clients

The coordinator must be able to reach the address itself (`curl` or `nc` from the
coordinator). Then check the masquerade rule:

```bash
sudo nft list chain inet wgcoord nat_routes
```

### alice can still reach something after a revoke

Wait 15 seconds for the reconcile, then check `coordinator grant list alice` and
`coordinator group show` for each group she holds. Another grant may cover the
same address, and `all` covers everything routed.

## Limits

- Enforcement needs a Linux coordinator with nftables. On any other coordinator,
  hub-only clients stay disconnected.
- All hub-only traffic crosses the coordinator, so its bandwidth and uptime are
  the limit for those clients.
- Grants filter destination address, protocol and port, but they do not inspect
  traffic.
- Groups hold addresses. A Kubernetes namespace has none of its own, so
  environments need their own ports, node pools or load-balancer addresses.
- wgcoord masquerades only on the coordinator. A LAN behind a mesh client needs a
  route back to the mesh, or masquerading on that client.
