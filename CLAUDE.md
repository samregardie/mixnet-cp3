# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

CMU 15-441/641 Project 1 (Mixnet). Everything outside `mixnet/node.c` (+ any helper
`.c`/`.h` you add next to it) and `impls/*/` is course-provided framework and must not be
modified. `mixnet/{address,config,connection,packet}.h` and `mixnet/CMakeLists.txt` are
explicitly *immutable* — `run_impl.sh`, `run_ec2.sh`, and `make_submission.sh` all filter
those filenames out when staging/zipping an implementation.

**Do not push this repo to a public fork** (course policy, stated in README.md).

## Build and test

```bash
mkdir -p build && cd build && cmake .. && make      # then just `make` in build/ afterwards
cmake .. -DDEBUG=ON                                 # -O0 -g instead of the default -O3
```

Tests are standalone binaries, one per `testing/*/testcase_*.cpp`, in `build/bin/{cp1,cp2,lab}/`:

```bash
./bin/cp1/testcase_line_easy -a     # autotester mode: spawns all nodes in-process, prints pass/fail
./bin/cp1/testcase_line_easy        # manual mode: orchestrator only, listens on :9107
./bin/node 127.0.0.1 9107           # ...then one of these per node, in its own terminal
../testing/cp1/run_tests.sh         # run all cp1 tests (run from build/); same for cp2
```

`-a` is what the autograder uses. Manual mode needs n+1 terminals for an n-node topology and is
for debugging / distributed (EC2) runs.

`testing/*/CMakeLists.txt` globs `testcase*.cpp`; cp1/cp2 glob without `CONFIGURE_DEPENDS`, so
**re-run `cmake ..` after adding a new testcase file there** (`lab/` re-globs automatically).

## Lab workflow (STP convergence optimization)

Scenario implementations live in `impls/{noloss,lossy,islands}/` — each a self-contained folder
with an entry `node.c` defining `run_node` plus optional helpers (every `.c` in the folder is
compiled together). They start as do-nothing stubs; the working baseline is `mixnet/node.c`.

```bash
./impls/run_impl.sh noloss 10                       # baseline: builds mixnet/ as-is, 10 runs
./impls/run_impl.sh islands 10 --impl impls/islands # builds that folder instead (staged into
                                                    # mixnet/, restored on exit)
./impls/make_submission.sh                          # -> impls/submission.zip for Gradescope
MIXNET_LOSS=25 ./impls/run_impl.sh lossy            # override the 50% per-link drop rate
MIXNET_STP_NORMALIZE=1 ./impls/run_impl.sh noloss   # tolerate a uniform root path-length offset
```

Scenario → test-case mapping: `noloss`→`testcase_stp_convergence_hybrid`,
`lossy`→`..._hybrid_lossy` (50% RX-side loss per link), `islands`→`..._islands`
(3 island meshes joined by 50 ms inter-island links; scored on `inter_island_stp_packets`).

Each convergence test prints one scored line:
`[STP] <name> converged=true stp_packets_until_convergence=N inter_island_stp_packets=M`.
"Converged" (see `testing/common/stp_convergence.h`) = every node's *latest* STP advertisement
reports both the correct root (lowest mixnet address) and its correct BFS hop distance to it;
counting freezes at that instant, so periodic hellos after convergence are free but pre-convergence
chatter is not. The grader means 10 runs and requires 10/10 convergence to score.

Distributed runs: `SSH_KEY=<key> ./impls/run_ec2.sh <testcase> hosts.txt` (add `SYNC=0` to reuse an
existing remote build, `NODE_LOGS=1` to dump per-node stdout — that's where RTT prints land). Env
vars must precede the command. See README.md for the EC2 security-group setup.

## Architecture

**Orchestrator / fragment split.** `framework/orchestrator.cpp` is a single controller process that
builds the virtual topology, forks/launches one *fragment* per mixnet node (`framework/fragment.cpp`,
also the `bin/node` binary), wires up TCP sockets between neighbors, then hands control to the
testcase. Two planes: **ctrl** on port 9107 (setup, link state, packet injection) and **pcap** on
9108 (mirrored packets flowing back to the testcase). Neighbor-to-neighbor traffic uses random
ephemeral ports.

**Your code is `run_node()`** (`mixnet/node.h`), called once per node with an opaque `handle`, a
`volatile bool *keep_running` to poll for shutdown, and a `mixnet_node_config` (own address,
neighbor count, STP timers, `link_costs[]`, `mixing_factor`, `do_random_routing`).

**The port model is the crux.** For a node with n neighbors, ports `0..n-1` are neighbor links
(port i ↔ the i'th entry of that node's adjacency list, so port index ↔ neighbor is positional and
stable) and port **n is the user port** — RX on it means user-injected traffic to route, TX on it
means "deliver to the user" (which is what the testcase's `pcap()` callback observes). Never relay
a FLOOD to the user port that shouldn't be delivered.

**`mixnet_recv`/`mixnet_send` contract** (`mixnet/connection.h`):
- `mixnet_recv` is **non-blocking** and round-robins over ports; it returns 0 when nothing is
  pending, so `run_node` must be a poll loop (the baseline drains until empty, then `nanosleep`s 1 ms).
- Received packets are heap-allocated and owned by you: `free()` them or hand them to `mixnet_send`.
- `mixnet_send` **takes ownership** — never touch or free a sent packet, and clone before sending
  the same logical packet out multiple ports.
- A failed send must be retried until it succeeds (the baseline's `send_packet()` loops).

**Packets** (`mixnet/packet.h`): a 12-byte packed `mixnet_packet` header (`total_size`, `type`,
`_reserved`) followed by a type-specific payload — `mixnet_packet_stp`, `mixnet_packet_lsa`
(variable-length link list), or a `mixnet_packet_routing_header` (variable-length source route,
`hop_index`) that DATA/PING payloads sit *after*. DATA/PING arriving on the user port are always
`MAX_MIXNET_PACKET_SIZE` with `dst_address` filled in; you compute the source route and fix up the
payload offset yourself. Note `_reserved[0]` is used by the framework's STP mirror to stash the
egress port — don't rely on it.

**Testcases** (`testing/common/testcase.h`) are subclasses implementing `setup()` (build the
`graph`, set timeouts — all static config must happen here), `run(orchestrator&)` (usually
`await_convergence()`, subscribe via `pcap_change_subscription`, then `send_packet` /
`change_link_state`), `pcap()` (**runs on the orchestrator's pcap thread** — careful with shared
state), and `teardown()` (sets `pass_teardown_`). `testing/common/graph.h` builds topologies
(`generate_topology` for LINE/RING/STAR/FULL_MESH, or explicit `add_edge(a, b, latency_ms)` with
per-link cost and latency).

## Current state

`mixnet/node.c` implements cp1 only: STP (root election, root port + tie-break on
`(path_length, address)`, periodic hellos from the root, reelection on timeout) and FLOOD over the
resulting spanning tree. There is no LSA/link-state database, no source routing, no ping handling,
and no mixing — so cp2's `testcase_ping` and `testcase_sp_uniform_ring` do not pass yet.

## Environment

The framework targets Linux (tested on Ubuntu 20.04+). Building on this macOS box currently fails
before it reaches any project code: the Apple toolchain can't find libc++ headers (`fatal error:
'memory' file not found`, reproducible with a bare `#include <memory>`), so C++ compilation of
`framework/` dies. Fix the local toolchain or build/run on Linux (or the EC2 hosts) before treating
a build failure as a code problem.
