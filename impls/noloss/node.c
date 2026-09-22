/**
 * Copyright (C) 2023 Carnegie Mellon University
 *
 * This file is part of the Mixnet course project developed for
 * the Computer Networks course (15-441/641) taught at Carnegie
 * Mellon University.
 *
 * No part of the Mixnet project may be copied and/or distributed
 * without the express permission of the 15-441/641 course staff.
 */

/* ======================================================================
 *  LAB SCENARIO 1 — hybrid topology, NO loss            (REQUIRED)
 * ----------------------------------------------------------------------
 *  Graded by:  testcase_stp_convergence_hybrid
 *  Goal:       minimize the number of STP control messages exchanged
 *              before the spanning tree converges. 
 *
 *
 *  Build & measure locally:   ./impls/run_impl.sh noloss
 *  Submit:                    ./impls/make_submission.sh
 * ====================================================================== */

#include "node.h"

#include "connection.h"
#include "packet.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t) ts.tv_sec * 1000) + ((uint64_t) ts.tv_nsec / 1000000);
}

// Microsecond-resolution clock, used for ping::send_time/RTT rather than
// now_ms(): intra-host and same-region EC2 RTTs commonly fall below a
// millisecond, which now_ms() would just round to 0.
static uint64_t now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t) ts.tv_sec * 1000000) + ((uint64_t) ts.tv_nsec / 1000);
}

// Number of reelection intervals of STP-belief silence required before
// a node trusts its (root, path_length) belief enough to send its LSA.
static const uint16_t LSA_SILENCE_MULTIPLIER = 2;

/**
 * One node's link-state entry: the (neighbor address, cost) list it
 * advertised in its LSA, plus the working state used to compute shortest
 * paths from this map (dist/prev). Indexed directly by mixnet_address (a
 * uint16_t), so the topology map below is a flat array rather than a
 * chained hash table -- the address space is small enough that direct
 * indexing is just a (perfect) hash map keyed by address.
 */
typedef struct {
    bool known;
    uint16_t neighbor_count;
    mixnet_address *neighbor_addr;
    uint16_t *neighbor_cost;

    // Dijkstra working state (valid once compute_fib() has run)
    uint32_t dist;
    mixnet_address prev;      // INVALID_MIXADDR for our own node (path start)
    mixnet_address first_hop; // address of our own neighbor this path departs through
} topology_entry;

/**
 * A computed FIB entry: the intermediate hops (excluding src/dst) of the
 * shortest path from this node to the given destination.
 */
typedef struct {
    bool known;
    uint16_t route_length;
    mixnet_address *route;
} fib_entry;

/**
 * Per-node STP + flooding state.
 */
typedef struct {
    mixnet_address my_addr;
    uint16_t num_neighbors;
    uint8_t user_port;

    // Current best root info
    mixnet_address root_addr;
    uint16_t path_length;
    int root_port;                 // -1 if this node is currently the root

    // Per-neighbor learned state (indexed by port)
    mixnet_address *neighbor_addr; // learned via STP node_address field
    bool *neighbor_known;
    mixnet_address *neighbor_root; // last-advertised root from this neighbor
    uint16_t *neighbor_path;       // last-advertised path length from this neighbor
    bool *port_forwarding;         // is this port part of the flooding tree?

    // Timers
    uint64_t last_hello_sent;      // meaningful while this node is root
    uint64_t last_hello_received;  // meaningful while this node is non-root
    uint64_t last_root_changed;    // last time root_addr/path_length changed
    bool sent_lsa;                 // whether we've sent our one-shot LSA

    // Link-state topology map, one entry per known node address
    topology_entry *topology;

    // Computed shortest-path FIB, one entry per destination address
    fib_entry *fib;

    bool do_random_routing;

    // Mixing: FLOOD/DATA/PING sends (both onto a neighbor link and up to our
    // own user) are held here rather than sent immediately. Once
    // messages_held reaches mixing_factor, every pending send is flushed.
    uint16_t mixing_factor;
    uint16_t messages_held;
    struct { uint8_t port; mixnet_packet *packet; } *pending_sends;
    uint16_t pending_count;
    uint16_t pending_capacity;
} node_state;

static mixnet_packet *make_stp_packet(const mixnet_address root,
                                       const uint16_t path_length,
                                       const mixnet_address node_addr) {
    const uint16_t size = sizeof(mixnet_packet) + sizeof(mixnet_packet_stp);
    mixnet_packet *packet = (mixnet_packet*) malloc(size);

    packet->total_size = size;
    packet->type = PACKET_TYPE_STP;

    mixnet_packet_stp *stp = (mixnet_packet_stp*) packet->payload;
    stp->root_address = root;
    stp->path_length = path_length;
    stp->node_address = node_addr;
    return packet;
}

static mixnet_packet *make_flood_packet(void) {
    mixnet_packet *packet = (mixnet_packet*) malloc(sizeof(mixnet_packet));
    packet->total_size = sizeof(mixnet_packet);
    packet->type = PACKET_TYPE_FLOOD;
    return packet;
}

static mixnet_packet *make_lsa_packet(const mixnet_address node_addr,
                                      const uint16_t neighbor_count,
                                      const mixnet_lsa_link_params *const links) {
    const uint16_t size = sizeof(mixnet_packet) + sizeof(mixnet_packet_lsa) +
        (neighbor_count * sizeof(mixnet_lsa_link_params));
    mixnet_packet *packet = (mixnet_packet*) malloc(size);

    packet->total_size = size;
    packet->type = PACKET_TYPE_LSA;

    mixnet_packet_lsa *lsa = (mixnet_packet_lsa*) packet->payload;
    lsa->node_address = node_addr;
    lsa->neighbor_count = neighbor_count;
    for (uint16_t i = 0; i < neighbor_count; i++) {
        lsa->links[i] = links[i];
    }
    return packet;
}

static mixnet_packet *make_data_packet(const mixnet_address src,
                                       const mixnet_address dst,
                                       const uint16_t route_length,
                                       const mixnet_address *const route,
                                       const void *const data,
                                       const uint16_t data_length) {
    const uint16_t size = sizeof(mixnet_packet) +
        sizeof(mixnet_packet_routing_header) +
        (route_length * sizeof(mixnet_address)) + data_length;
    mixnet_packet *packet = (mixnet_packet*) malloc(size);

    packet->total_size = size;
    packet->type = PACKET_TYPE_DATA;

    mixnet_packet_routing_header *rh =
        (mixnet_packet_routing_header*) packet->payload;
    rh->src_address = src;
    rh->dst_address = dst;
    rh->route_length = route_length;
    rh->hop_index = 0;
    for (uint16_t i = 0; i < route_length; i++) {
        rh->route[i] = route[i];
    }
    memcpy(((char*) rh) + sizeof(mixnet_packet_routing_header) +
        (route_length * sizeof(mixnet_address)), data, data_length);
    return packet;
}

static mixnet_packet *make_ping_packet(const mixnet_address src,
                                       const mixnet_address dst,
                                       const uint16_t route_length,
                                       const mixnet_address *const route,
                                       const bool is_request,
                                       const uint64_t send_time) {
    const uint16_t size = sizeof(mixnet_packet) +
        sizeof(mixnet_packet_routing_header) +
        (route_length * sizeof(mixnet_address)) + sizeof(mixnet_packet_ping);
    mixnet_packet *packet = (mixnet_packet*) malloc(size);

    packet->total_size = size;
    packet->type = PACKET_TYPE_PING;

    mixnet_packet_routing_header *rh =
        (mixnet_packet_routing_header*) packet->payload;
    rh->src_address = src;
    rh->dst_address = dst;
    rh->route_length = route_length;
    rh->hop_index = 0;
    for (uint16_t i = 0; i < route_length; i++) {
        rh->route[i] = route[i];
    }

    mixnet_packet_ping *ping = (mixnet_packet_ping*) (((char*) rh) +
        sizeof(mixnet_packet_routing_header) +
        (route_length * sizeof(mixnet_address)));
    ping->is_request = is_request;
    ping->send_time = send_time;
    return packet;
}

// Clones an in-flight routed packet (DATA or PING), overwriting only its
// hop_index -- used when relaying a packet that already carries its full
// route, as opposed to a packet built fresh from a FIB lookup.
static mixnet_packet *copy_packet_with_hop_index(const mixnet_packet *const packet,
                                                 const uint16_t hop_index) {
    mixnet_packet *copy = (mixnet_packet*) malloc(packet->total_size);
    memcpy(copy, packet, packet->total_size);

    mixnet_packet_routing_header *rh =
        (mixnet_packet_routing_header*) copy->payload;
    rh->hop_index = hop_index;
    return copy;
}

// Finds the port a given neighbor address is reachable on.
static uint8_t find_port(const node_state *const s, const mixnet_address addr) {
    for (uint16_t i = 0; i < s->num_neighbors; i++) {
        if (s->neighbor_addr[i] == addr) {
            return (uint8_t) i;
        }
    }
    return 0; // Unreachable given a correct FIB/topology
}

// Sends a packet, retrying on backpressure (mixnet_send() returning 0) until
// the framework accepts it, per connection.h's contract. A return of -1
// means the packet itself is malformed -- that's a bug in how we built it,
// not a transient condition, so retrying forever would just hang the node;
// abort immediately instead so the failure is obvious at its actual cause.
static void send_packet(void *const handle, const uint8_t port,
                         mixnet_packet *const packet) {
    for (;;) {
        const int rc = mixnet_send(handle, port, packet);
        if (rc > 0) { return; }
        if (rc < 0) {
            fprintf(stderr, "mixnet_send() rejected a malformed packet "
                "(port=%u, type=%u, total_size=%u)\n",
                port, packet->type, packet->total_size);
            abort();
        }
    }
}

// Queues a FLOOD/DATA/PING send (onto a neighbor link or up to our own
// user) for mixing, rather than sending it immediately.
static void enqueue_send(node_state *const s, const uint8_t port,
                         mixnet_packet *const packet) {
    if (s->pending_count == s->pending_capacity) {
        s->pending_capacity = s->pending_capacity ? (uint16_t) (s->pending_capacity * 2) : 4;
        s->pending_sends = realloc(s->pending_sends,
            s->pending_capacity * sizeof(*s->pending_sends));
    }
    s->pending_sends[s->pending_count].port = port;
    s->pending_sends[s->pending_count].packet = packet;
    s->pending_count++;
}

// Sends out every currently-queued packet and resets the queue.
static void flush_pending_sends(void *const handle, node_state *const s) {
    for (uint16_t i = 0; i < s->pending_count; i++) {
        send_packet(handle, s->pending_sends[i].port, s->pending_sends[i].packet);
    }
    s->pending_count = 0;
}

// Marks one FLOOD/DATA/PING packet as fully received and queued (regardless
// of how many enqueue_send() calls it produced -- e.g. a FLOOD fanning out
// to several neighbors still counts once), flushing the whole queue once
// mixing_factor such packets have been collected.
static void mixing_message_received(void *const handle, node_state *const s) {
    s->messages_held++;
    if (s->messages_held == s->mixing_factor) {
        flush_pending_sends(handle, s);
        s->messages_held = 0;
    }
}

static void send_stp(void *const handle, const node_state *const s,
                     const uint8_t port) {
    send_packet(handle, port,
        make_stp_packet(s->root_addr, s->path_length, s->my_addr));
}

// Sends our current STP belief to every neighbor except our path to the
// root (root_port), so we never echo it straight back to our parent. When
// we are the root (root_port == -1), every port qualifies.
//
// Exception: a LEAF (num_neighbors == 1) has no other port to relay to, so
// excluding its only port -- once that port becomes root_port -- would make
// it go permanently silent after its first (pre-adoption) hello, even though
// its belief keeps changing as convergence proceeds. Sending its belief back
// to its own parent in that case is harmless (the parent's comparator always
// finds its own path at least as good and ignores it), and is what keeps a
// leaf's current state observable/relayed at all once it has a parent.
static void broadcast_stp(void *const handle, const node_state *const s) {
    for (uint16_t i = 0; i < s->num_neighbors; i++) {
        if (((int) i != s->root_port) || (s->num_neighbors == 1)) {
            send_stp(handle, s, (uint8_t) i);
        }
    }
}

/**
 * (Re)computes, for every neighbor port, whether it is part of the
 * flooding tree. A port is forwarding if it is our route to the root
 * (root port), or if we are "better" than the neighbor on that port
 * (i.e., we might be that neighbor's chosen parent). This is the same
 * (path_length, then address) comparator used to pick our own parent,
 * applied symmetrically so that redundant links get a single, consistent
 * forwarding side instead of both (or neither) ends forwarding.
 */
static void recompute_port_roles(node_state *const s) {
    for (uint16_t i = 0; i < s->num_neighbors; i++) {
        if ((int) i == s->root_port) {
            s->port_forwarding[i] = true;
            continue;
        }
        if (!s->neighbor_known[i] || (s->neighbor_root[i] != s->root_addr)) {
            // Haven't converged with this neighbor on a common root yet;
            // default to open so we don't wrongly wedge convergence.
            s->port_forwarding[i] = true;
            continue;
        }
        const bool i_am_better = (
            (s->path_length < s->neighbor_path[i]) ||
            ((s->path_length == s->neighbor_path[i]) &&
             (s->my_addr < s->neighbor_addr[i])));

        s->port_forwarding[i] = i_am_better;
    }
}

/**
 * Adopts a fresh (root = self, path_length = 0) identity, i.e., this
 * node believes itself to be the root. Used at startup and whenever
 * the previous root is presumed dead (reelection timeout).
 */
static void become_own_root(void *const handle, node_state *const s,
                            const uint64_t t) {
    s->root_addr = s->my_addr;
    s->path_length = 0;
    s->root_port = -1;
    s->last_hello_sent = t;
    s->last_hello_received = t;
    s->last_root_changed = t;

    recompute_port_roles(s);
    broadcast_stp(handle, s);
}

static void handle_stp_packet(void *const handle, node_state *const s,
                              const uint8_t port,
                              const mixnet_packet_stp *const stp) {
    const uint64_t t = now_ms();

    s->neighbor_addr[port] = stp->node_address;
    s->neighbor_known[port] = true;
    s->neighbor_root[port] = stp->root_address;
    s->neighbor_path[port] = stp->path_length;

    const uint16_t candidate_path = (uint16_t) (stp->path_length + 1);
    bool changed = false;

    // Was this port our path to root *before* processing this packet? If
    // so, its sender is our sole source of truth for reaching whatever the
    // root is -- we have no independent way to tell it's wrong -- so its
    // belief is adopted unconditionally (even if it looks "worse" than what
    // we currently have). Any other port's info is only a candidate: we
    // switch to it only if it's strictly better than our current belief.
    const bool via_root_port_before = (s->root_port == (int) port);

    if (via_root_port_before) {
        if ((stp->root_address != s->root_addr) ||
            (candidate_path != s->path_length)) {
            s->root_addr = stp->root_address;
            s->path_length = candidate_path;
            changed = true;
        }
    }
    else if (stp->root_address < s->root_addr) {
        s->root_addr = stp->root_address;
        s->path_length = candidate_path;
        s->root_port = (int) port;
        changed = true;
    }
    else if (stp->root_address == s->root_addr) {
        if (candidate_path < s->path_length) {
            s->path_length = candidate_path;
            s->root_port = (int) port;
            changed = true;
        }
        else if ((candidate_path == s->path_length) &&
                 (s->root_port >= 0) && (s->root_port != (int) port) &&
                 (stp->node_address < s->neighbor_addr[s->root_port])) {
            s->root_port = (int) port; // Tie-break: smaller mixnet address
            changed = true;
        }
    }

    // Recompute using the (possibly just-updated) root_port: a candidate
    // on another port may have just been promoted to our new parent.
    const bool via_root_port = (s->root_port == (int) port);
    if (via_root_port) {
        s->last_hello_received = t; // Heard from our (possibly new) parent
    }

    if (changed) {
        s->last_root_changed = t;
        recompute_port_roles(s);
        broadcast_stp(handle, s);
    }
    else {
        // Our own (root, path_length) didn't change, but this neighbor's
        // advertised info might have, so its port role could still shift.
        recompute_port_roles(s);

        // Relay a hello arriving via our root port onward to every other
        // neighbor, regardless of whether it changed our own belief. This
        // is what carries the root's periodic liveness signal past the
        // first hop, down the rest of the tree.
        if (via_root_port) {
            broadcast_stp(handle, s);
        }
    }
}

// Forward declaration: topology_set() triggers a recompute on every update
// (defined further below, alongside the rest of the FIB-building logic).
static void compute_fib(node_state *const s);

/**
 * Records (or overwrites) the given node's advertised link list in the
 * topology map, then immediately recomputes the FIB against the updated
 * map. Recomputing on every update (rather than waiting for the map to go
 * quiet) means the FIB is always whatever Dijkstra says given what we know
 * so far -- possibly wrong/incomplete mid-convergence, but guaranteed
 * correct by the time the map stops changing, which is all CP2 requires.
 */
static void topology_set(node_state *const s, const mixnet_address addr,
                         const uint16_t neighbor_count,
                         const mixnet_lsa_link_params *const links) {
    topology_entry *entry = &s->topology[addr];

    free(entry->neighbor_addr);
    free(entry->neighbor_cost);

    entry->known = true;
    entry->neighbor_count = neighbor_count;
    entry->neighbor_addr = (mixnet_address*) malloc(neighbor_count * sizeof(mixnet_address));
    entry->neighbor_cost = (uint16_t*) malloc(neighbor_count * sizeof(uint16_t));

    for (uint16_t i = 0; i < neighbor_count; i++) {
        entry->neighbor_addr[i] = links[i].neighbor_mixaddr;
        entry->neighbor_cost[i] = links[i].cost;
    }

    compute_fib(s);
}

/**
 * Builds this node's own LSA from its already-known neighbor addresses and
 * configured link costs, records it as our own topology entry, and sends
 * it out every forwarding port.
 */
static void send_own_lsa(void *const handle, node_state *const s,
                         const uint16_t *const link_costs) {
    mixnet_lsa_link_params *links = (mixnet_lsa_link_params*)
        malloc(s->num_neighbors * sizeof(mixnet_lsa_link_params));

    for (uint16_t i = 0; i < s->num_neighbors; i++) {
        links[i].neighbor_mixaddr = s->neighbor_addr[i];
        links[i].cost = link_costs[i];
    }

    topology_set(s, s->my_addr, s->num_neighbors, links);

    for (uint16_t i = 0; i < s->num_neighbors; i++) {
        if (s->port_forwarding[i]) {
            send_packet(handle, (uint8_t) i,
                make_lsa_packet(s->my_addr, s->num_neighbors, links));
        }
    }
    free(links);
}

static void handle_lsa_packet(void *const handle, node_state *const s,
                              const uint8_t in_port,
                              const mixnet_packet_lsa *const lsa) {
    if (!s->port_forwarding[in_port]) {
        return; // Blocked (non-tree) link; drop silently
    }

    topology_set(s, lsa->node_address, lsa->neighbor_count, lsa->links);

    for (uint16_t i = 0; i < s->num_neighbors; i++) {
        if ((i != in_port) && s->port_forwarding[i]) {
            send_packet(handle, (uint8_t) i,
                make_lsa_packet(lsa->node_address, lsa->neighbor_count, lsa->links));
        }
    }
}

/**
 * Runs Dijkstra from this node over the topology map (dist/prev live on
 * each topology_entry), then reconstructs and stores, for every other
 * known node, the intermediate-hop route to it (excluding src/dst, per
 * the routing header's format) into the FIB.
 */
static void compute_fib(node_state *const s) {
    bool *visited = (bool*) calloc(((uint32_t) UINT16_MAX) + 1, sizeof(bool));

    for (uint32_t addr = 0; addr < ((uint32_t) UINT16_MAX) + 1; addr++) {
        if (!s->topology[addr].known) {
            continue;
        }
        s->topology[addr].dist = (addr == s->my_addr) ? 0 : UINT32_MAX;
        s->topology[addr].prev = INVALID_MIXADDR;
        s->topology[addr].first_hop = INVALID_MIXADDR;
    }

    for (;;) {
        int32_t u = -1;
        for (uint32_t addr = 0; addr < ((uint32_t) UINT16_MAX) + 1; addr++) {
            if (s->topology[addr].known && !visited[addr] &&
                (s->topology[addr].dist != UINT32_MAX) &&
                ((u == -1) || (s->topology[addr].dist < s->topology[(uint32_t) u].dist))) {
                u = (int32_t) addr;
            }
        }
        if (u == -1) {
            break; // No more reachable, unvisited nodes
        }
        visited[(uint32_t) u] = true;

        const topology_entry *const u_entry = &s->topology[(uint32_t) u];
        for (uint16_t i = 0; i < u_entry->neighbor_count; i++) {
            const mixnet_address v = u_entry->neighbor_addr[i];
            if (!s->topology[v].known || visited[v]) {
                continue;
            }
            const uint32_t candidate = u_entry->dist + u_entry->neighbor_cost[i];
            // The neighbor-of-source this candidate path departs through:
            // v itself if u is us, otherwise whatever u already departs through.
            const mixnet_address candidate_first_hop =
                ((mixnet_address) u == s->my_addr) ? v : u_entry->first_hop;

            if (candidate < s->topology[v].dist) {
                s->topology[v].dist = candidate;
                s->topology[v].prev = (mixnet_address) u;
                s->topology[v].first_hop = candidate_first_hop;
            }
            else if ((candidate == s->topology[v].dist) &&
                     (candidate_first_hop < s->topology[v].first_hop)) {
                s->topology[v].prev = (mixnet_address) u;
                s->topology[v].first_hop = candidate_first_hop;
            }
        }
    }
    free(visited);

    mixnet_address path[MAX_MIXNET_ROUTE_LENGTH];
    for (uint32_t addr = 0; addr < ((uint32_t) UINT16_MAX) + 1; addr++) {
        if (!s->topology[addr].known || (addr == s->my_addr) ||
            (s->topology[addr].dist == UINT32_MAX)) {
            continue;
        }

        uint16_t count = 0;
        mixnet_address cur = s->topology[addr].prev;
        while ((cur != INVALID_MIXADDR) && (cur != s->my_addr)) {
            path[count++] = cur;
            cur = s->topology[cur].prev;
        }

        fib_entry *entry = &s->fib[addr];
        free(entry->route); // No-op if this is the first computation for addr
        entry->known = true;
        entry->route_length = count;
        entry->route = (mixnet_address*) malloc(count * sizeof(mixnet_address));
        for (uint16_t i = 0; i < count; i++) {
            entry->route[i] = path[count - 1 - i]; // Reverse: source-to-dest order
        }
    }
}

/**
 * Builds a randomized, loop-free path from this node to dst: a depth-first
 * walk over the known topology graph that, at each step, picks uniformly
 * among the current node's not-yet-visited neighbors, and backtracks to the
 * nearest earlier branch point when a node has none left. Terminates at dst
 * (guaranteed reachable once link-state has converged over a connected
 * network). Writes the intermediate hops (excluding src/dst, matching the
 * FIB's convention) into a freshly malloc'd *out_route -- caller must free.
 */
static void compute_random_route(const node_state *const s,
                                 const mixnet_address dst,
                                 mixnet_address **const out_route,
                                 uint16_t *const out_route_length) {
    bool *visited = (bool*) calloc(((uint32_t) UINT16_MAX) + 1, sizeof(bool));
    mixnet_address stack[MAX_MIXNET_ROUTE_LENGTH];
    uint16_t depth = 0; // number of hops pushed onto stack so far

    mixnet_address current = s->my_addr;
    visited[current] = true;

    while (current != dst) {
        const topology_entry *const entry = &s->topology[current];
        mixnet_address *candidates = (mixnet_address*)
            malloc(entry->neighbor_count * sizeof(mixnet_address));
        uint16_t num_candidates = 0;

        for (uint16_t i = 0; i < entry->neighbor_count; i++) {
            const mixnet_address n = entry->neighbor_addr[i];
            if (s->topology[n].known && !visited[n]) {
                candidates[num_candidates++] = n;
            }
        }

        if (num_candidates > 0) {
            current = candidates[rand() % num_candidates];
            visited[current] = true;
            stack[depth++] = current;
        }
        else { // Dead end: backtrack to the previous branch point.
            depth--;
            current = (depth == 0) ? s->my_addr : stack[depth - 1];
        }
        free(candidates);
    }

    // stack[0 .. depth - 2] are the intermediate hops; stack[depth - 1] == dst.
    *out_route_length = (depth > 0) ? (uint16_t) (depth - 1) : 0;
    *out_route = (mixnet_address*) malloc((*out_route_length) * sizeof(mixnet_address));
    for (uint16_t i = 0; i < *out_route_length; i++) {
        (*out_route)[i] = stack[i];
    }
    free(visited);
}

static void handle_flood_from_user(void *const handle,
                                   node_state *const s) {
    for (uint16_t i = 0; i < s->num_neighbors; i++) {
        if (s->port_forwarding[i]) {
            enqueue_send(s, (uint8_t) i, make_flood_packet());
        }
    }
    mixing_message_received(handle, s);
}

static void handle_flood_from_neighbor(void *const handle,
                                       node_state *const s,
                                       const uint8_t in_port) {
    if (!s->port_forwarding[in_port]) {
        return; // Blocked (non-tree) link; drop silently
    }
    enqueue_send(s, s->user_port, make_flood_packet());

    for (uint16_t i = 0; i < s->num_neighbors; i++) {
        if ((i != in_port) && s->port_forwarding[i]) {
            enqueue_send(s, (uint8_t) i, make_flood_packet());
        }
    }
    mixing_message_received(handle, s);
}

/**
 * A DATA packet arrived from the user (route_length == 0): compute the
 * route to the destination (shortest-path via the FIB, or a randomized walk
 * if configured), build the fully-routed packet, and send it to the first
 * hop.
 */
static void handle_data_from_user(void *const handle, node_state *const s,
                                  const mixnet_packet_routing_header *const rh,
                                  const uint16_t total_size) {
    const uint16_t data_length = (uint16_t) (total_size -
        sizeof(mixnet_packet) - sizeof(mixnet_packet_routing_header));
    const void *const data =
        ((const char*) rh) + sizeof(mixnet_packet_routing_header);

    mixnet_address *route;
    uint16_t route_length;
    if (s->do_random_routing) {
        compute_random_route(s, rh->dst_address, &route, &route_length);
    }
    else {
        const fib_entry *const entry = &s->fib[rh->dst_address];
        route = entry->route;
        route_length = entry->route_length;
    }

    const mixnet_address next_hop = (route_length > 0)
        ? route[0] : rh->dst_address;

    enqueue_send(s, find_port(s, next_hop),
        make_data_packet(rh->src_address, rh->dst_address,
            route_length, route, data, data_length));
    mixing_message_received(handle, s);

    if (s->do_random_routing) {
        free(route);
    }
}

/**
 * A DATA packet arrived from a neighbor, already mid-route: deliver it to
 * the user if we're the destination, otherwise relay it to the next hop
 * per route[hop_index + 1] (or dst_address, if that's past the route).
 */
static void handle_data_from_neighbor(void *const handle, node_state *const s,
                                      const mixnet_packet *const packet,
                                      const mixnet_packet_routing_header *const rh) {
    if (rh->dst_address == s->my_addr) {
        enqueue_send(s, s->user_port,
            copy_packet_with_hop_index(packet, rh->hop_index));
        mixing_message_received(handle, s);
        return;
    }

    const uint16_t next_index = (uint16_t) (rh->hop_index + 1);
    const mixnet_address next_hop = (next_index < rh->route_length)
        ? rh->route[next_index] : rh->dst_address;

    enqueue_send(s, find_port(s, next_hop),
        copy_packet_with_hop_index(packet, next_index));
    mixing_message_received(handle, s);
}

// A PING request arrived from the user (route_length == 0): compute the
// route like DATA (FIB or random walk), and additionally stamp the
// request's is_request/send_time.
static void handle_ping_from_user(void *const handle, node_state *const s,
                                  const mixnet_packet_routing_header *const rh) {
    mixnet_address *route;
    uint16_t route_length;
    if (s->do_random_routing) {
        compute_random_route(s, rh->dst_address, &route, &route_length);
    }
    else {
        const fib_entry *const entry = &s->fib[rh->dst_address];
        route = entry->route;
        route_length = entry->route_length;
    }

    const mixnet_address next_hop = (route_length > 0)
        ? route[0] : rh->dst_address;

    enqueue_send(s, find_port(s, next_hop),
        make_ping_packet(rh->src_address, rh->dst_address,
            route_length, route, true, now_us()));
    mixing_message_received(handle, s);

    if (s->do_random_routing) {
        free(route);
    }
}

/**
 * A PING packet arrived from a neighbor. If we're the destination, always
 * propagate a copy to our own user (per the general delivery rule); if it
 * was a request, additionally turn it around into a response and forward
 * it back out. If we're not the destination, relay it like DATA.
 */
static void handle_ping_from_neighbor(void *const handle, node_state *const s,
                                      const mixnet_packet *const packet,
                                      const mixnet_packet_routing_header *const rh) {
    if (rh->dst_address == s->my_addr) {
        enqueue_send(s, s->user_port,
            copy_packet_with_hop_index(packet, rh->hop_index));

        const mixnet_packet_ping *const ping = (const mixnet_packet_ping*)
            (((const char*) rh) + sizeof(mixnet_packet_routing_header) +
             (rh->route_length * sizeof(mixnet_address)));

        if (ping->is_request) {
            mixnet_address reversed[rh->route_length];
            for (uint16_t i = 0; i < rh->route_length; i++) {
                reversed[i] = rh->route[rh->route_length - 1 - i];
            }
            const mixnet_address next_hop = (rh->route_length > 0)
                ? reversed[0] : rh->src_address;

            enqueue_send(s, find_port(s, next_hop),
                make_ping_packet(rh->dst_address, rh->src_address,
                    rh->route_length, reversed, false, ping->send_time));
        }
        else {
            // A response addressed back to us: this is the round trip we
            // started in handle_ping_from_user() completing. send_time was
            // stamped there (and left untouched by every hop in between), so
            // now_us() - send_time is the full request-to-response RTT.
            // rh->src_address is the node that answered (the ping's original
            // destination).
            const uint64_t rtt_us = now_us() - ping->send_time;
            printf("RTT to %u: %.3f ms (%llu us)\n",
                (unsigned) rh->src_address, ((double) rtt_us) / 1000.0,
                (unsigned long long) rtt_us);
            fflush(stdout);
        }
        mixing_message_received(handle, s);
        return;
    }

    const uint16_t next_index = (uint16_t) (rh->hop_index + 1);
    const mixnet_address next_hop = (next_index < rh->route_length)
        ? rh->route[next_index] : rh->dst_address;

    enqueue_send(s, find_port(s, next_hop),
        copy_packet_with_hop_index(packet, next_index));
    mixing_message_received(handle, s);
}

void run_node(void *const handle,
              volatile bool *const keep_running,
              const struct mixnet_node_config c) {

    node_state s;
    s.my_addr = c.node_addr;
    s.num_neighbors = c.num_neighbors;
    s.user_port = (uint8_t) c.num_neighbors;

    s.neighbor_addr = (mixnet_address*) calloc(s.num_neighbors, sizeof(mixnet_address));
    s.neighbor_known = (bool*) calloc(s.num_neighbors, sizeof(bool));
    s.neighbor_root = (mixnet_address*) calloc(s.num_neighbors, sizeof(mixnet_address));
    s.neighbor_path = (uint16_t*) calloc(s.num_neighbors, sizeof(uint16_t));
    s.port_forwarding = (bool*) calloc(s.num_neighbors, sizeof(bool));
    s.sent_lsa = false;
    s.topology = (topology_entry*) calloc(
        ((uint32_t) UINT16_MAX) + 1, sizeof(topology_entry));
    s.fib = (fib_entry*) calloc(((uint32_t) UINT16_MAX) + 1, sizeof(fib_entry));
    s.do_random_routing = c.do_random_routing;

    s.mixing_factor = c.mixing_factor;
    s.messages_held = 0;
    s.pending_sends = NULL;
    s.pending_count = 0;
    s.pending_capacity = 0;

    for (uint16_t i = 0; i < s.num_neighbors; i++) {
        s.port_forwarding[i] = true;
    }

    // Seeded per-node so sibling processes started at the same wall-clock
    // moment don't all draw the same pseudorandom sequence.
    srand((unsigned int) (now_ms() ^ s.my_addr));

    become_own_root(handle, &s, now_ms());

    while (*keep_running) {
        uint8_t port;
        mixnet_packet *packet = NULL;
        const int received = mixnet_recv(handle, &port, &packet);

        if (received > 0) {
            if (port == s.user_port) {
                if (packet->type == PACKET_TYPE_FLOOD) {
                    handle_flood_from_user(handle, &s);
                }
                else if (packet->type == PACKET_TYPE_DATA) {
                    handle_data_from_user(handle, &s,
                        (const mixnet_packet_routing_header*) packet->payload,
                        packet->total_size);
                }
                else if (packet->type == PACKET_TYPE_PING) {
                    handle_ping_from_user(handle, &s,
                        (const mixnet_packet_routing_header*) packet->payload);
                }
            }
            else if (packet->type == PACKET_TYPE_STP) {
                handle_stp_packet(handle, &s, port,
                    (const mixnet_packet_stp*) packet->payload);
            }
            else if (packet->type == PACKET_TYPE_FLOOD) {
                handle_flood_from_neighbor(handle, &s, port);
            }
            else if (packet->type == PACKET_TYPE_LSA) {
                handle_lsa_packet(handle, &s, port,
                    (const mixnet_packet_lsa*) packet->payload);
            }
            else if (packet->type == PACKET_TYPE_DATA) {
                handle_data_from_neighbor(handle, &s, packet,
                    (const mixnet_packet_routing_header*) packet->payload);
            }
            else if (packet->type == PACKET_TYPE_PING) {
                handle_ping_from_neighbor(handle, &s, packet,
                    (const mixnet_packet_routing_header*) packet->payload);
            }
            free(packet);
            continue; // Drain any other pending packets before sleeping
        }

        const uint64_t t = now_ms();
        // Scenario 1 guarantees no link/node failures, so there is never a
        // legitimate reason to reelect or to re-announce liveness: the
        // periodic root hello (root_hello_interval_ms) and the reelection
        // timeout (reelection_interval_ms) exist purely to detect and
        // recover from a dead root/parent. Every tick either one fires
        // before the tree has finished settling costs a full extra flood,
        // so under this scenario's no-failure guarantee we just leave the
        // tree to converge once via the change-triggered broadcasts in
        // handle_stp_packet() and never re-announce afterward.

        if (!s.sent_lsa && ((t - s.last_root_changed) >=
                (LSA_SILENCE_MULTIPLIER * c.reelection_interval_ms))) {
            send_own_lsa(handle, &s, c.link_costs);
            s.sent_lsa = true;
        }

        struct timespec sleep_time = {0, 1000000}; // 1ms
        nanosleep(&sleep_time, NULL);
    }

    for (uint32_t i = 0; i < ((uint32_t) UINT16_MAX) + 1; i++) {
        free(s.topology[i].neighbor_addr);
        free(s.topology[i].neighbor_cost);
        free(s.fib[i].route);
    }
    free(s.topology);
    free(s.fib);

    free(s.neighbor_addr);
    free(s.neighbor_known);
    free(s.neighbor_root);
    free(s.neighbor_path);
    free(s.port_forwarding);

    for (uint16_t i = 0; i < s.pending_count; i++) {
        free(s.pending_sends[i].packet);
    }
    free(s.pending_sends);
}
