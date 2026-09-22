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
#include "common/testing.h"

/**
 * RTT driver for the 8-node RING topology (Step 1 of the lab), the same
 * topology wired up in testcase_stp_convergence_ring:
 *
 *      0 - 1 - 2 - 3
 *      |           |
 *      7 - 6 - 5 - 4
 *
 * On an 8-node ring the two furthest nodes are diametrically opposite (4
 * hops apart either way around); we ping 0 -> 4.
 *
 * As in testcase_rtt_line, this test-case does NOT compute the RTT itself --
 * the source node (0) prints it on receiving the ping response (see the
 * handout, Step 1, RTT). Run it in manual mode across your cluster
 * (co-locate the orchestrator with node 0); the RTT line appears on node 0's
 * terminal (or its per-host log under run_ec2.sh with NODE_LOGS=1).
 */
class testcase_rtt_ring final : public testcase {
public:
    explicit testcase_rtt_ring() : testcase("testcase_rtt_ring") {}

    virtual void pcap(const uint16_t /* fragment_id */,
                      const mixnet_packet *const packet) override {
        // We only expect the ping request (delivered at node 4) and the ping
        // response (delivered back at node 0).
        if (packet->type == PACKET_TYPE_PING) { pcap_count_++; }
        else { pass_pcap_ = false; }
    }

    virtual void setup() override {
        init_graph(8);
        graph_->generate_topology(graph::type::RING);
        // Default mixnet addresses are the node indices (0..7), so the ring
        // is 0-1-...-7-0 and the two furthest nodes are 0 and 4.
    }

    virtual error_code run(orchestrator& o) override {
        await_convergence();                 // let STP + routing settle
        // Watch every node's user-delivered packets via the pcap plane.
        for (uint16_t i = 0; i < graph_->num_nodes; i++) {
            DIE_ON_ERROR(o.pcap_change_subscription(i, true));
        }
        // Ping between the two furthest nodes; source = node 0.
        DIE_ON_ERROR(o.send_packet(0, 4, PACKET_TYPE_PING));
        await_packet_propagation();
        return error_code::NONE;
    }

    virtual void teardown() override {
        // Request delivered at node 4 + response delivered back at node 0.
        pass_teardown_ = (pcap_count_ == 2);
    }
};

int main(int argc, char **argv) {
    testcase_rtt_ring tc;
    return testcase::run_testcase(tc, argc, argv);
}
