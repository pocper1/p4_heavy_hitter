#include <core.p4>
#include <v1model.p4>
#include "includes/headers.p4"
#include "includes/parser.p4"

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_SRCROUTING = 0x1234;

const bit<32> THRESHOLD = 1000;

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action count_packets() {
        heavy_hitter_counter.count(meta.pkt_id);
        if(heavy_hitter_counter.read(meta.pkt_id) > THRESHOLD) {
            mark_as_heavy_hitter();
            report_heavy_hitter();
        }
    }

    action mark_as_heavy_hitter() {
        hdr.ipv4.diffserv = 0x2E;
    }

    action report_heavy_hitter() {
        generate_digest(digest_id, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr});
    }

    table detect_heavy_hitter {
        actions = {
            count_packets;
            NoAction;
        }

        key = {
            hdr.ipv4.srcAddr: lpm;
            hdr.ipv4.dstAddr: lpm;
        }

        size = 4096;
        default_action = NoAction();
    }
    action drop() {
        mark_to_drop(standard_metadata);
    }

    apply {
        if(hdr.ipv4.isValid()) {
            detect_heavy_hitter.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
