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

    action no_op() {}

    action count_flow() {
        meta.flow_count = meta.flow_count + 1;
        if (meta.flow_count > THRESHOLD) {
            standard_metadata.egress_spec = 0;
        }
    }

    action update_link_status() {
        meta.link_status = 1;
    }

    action reset_link_status() {
        meta.link_status = 0;
    }

    table heavy_hitter_detection {
        key = {
            meta.flow_id : exact;
        }
        actions = {
            count_flow;
            no_op;
        }
        size = 1024;
        default_action = no_op(); 
    }

    table link_monitor {
        key = {
            hdr.ethernet.srcAddr : exact;
            hdr.ethernet.dstAddr : exact;
        }
        actions = {
            update_link_status;
            reset_link_status;
            no_op;
        }
        size = 1024;
        default_action = no_op();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            meta.flow_id.srcAddr = hdr.ipv4.srcAddr;
            meta.flow_id.dstAddr = hdr.ipv4.dstAddr;
            meta.flow_id.proto = hdr.ipv4.protocol;

            if (hdr.tcp.isValid()) {
                meta.flow_id.srcPort = hdr.tcp.srcPort;
                meta.flow_id.dstPort = hdr.tcp.dstPort;
            } else if (hdr.udp.isValid()) {
                meta.flow_id.srcPort = hdr.udp.srcPort;
                meta.flow_id.dstPort = hdr.udp.dstPort;
            }
            heavy_hitter_detection.apply();
            link_monitor.apply();
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
        if (hdr.tcp.isValid()) {
            packet.emit(hdr.tcp);
        } else if (hdr.udp.isValid()) {
            packet.emit(hdr.udp);
        }
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyIngress(),
MyEgress(),
MyDeparser()
) main;
