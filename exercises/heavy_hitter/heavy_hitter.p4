#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4  = 0x800;
const bit<16> TYPE_PROBE = 0x812;

#define MAX_HOPS 10
#define MAX_PORTS 8
#define THRESHOLD 1000

#include "includes/headers.p4"
#include "includes/parser.p4"

/*************************************************************************
**************  C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {}
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action no_op() {}

    action drop() {
        standard_metadata.egress_spec = 0;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    action count_flow() {
        meta.flow_count = meta.flow_count + 1;
        if (meta.flow_count > THRESHOLD) {
            mark_to_drop();
        }
    }

    table heavy_hitter_detection {
        key = {
            meta.flow_id_srcAddr : exact;
            meta.flow_id_dstAddr : exact;
            meta.flow_id_srcPort : exact;
            meta.flow_id_dstPort : exact;
            meta.flow_id_proto   : exact;
        }
        actions = {
            count_flow;
            NoAction;
        }
        size = 1024;
        default_action = NoAction(); 
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
            ipv4_lpm.apply();
        } 
        else if(hdr.probe.isValid()) {
            standard_metadata.egress_spec = (bit<9>) meta.egress_spec;
            hdr.probe.hop_cnt = hdr.probe.hop_cnt + 1;
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    // count the number of bytes seen since the last probe
    register<bit<32>>(MAX_PORTS) byte_cnt_reg;
    //remember the time of the last probe
    register<time_t>(MAX_PORTS) last_time_reg;

    action set_swid(bit<7> swid) {
        hdr.probe_data[0].swid = swid;
    }

    table swid {
        actions = {
            set_swid;
            NoAction;
        }
        default_action = NoAction();
    }

    apply { 
        bit<32> byte_cnt;
        bit<32> new_byte_cnt;
        time_t last_time;
        time_t cur_time = standard_metadata.egress_global_timestamp;
        
        // increment byte cnt for the packet's port
        byte_cnt_reg.read(byte_cnt, (bit<32>)standard_metadata.egress_port, new_byte_cnt);

        // reset the byte count when a probe packet passes through
        new_byte_cnt = (hdr.probe.isValid()) ? 0 : byte_cnt;
        byte_cnt_reg.write((bit<32>)standard_metadata.egress_port, new_byte_cnt);

        if(hdr.probe.isValid()) {
            // fill out probe fields
            hdr.probe_data.push_front(1);
            hdr.probe_data[0].setValid();
            if(hdr.probe.hop_cnt == 1) {
                hdr.probe_data[0].bos = 1;
            }
            else {
                hdr.probe_data[0].bos = 0;
            }

            // set switch ID field
            swid.apply();
            hdr.probe_data[0].port = (bit<8>) standard_metadata.egress_port;
            hdr.probe_data[0].byte_cnt = byte_cnt;

            // read / update the last last_time_reg
            last_time_reg.read(last_time, (bit<32>) standard_metadata.egress_port);
            last_time_reg.write((bit<32>)standard_metadata.egress_port, cur_time);

            hdr.probe_data[0].last_time = last_time;
            hdr.probe_data[0].cur_time = cur_time;
        }
    }
}

/*************************************************************************
**************  C H E C K S U M  C O M P U T A T I O N  ******************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ipl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.probe);
        packet.emit(hdr.probe_data);
        packet.emit(hdr.probe_fwd);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(MyParser(),
        MyParser(),
        MyVerifyChecksum(),
        MyIngress(),
        MyEgress(),
        MyComputeChecksum(),
        MyDeparser()) main;
