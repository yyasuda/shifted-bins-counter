#include <core.p4>
#include <v1model.p4>

#define CPU_PORT 255
/*
  255 is confirmed for opennetworking/p4mn　(Mininet/Stratum on docker)
  192 is confirmed for WEDGE-100BF-32X (2 pipes device)
  320 is probably good for 4 pipes devices
*/

const bit<16> TYPE_IPV4 = 0x800;

typedef bit<9> egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

@controller_header("packet_out")
header packet_out_header_t {
    bit<9> egress_port;
    bit<7> _pad;
    bit<16> mcast_grp;
}

@controller_header("packet_in")
header packet_in_header_t {
    bit<9> ingress_port;
    bit<7> _pad;
}

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
    bit<9> ingress_port;
    bit<7> _pad1;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t  ipv4;
    packet_out_header_t packet_out;
    packet_in_header_t packet_in;
}

parser MyParser(packet_in packet, out headers hdr, inout metadata meta,
                inout standard_metadata_t standard_metadata)
{
    state start {
        transition select(standard_metadata.ingress_port) {
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
    }
 
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

control MyIngress(inout headers hdr, inout metadata meta,
                    inout standard_metadata_t standard_metadata)
{
    action forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    action to_controller() {
        standard_metadata.egress_spec = CPU_PORT;
        hdr.packet_in.setValid();
    }

    action nop() { } // nothing to do

    table l2_dst_table {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            forward;
        }
        size = 1024;
        // default_action = flooding;
    }

    const int SHIFT = 19; // timestamp is usec, 20 is near 1sec (2^20 = 1 million)
    const int BINS = 10; // timestamp is usec, 20 is near 1sec (2^20 = 1 million)
    counter(BINS+1, CounterType.packets) bins_1;
    register<bit<48>>(1) prev_ts_regs; // no need to be array sigh...
    bit<48> prev_ts;
    bit<32> bin_index;

    apply {
        if (standard_metadata.ingress_port == CPU_PORT) { // must Packet-Out
            // nothing to do right now
            hdr.packet_out.setInvalid();
        } else {
            if (hdr.ethernet.isValid()) {
                if( l2_dst_table.apply().hit) {
                    prev_ts_regs.read(prev_ts, 0); 
                    bin_index = (bit<32>)( ( standard_metadata.ingress_global_timestamp - prev_ts ) >> SHIFT);
                    if( bin_index > (BINS -1) ) bin_index = BINS; // overflow
                    bins_1.count(bin_index); // toriaezu zero
                    prev_ts_regs.write(0, standard_metadata.ingress_global_timestamp);
                }
            }
        }
    }
}

control MyEgress(inout headers hdr, inout metadata meta,
                inout standard_metadata_t standard_metadata)
{
    apply { }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
            update_checksum(
                hdr.ipv4.isValid(),
            {   hdr.ipv4.version,
                  hdr.ipv4.ihl,
                  hdr.ipv4.diffserv,
                  hdr.ipv4.totalLen,
                  hdr.ipv4.identification,
                  hdr.ipv4.flags,
                  hdr.ipv4.fragOffset,
                  hdr.ipv4.ttl,
                  hdr.ipv4.protocol,
                  hdr.ipv4.srcAddr,
                  hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr)
{
    apply {
        // packet.emit(hdr.packet_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
