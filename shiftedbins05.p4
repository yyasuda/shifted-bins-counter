#include <core.p4>
#include <v1model.p4>

#define CPU_PORT 255
/*
  255 is confirmed for opennetworking/p4mn　(Mininet/Stratum on docker)
  192 is confirmed for WEDGE-100BF-32X (2 pipes device)
  320 is probably good for 4 pipes devices
*/

const bit<16> TYPE_IPV4 = 0x800;

// Shifted Bins structure
#define MAX_LOTS 8 // max number of shifted bins
register<bit<32>>(MAX_LOTS) offset_regs; // {bins[offset_regs[n] + index] is target counter} 
register<bit<32>>(MAX_LOTS) shift_regs; // {20, 18, ..} timestamp is usec, 20 is near 1sec (2^20 = 1 million)
#define MAX_COUNTERS 1024 // max number of size of counter (keep MAX_COUNTERS >= LOTS * BINS)
counter(MAX_COUNTERS, CounterType.packets) bins;

// there is no global variables, so there are no need to be array sigh...
register<bit<32>>(1) lots_regs;    // number of shifted bins
register<bit<32>>(1) max_bin_regs; // number of bin (of each single shifted bins)
register<bit<48>>(1) prev_ts_regs; // time stamp

typedef bit<9> egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

@controller_header("packet_out")
header packet_out_header_t {
    bit<32> lots; // needs to be lots <= MAX_LOTS
    bit<32> bins; // needs to be lots * bins <= MAX_COUNTERS
    bit<32> offset_0;
    bit<32> shift_0;
    bit<32> offset_1;
    bit<32> shift_1;
    bit<32> offset_2;
    bit<32> shift_2;
    bit<32> offset_3;
    bit<32> shift_3;
    bit<32> offset_4;
    bit<32> shift_4;
    bit<32> offset_5;
    bit<32> shift_5;
    bit<32> offset_6;
    bit<32> shift_6;
    bit<32> offset_7;
    bit<32> shift_7;
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
    /* empty */
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
        transition accept;
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
    
    // temporal variables
    bit<48> prev_ts;

    action count_bin(bit<32> lot) {
        bit<32> shift;
        bit<32> bin_index;
        bit<32> offset;
        bit<32> max_bin;
        shift_regs.read(shift, lot); 
        bin_index = (bit<32>)( ( standard_metadata.ingress_global_timestamp - prev_ts ) >> (bit<8>)shift);
        max_bin_regs.read(max_bin, 0); 
        if( bin_index > (max_bin -1) ) bin_index = max_bin -1; // overflow
        offset_regs.read(offset, lot); 
        bins.count( offset + bin_index );
    }

    apply {
        if (standard_metadata.ingress_port == CPU_PORT) { // must Packet-Out
            lots_regs.write(0, hdr.packet_out.lots);
            max_bin_regs.write(0, hdr.packet_out.bins);

            offset_regs.write(0, hdr.packet_out.offset_0);
            shift_regs.write(0, hdr.packet_out.shift_0);
            offset_regs.write(1, hdr.packet_out.offset_1);
            shift_regs.write(1, hdr.packet_out.shift_1);
            offset_regs.write(2, hdr.packet_out.offset_2);
            shift_regs.write(2, hdr.packet_out.shift_2);
            offset_regs.write(3, hdr.packet_out.offset_3);
            shift_regs.write(3, hdr.packet_out.shift_3);
            offset_regs.write(4, hdr.packet_out.offset_4);
            shift_regs.write(4, hdr.packet_out.shift_4);
            offset_regs.write(5, hdr.packet_out.offset_5);
            shift_regs.write(5, hdr.packet_out.shift_5);
            offset_regs.write(6, hdr.packet_out.offset_6);
            shift_regs.write(6, hdr.packet_out.shift_6);
            offset_regs.write(7, hdr.packet_out.offset_7);
            shift_regs.write(7, hdr.packet_out.shift_7);

            // hdr.packet_out.setInvalid();
            mark_to_drop(standard_metadata);
        } else {
            if (hdr.ethernet.isValid()) {
                if( l2_dst_table.apply().hit) {
                    // get timestamp
                    prev_ts_regs.read(prev_ts, 0); 

                    // count each bin
                    count_bin(0); // bin #1
                    count_bin(1); // bin #2
                    count_bin(2); // bin #3
                    count_bin(3); // bin #4
                    count_bin(4); // bin #5
                    count_bin(5); // bin #6
                    count_bin(6); // bin #7
                    count_bin(7); // bin #8

                    // update timestamp
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
