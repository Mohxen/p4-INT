/*
 * Copyright 2020-2021 PSNC, FBK
 *
 * Author: Damian Parniewicz, Damu Ding
 *
 * Created in the GN4-3 project.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 /*
 * Edited by Mohsen Rahmati
 */

/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** D E F I N E  *************************************
*************************************************************************/

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6

const bit<6> IPv4_DSCP_INT = 0x20;   // indicates an INT header in the packet
const bit<16> INT_SHIM_HEADER_LEN_BYTES = 4;
const bit<8> INT_TYPE_HOP_BY_HOP = 1;

const bit<16> INT_HEADER_LEN_BYTES = 8;
const bit<4> INT_VERSION = 1;

const bit<16> INT_ALL_HEADER_LEN_BYTES = INT_SHIM_HEADER_LEN_BYTES + INT_HEADER_LEN_BYTES;

const bit<4> INT_REPORT_HEADER_LEN_WORDS = 4;
const bit<4> INT_REPORT_VERSION = 1;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<6>  dscp;
    bit<2>  ecn;
    bit<16> totalLen;
    bit<16> id;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> csum;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNum;
    bit<32> ackNum;
    bit<4>  dataOffset;
    bit<3>  reserved;
    bit<9>  flags;
    bit<16> winSize;
    bit<16> csum;
    bit<16> urgPoint;
}

header intl4_shim_t {
    bit<8> int_type;
    bit<8> rsvd1;
    bit<8> len;    // the length of all INT headers in 4-byte words
    bit<6> dscp;  // copy DSCP here
    bit<2> rsvd3;
}

header int_header_t {
    bit<4>  ver;
    bit<2>  rep;
    bit<1>  c;
    bit<1>  e;
    bit<1>  m;
    bit<7>  rsvd1;
    bit<3>  rsvd2;
    bit<5>  hop_metadata_len;   // the length of the metadata added by a single INT node (4-byte words)
    bit<8>  remaining_hop_cnt;  // how many switches can still add INT metadata
    bit<16> instruction_mask;
    bit<16> seq;  // rsvd3 - custom implementation of a sequence number
}

header int_switch_id_t {
    bit<32> switch_id;
}

header int_port_ids_t {
    bit<16> ingress_port_id;
    bit<16> egress_port_id;
}

header int_hop_latency_t {
    bit<32> hop_latency;
}

header int_q_occupancy_t {
    bit<8>  q_id;
    bit<24> q_occupancy;
}

header int_ingress_tstamp_t {
    bit<64> ingress_tstamp;
}

header int_egress_tstamp_t {
    bit<64> egress_tstamp;
}

header int_level2_port_ids_t {
    bit<16> ingress_port_id;
    bit<16> egress_port_id;
}

header int_egress_port_tx_util_t {
    bit<32> egress_port_tx_util;
}

header int_report_fixed_header_t {
    bit<4> ver;
    bit<4> len;
    bit<3> nprot;
    bit<5> rep_md_bits_high; // Split rep_md_bits to align to word boundaries
    bit<1> rep_md_bits_low;
    bit<6> reserved;
    bit<1> d;
    bit<1> q;
    bit<1> f;
    bit<6> hw_id;
    bit<32> switch_id;
    bit<32> seq_num;
    bit<32> ingress_tstamp;
}

struct int_metadata_t {
    bit<1>  source;    // is INT source functionality enabled
    bit<1>  sink;        // is INT sink functionality enabled
    bit<32> switch_id;  // INT switch id is configured by network controller
    bit<16> insert_byte_cnt;  // counter of inserted INT bytes
    bit<8>  int_hdr_word_len;  // counter of inserted INT words
    bit<1>  remove_int;           // indicator that all INT headers and data must be removed at egress for the processed packet 
    bit<16> sink_reporting_port;    // on which port INT reports must be send to INT collector
    bit<64> ingress_tstamp;   // pass ingress timestamp from Ingress pipeline to Egress pipeline
    bit<16> ingress_port;  // pass ingress port from Ingress pipeline to Egress pipeline 
}

struct layer34_metadata_t {
    bit<32> ip_src;
    bit<32> ip_dst;
    bit<8>  ip_ver;
    bit<16> l4_src;
    bit<16> l4_dst;
    bit<8>  l4_proto;
    bit<16> l3_mtu;
    bit<6>  dscp;
}

struct metadata {
    int_metadata_t       int_metadata;
    intl4_shim_t         int_shim;
    layer34_metadata_t   layer34_metadata;
}

header int_data_t {
    // Enough room for previous 4 nodes worth of data
    varbit<1600> data;
}

struct headers {
    // INT report headers
    ethernet_t                report_ethernet;
    ipv4_t                    report_ipv4;
    udp_t                     report_udp;
    int_report_fixed_header_t report_fixed_header;
    
    // normal headers
    ethernet_t                ethernet;
    ipv4_t                    ipv4;
    tcp_t                     tcp;
    udp_t                     udp;

    // INT headers
    intl4_shim_t              int_shim;
    int_header_t              int_header;
  
    // local INT node metadata
    int_egress_port_tx_util_t int_egress_port_tx_util;
    int_egress_tstamp_t       int_egress_tstamp;
    int_hop_latency_t         int_hop_latency;
    int_ingress_tstamp_t      int_ingress_tstamp;
    int_port_ids_t            int_port_ids;
    int_level2_port_ids_t     int_level2_port_ids;
    int_q_occupancy_t         int_q_occupancy;
    int_switch_id_t           int_switch_id;

    // INT metadata of previous nodes
    int_data_t                int_data;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
error {
	INTShimLenTooShort,
	INTVersionNotSupported
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    state start {
       transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.layer34_metadata.ip_src = hdr.ipv4.srcAddr;
        meta.layer34_metadata.ip_dst = hdr.ipv4.dstAddr;
        meta.layer34_metadata.ip_ver = 8w4;
        meta.layer34_metadata.dscp = hdr.ipv4.dscp;
        transition select(hdr.ipv4.protocol) {
            8w0x11: parse_udp;
            8w0x6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        meta.layer34_metadata.l4_src = hdr.tcp.srcPort;
        meta.layer34_metadata.l4_dst = hdr.tcp.dstPort;
        meta.layer34_metadata.l4_proto = 8w0x6;
        transition select(meta.layer34_metadata.dscp) {
            IPv4_DSCP_INT: parse_int;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        meta.layer34_metadata.l4_src = hdr.udp.srcPort;
        meta.layer34_metadata.l4_dst = hdr.udp.dstPort;
        meta.layer34_metadata.l4_proto = 8w0x11;
        transition select(meta.layer34_metadata.dscp, hdr.udp.dstPort) {
            (6w0x20 &&& 6w0x3f, 16w0x0 &&& 16w0x0): parse_int;
            default: accept;
        }
    }

    state parse_int {
        packet.extract(hdr.int_shim);
        /*verify(hdr.int_shim.len >= 3, error.INTShimLenTooShort);*/
        packet.extract(hdr.int_header);
        // DAMU: warning (from TOFINO): Parser "verify" is currently unsupported
        /*verify(hdr.int_header.ver == INT_VERSION, error.INTVersionNotSupported);*/
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

/*************************************************************************
************************  F O R W A R D  *********************************
*************************************************************************/

control Forward(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action send_to_cpu(bit<9> port) {
        standard_metadata.egress_spec = port;
    }
    action send_to_port(bit<9> port) {
        standard_metadata.egress_spec = port;
    }
    table tb_forward {
        actions = {
            send_to_cpu;
            send_to_port;
        }
        key = {
            hdr.ethernet.dstAddr: ternary;
        }
        size = 31;
    }

    apply {
        tb_forward.apply();
    }
}

/*************************************************************************
************************  I N T   R E P O R T ****************************
*************************************************************************/

// Code adapted from:
// - https://github.com/baru64/int-p4/blob/master/int.p4app/p4src/int_report.p4

// register to store seq_num
register<bit<32>> (1) report_seq_num_register;

control Int_report(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    bit<32> seq_num_value = 0;

    // INT Report structure
    // [Eth][IP][UDP][INT RAPORT HDR][ETH][IP][UDP/TCP][INT SHIM][INT DATA]

    action send_report(bit<48> dp_mac, bit<32> dp_ip, bit<48> collector_mac, bit<32> collector_ip, bit<16> collector_port) {

        // Ethernet **********************************************************
        hdr.report_ethernet.setValid();
        hdr.report_ethernet.dstAddr = collector_mac;
        hdr.report_ethernet.srcAddr = dp_mac;
        hdr.report_ethernet.etherType = 0x0800;

        // IPv4 **************************************************************
        hdr.report_ipv4.setValid();
        hdr.report_ipv4.version = 4;
        hdr.report_ipv4.ihl = 5;
        hdr.report_ipv4.dscp = 0;
        hdr.report_ipv4.ecn = 0;

        // 2x ipv4 header (20*2) + udp header (8) + eth header (14) + report header (16) + int data len
        hdr.report_ipv4.totalLen = (bit<16>)(20 + 20 + 8 + 14)
            + ((bit<16>)(INT_REPORT_HEADER_LEN_WORDS)<<2)
            + (((bit<16>)hdr.int_shim.len) << 2);

        // add size of original tcp/udp header
        if (hdr.tcp.isValid()) {
            hdr.report_ipv4.totalLen = hdr.report_ipv4.totalLen
                + (((bit<16>)hdr.tcp.dataOffset) << 2);

        } else {
            hdr.report_ipv4.totalLen = hdr.report_ipv4.totalLen + 8;
        }

        hdr.report_ipv4.id = 0;
        hdr.report_ipv4.flags = 0;
        hdr.report_ipv4.fragOffset = 0;
        hdr.report_ipv4.ttl = 64;
        hdr.report_ipv4.protocol = 17; // UDP
        hdr.report_ipv4.srcAddr = dp_ip;
        hdr.report_ipv4.dstAddr = collector_ip;

        // UDP ***************************************************************
        hdr.report_udp.setValid();
        hdr.report_udp.srcPort = 0;
        hdr.report_udp.dstPort = collector_port;
        hdr.report_udp.len = hdr.report_ipv4.totalLen - 20;

        // INT report fixed header ************************************************/
        // INT report version 1.0
        hdr.report_fixed_header.setValid();
        hdr.report_fixed_header.ver = INT_REPORT_VERSION;
        hdr.report_fixed_header.len = INT_REPORT_HEADER_LEN_WORDS;

        hdr.report_fixed_header.nprot = 0; // 0 for Ethernet
        hdr.report_fixed_header.rep_md_bits_high = 0;
        hdr.report_fixed_header.rep_md_bits_low = 0;
        hdr.report_fixed_header.reserved = 0;
        hdr.report_fixed_header.d = 0;
        hdr.report_fixed_header.q = 0;
        // f - indicates that report is for tracked flow, INT data is present
        hdr.report_fixed_header.f = 1;
        // hw_id - specific to the switch, e.g. id of linecard
        hdr.report_fixed_header.hw_id = 0;
        hdr.report_fixed_header.switch_id = meta.int_metadata.switch_id;

        report_seq_num_register.read(seq_num_value, 0);
        hdr.report_fixed_header.seq_num = seq_num_value;
        report_seq_num_register.write(0, seq_num_value + 1);

        hdr.report_fixed_header.ingress_tstamp = (bit<32>)standard_metadata.ingress_global_timestamp;

        // Original packet headers, INT shim and INT data come after report header.
        // drop all data besides int report and report eth header
        truncate((bit<32>)hdr.report_ipv4.totalLen + 14);
    }

    table tb_int_reporting {
        actions = {
            send_report;
        }
        size = 512;
    }

    apply {
        tb_int_reporting.apply();
    }
}

/*************************************************************************
************************  I N T   S I N K ********************************
*************************************************************************/

const bit<32> INT_REPORT_MIRROR_SESSION_ID = 1;   // mirror session specifying egress_port for cloned INT report packets, defined by switch CLI command   

control Int_sink_config(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    action configure_sink(bit<16> sink_reporting_port) {
        meta.int_metadata.remove_int = 1;   // indicate that INT headers must be removed in egress
        meta.int_metadata.sink_reporting_port = (bit<16>)sink_reporting_port; 
        clone3<metadata>(CloneType.I2E, INT_REPORT_MIRROR_SESSION_ID, meta);
    }

    // Table used to activate INT sink for a particular egress port of the switch
    table tb_int_sink {
        actions = {
            configure_sink;
        }
        key = {
            standard_metadata.egress_spec: exact;
        }
        size = 255;
    }
    
    apply {
        // INT sink must process only INT packets
        if (!hdr.int_header.isValid())
            return;
        
        tb_int_sink.apply();
    }
}

control Int_sink(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    action remove_sink_header() {
         // Restore original headers
        hdr.ipv4.dscp = hdr.int_shim.dscp;
        bit<16> len_bytes = ((bit<16>)hdr.int_shim.len) << 2;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - len_bytes;
        if (hdr.udp.isValid()) {
            hdr.udp.len = hdr.udp.len - len_bytes;
        }

        // Remove INT data added in INT sink
        hdr.int_switch_id.setInvalid();
        hdr.int_port_ids.setInvalid();
        hdr.int_ingress_tstamp.setInvalid();
        hdr.int_egress_tstamp.setInvalid();
        hdr.int_hop_latency.setInvalid();
        hdr.int_level2_port_ids.setInvalid();
        hdr.int_q_occupancy.setInvalid();
        hdr.int_egress_port_tx_util.setInvalid();
        
        // Remove INT data
        hdr.int_shim.setInvalid();
        hdr.int_header.setInvalid();
    }

    apply {
        // INT sink must process only INT packets
        if (!hdr.int_header.isValid())
            return;

        if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_NORMAL && meta.int_metadata.remove_int == 1) {
            // Remove INT headers from a frame
            remove_sink_header();
        }
        if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE) {
            // Prepare an INT report for the INT collector
            Int_report.apply(hdr, meta, standard_metadata);
        }
    }
}

/*************************************************************************
************************  I N T   T R A N S I T **************************
*************************************************************************/

control Int_transit(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    // Configure parameters of INT transit node:
    // switch_id which is used within INT node metadata
    // l3_mtu is currently not used but should allow detecting if adding new INT metadata will exceed allowed MTU packet size
    action configure_transit(bit<32> switch_id, bit<16> l3_mtu) {
        meta.int_metadata.switch_id = switch_id;
        meta.int_metadata.insert_byte_cnt = 0;
        meta.int_metadata.int_hdr_word_len = 0;
        meta.layer34_metadata.l3_mtu = l3_mtu;
    }

    // Table used to configure a switch as an INT transit
    // If INT transit is configured, then all packets with an INT header will be processed by INT transit logic
    table tb_int_transit {
        actions = {
            configure_transit;
        }
    }

    action int_set_header_0() {
        hdr.int_switch_id.setValid();
        hdr.int_switch_id.switch_id = meta.int_metadata.switch_id;
    }
    action int_set_header_1() {
        hdr.int_port_ids.setValid();
        hdr.int_port_ids.ingress_port_id = meta.int_metadata.ingress_port;
        hdr.int_port_ids.egress_port_id = (bit<16>)standard_metadata.egress_port;
    }
    action int_set_header_2() {
        hdr.int_hop_latency.setValid();
        hdr.int_hop_latency.hop_latency = (bit<32>)(standard_metadata.egress_global_timestamp - standard_metadata.ingress_global_timestamp);
    }
    action int_set_header_3() {
        hdr.int_q_occupancy.setValid();
        hdr.int_q_occupancy.q_id = 0; // qid not defined in v1model
        hdr.int_q_occupancy.q_occupancy = (bit<24>)standard_metadata.enq_qdepth;
    }
    action int_set_header_4() {
        hdr.int_ingress_tstamp.setValid();
        bit<64> _timestamp = (bit<64>)meta.int_metadata.ingress_tstamp;  
        hdr.int_ingress_tstamp.ingress_tstamp = hdr.int_ingress_tstamp.ingress_tstamp + 1000 * _timestamp;
    }
    action int_set_header_5() {
        hdr.int_egress_tstamp.setValid();
        bit<64> _timestamp = (bit<64>)standard_metadata.egress_global_timestamp;
        hdr.int_egress_tstamp.egress_tstamp = hdr.int_egress_tstamp.egress_tstamp + 1000 * _timestamp;
    }
    action int_set_header_6() {
        hdr.int_level2_port_ids.setValid();
        hdr.int_level2_port_ids.ingress_port_id = 0;
        hdr.int_level2_port_ids.egress_port_id = 0;
    }
    action int_set_header_7() {
        hdr.int_egress_port_tx_util.setValid();
        hdr.int_egress_port_tx_util.egress_port_tx_util = 0;
    }

    action add_1() {
        meta.int_metadata.int_hdr_word_len = meta.int_metadata.int_hdr_word_len + 1;
        meta.int_metadata.insert_byte_cnt = meta.int_metadata.insert_byte_cnt + 4;
    }

    action add_2() {
        meta.int_metadata.int_hdr_word_len = meta.int_metadata.int_hdr_word_len + 2;
        meta.int_metadata.insert_byte_cnt = meta.int_metadata.insert_byte_cnt + 8;
    }

    action add_3() {
        meta.int_metadata.int_hdr_word_len = meta.int_metadata.int_hdr_word_len + 3;
        meta.int_metadata.insert_byte_cnt = meta.int_metadata.insert_byte_cnt + 12;
    }

    action add_4() {
        meta.int_metadata.int_hdr_word_len = meta.int_metadata.int_hdr_word_len + 4;
        meta.int_metadata.insert_byte_cnt = meta.int_metadata.insert_byte_cnt + 16;
    }

    action add_5() {
        meta.int_metadata.int_hdr_word_len = meta.int_metadata.int_hdr_word_len + 5;
        meta.int_metadata.insert_byte_cnt = meta.int_metadata.insert_byte_cnt + 20;
    }

    action add_6() {
        meta.int_metadata.int_hdr_word_len = meta.int_metadata.int_hdr_word_len + 6;
        meta.int_metadata.insert_byte_cnt = meta.int_metadata.insert_byte_cnt + 24;
    }

    table tb_int_inst_0003 {
        actions = {
            int_set_header_0003_i0;
            int_set_header_0003_i1;
            int_set_header_0003_i2;
            int_set_header_0003_i3;
            int_set_header_0003_i4;
            int_set_header_0003_i5;
            int_set_header_0003_i6;
            int_set_header_0003_i7;
            int_set_header_0003_i8;
            int_set_header_0003_i9;
            int_set_header_0003_i10;
            int_set_header_0003_i11;
            int_set_header_0003_i12;
            int_set_header_0003_i13;
            int_set_header_0003_i14;
            int_set_header_0003_i15;
        }
        key = {
            hdr.int_header.instruction_mask: ternary;
        }
        const entries = {
            0x0000 &&& 0xF000 : int_set_header_0003_i0();
            0x1000 &&& 0xF000 : int_set_header_0003_i1();
            0x2000 &&& 0xF000 : int_set_header_0003_i2();
            0x3000 &&& 0xF000 : int_set_header_0003_i3();
            0x4000 &&& 0xF000 : int_set_header_0003_i4();
            0x5000 &&& 0xF000 : int_set_header_0003_i5();
            0x6000 &&& 0xF000 : int_set_header_0003_i6();
            0x7000 &&& 0xF000 : int_set_header_0003_i7();
            0x8000 &&& 0xF000 : int_set_header_0003_i8();
            0x9000 &&& 0xF000 : int_set_header_0003_i9();
            0xA000 &&& 0xF000 : int_set_header_0003_i10();
            0xB000 &&& 0xF000 : int_set_header_0003_i11();
            0xC000 &&& 0xF000 : int_set_header_0003_i12();
            0xD000 &&& 0xF000 : int_set_header_0003_i13();
            0xE000 &&& 0xF000 : int_set_header_0003_i14();
            0xF000 &&& 0xF000 : int_set_header_0003_i15();
        }
    }

    table tb_int_inst_0407 {
        actions = {
            int_set_header_0407_i0;
            int_set_header_0407_i1;
            int_set_header_0407_i2;
            int_set_header_0407_i3;
            int_set_header_0407_i4;
            int_set_header_0407_i5;
            int_set_header_0407_i6;
            int_set_header_0407_i7;
            int_set_header_0407_i8;
            int_set_header_0407_i9;
            int_set_header_0407_i10;
            int_set_header_0407_i11;
            int_set_header_0407_i12;
            int_set_header_0407_i13;
            int_set_header_0407_i14;
            int_set_header_0407_i15;
        }
        key = {
            hdr.int_header.instruction_mask: ternary;
        }
        const entries = {
            0x0000 &&& 0x0F00 : int_set_header_0407_i0();
            0x0100 &&& 0x0F00 : int_set_header_0407_i1();
            0x0200 &&& 0x0F00 : int_set_header_0407_i2();
            0x0300 &&& 0x0F00 : int_set_header_0407_i3();
            0x0400 &&& 0x0F00 : int_set_header_0407_i4();
            0x0500 &&& 0x0F00 : int_set_header_0407_i5();
            0x0600 &&& 0x0F00 : int_set_header_0407_i6();
            0x0700 &&& 0x0F00 : int_set_header_0407_i7();
            0x0800 &&& 0x0F00 : int_set_header_0407_i8();
            0x0900 &&& 0x0F00 : int_set_header_0407_i9();
            0x0A00 &&& 0x0F00 : int_set_header_0407_i10();
            0x0B00 &&& 0x0F00 : int_set_header_0407_i11();
            0x0C00 &&& 0x0F00 : int_set_header_0407_i12();
            0x0D00 &&& 0x0F00 : int_set_header_0407_i13();
            0x0E00 &&& 0x0F00 : int_set_header_0407_i14();
            0x0F00 &&& 0x0F00 : int_set_header_0407_i15();
        }
    }

    action int_hop_cnt_increment() {
        hdr.int_header.remaining_hop_cnt = hdr.int_header.remaining_hop_cnt - 1;
    }
    action int_hop_exceeded() {
        hdr.int_header.e = 1w1;
    }

    action int_update_ipv4_ac() {
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + (bit<16>)meta.int_metadata.insert_byte_cnt;
    }
    action int_update_shim_ac() {
        hdr.int_shim.len = hdr.int_shim.len + (bit<8>)meta.int_metadata.int_hdr_word_len;
    }
    action int_update_udp_ac() {
        hdr.udp.len = hdr.udp.len + (bit<16>)meta.int_metadata.insert_byte_cnt;
    }

    apply {    
        // INT transit must process only INT packets
        if (!hdr.int_header.isValid())
            return;

        // Check if INT transit can add a new INT node metadata
        if (hdr.int_header.remaining_hop_cnt == 0 || hdr.int_header.e == 1) {
            int_hop_exceeded();
            return;
        }

        int_hop_cnt_increment();

        // Add INT node metadata headers based on INT instruction_mask
        tb_int_transit.apply();
        tb_int_inst_0003.apply();
        tb_int_inst_0407.apply();

        // Update length fields in IPv4, UDP, and INT
        int_update_ipv4_ac();

        if (hdr.udp.isValid())
            int_update_udp_ac();

        if (hdr.int_shim.isValid()) 
            int_update_shim_ac();
    }
}

/*************************************************************************
*******************  I N G R E S S   F O R W A R D  **********************
*************************************************************************/

control PortForward(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    action send(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    table tb_port_forward {
        actions = {
            send;
        }
        key = {
            standard_metadata.egress_port : exact;
        }
        size = 31;
    }

    apply {
        tb_port_forward.apply();
    }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t ig_intr_md) {
	apply {
		if (!hdr.udp.isValid() && !hdr.tcp.isValid())
			exit;

		// in case of INT source port add main INT headers
		Int_source.apply(hdr, meta, ig_intr_md);

		// perform minimalistic L1 or L2 frame forwarding
		// set egress_port for the frame
		Forward.apply(hdr, meta, ig_intr_md);
		PortForward.apply(hdr, meta, ig_intr_md);

		// in case of sink node make packet clone I2E in order to create INT report
		// which will be send to INT reporting port
		Int_sink_config.apply(hdr, meta, ig_intr_md);
	}
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t eg_intr_md) {
	apply {
		Int_transit.apply(hdr, meta, eg_intr_md);
		// in case of the INT sink port remove INT headers
		// when frame duplicate on the INT report port then reformat frame into INT report frame
		Int_sink.apply(hdr, meta, eg_intr_md);
	}
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.dscp,
                hdr.ipv4.ecn,
                hdr.ipv4.totalLen,
                hdr.ipv4.id,
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
        
        update_checksum(
            hdr.report_ipv4.isValid(),
            {
                hdr.report_ipv4.version,
                hdr.report_ipv4.ihl,
                hdr.report_ipv4.dscp,
                hdr.report_ipv4.ecn,
                hdr.report_ipv4.totalLen,
                hdr.report_ipv4.id,
                hdr.report_ipv4.flags,
                hdr.report_ipv4.fragOffset,
                hdr.report_ipv4.ttl,
                hdr.report_ipv4.protocol,
                hdr.report_ipv4.srcAddr,
                hdr.report_ipv4.dstAddr
            },
            hdr.report_ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
        
        update_checksum_with_payload(
            hdr.udp.isValid(), 
            {  hdr.ipv4.srcAddr, 
                hdr.ipv4.dstAddr, 
                8w0, 
                hdr.ipv4.protocol, 
                hdr.udp.len, 
                hdr.udp.srcPort, 
                hdr.udp.dstPort, 
                hdr.udp.len 
            }, 
            hdr.udp.csum, 
            HashAlgorithm.csum16
        ); 

        update_checksum_with_payload(
            hdr.udp.isValid() && hdr.int_header.isValid() , 
            {  hdr.ipv4.srcAddr, 
                hdr.ipv4.dstAddr, 
                8w0, 
                hdr.ipv4.protocol, 
                hdr.udp.len, 
                hdr.udp.srcPort, 
                hdr.udp.dstPort, 
                hdr.udp.len,
                hdr.int_shim,
                hdr.int_header,
                hdr.int_switch_id,
                hdr.int_port_ids,
                hdr.int_q_occupancy,
                hdr.int_level2_port_ids,
                hdr.int_ingress_tstamp,
                hdr.int_egress_tstamp,
                hdr.int_egress_port_tx_util,
                hdr.int_hop_latency
            }, 
            hdr.udp.csum, 
            HashAlgorithm.csum16
        );
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        // raport headers
        packet.emit(hdr.report_ethernet);
        packet.emit(hdr.report_ipv4);
        packet.emit(hdr.report_udp);
        packet.emit(hdr.report_fixed_header);
        
        // original headers
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
        
        // INT headers
        packet.emit(hdr.int_shim);
        packet.emit(hdr.int_header);
        
        // local INT node metadata
        packet.emit(hdr.int_switch_id);     //bit 1
        packet.emit(hdr.int_port_ids);       //bit 2
        packet.emit(hdr.int_hop_latency);   //bit 3
        packet.emit(hdr.int_q_occupancy);  // bit 4
        packet.emit(hdr.int_ingress_tstamp);  // bit 5
        packet.emit(hdr.int_egress_tstamp);   // bit 6
        packet.emit(hdr.int_level2_port_ids);   // bit 7
        packet.emit(hdr.int_egress_port_tx_util);  // bit 8
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
