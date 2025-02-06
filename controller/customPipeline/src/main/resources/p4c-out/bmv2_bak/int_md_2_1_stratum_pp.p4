#include <core.p4>
#include <v1model.p4>

const bit<6> HW_ID = 1;
const bit<32> PACKET_ADVANCE = 40;
const bit<16> TYPE_IPV4 = 0x800;
const bit<8> IP_PROTO_UDP = 0x11;
const bit<8> IP_PROTO_TCP = 0x6;
const bit<16> INT_PORT = 5000;
const bit<16> SHIM_LEN = 84;
const bit<16> INT_DATA_LEN = 120;
const bit<6> DSCP_INT = 0x17;
const bit<6> DSCP_MASK = 0x3f;
const bit<8> HOP_1 = 0x1a;
const bit<8> HOP_2 = 0xc;
typedef bit<48> mac_t;
typedef bit<32> ip_address_t;
typedef bit<16> l4_port_t;
typedef bit<9> port_t;
typedef bit<16> next_hop_id_t;
const bit<8> INT_HEADER_LEN_WORD = 3;
const bit<8> REPORT_HDR_TTL = 64;
const port_t CPU_PORT = 255;
const bit<3> NPROTO_ETHERNET = 0;
const bit<3> NPROTO_TELEMETRY_DROP_HEADER = 1;
const bit<3> NPROTO_TELEMETRY_SWITCH_LOCAL_HEADER = 2;
const bit<5> IPV4_OPTION_INT = 31;
typedef bit<3> mirror_type_t;
typedef bit<8> pkt_type_t;
const bit<32> REPORT_MIRROR_SESSION_ID = 500;
const pkt_type_t PKT_TYPE_MIRROR = 2;
typedef bit<32> switch_id_t;
typedef bit<48> timestamp_t;
typedef bit<6> output_port_t;
typedef bit<8> MeterColor;
const MeterColor MeterColor_GREEN = 8w0;
const MeterColor MeterColor_YELLOW = 8w1;
const MeterColor MeterColor_RED = 8w2;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_NORMAL = 0;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE = 1;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE = 2;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_COALESCED = 3;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_RECIRC = 4;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_REPLICATION = 5;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_RESUBMIT = 6;
@controller_header("packet_in") header packet_in_header_t {
    bit<9> ingress_port;
    bit<7> _padding;
}

@controller_header("packet_out") header packet_out_header_t {
    bit<9> egress_port;
    bit<7> _padding;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

const bit<8> ETH_HEADER_LEN = 14;
header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<6>  dscp;
    bit<2>  ecn;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

const bit<8> IPV4_MIN_HEAD_LEN = 20;
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

const bit<8> UDP_HEADER_LEN = 8;
header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

const bit<8> TCP_HEADER_LEN = 20;
header intl4_shim_t {
    bit<4>  int_type;
    bit<2>  npt;
    bit<2>  rsvd;
    bit<8>  len;
    bit<6>  udp_ip_dscp;
    bit<10> udp_ip;
}

const bit<16> INT_SHIM_HEADER_SIZE = 4;
header int_header_t {
    bit<4>  ver;
    bit<1>  d;
    bit<1>  e;
    bit<1>  m;
    bit<12> rsvd1;
    bit<5>  hop_metadata_len;
    bit<8>  remaining_hop_cnt;
    bit<4>  instruction_mask_0003;
    bit<4>  instruction_mask_0407;
    bit<4>  instruction_mask_0811;
    bit<4>  instruction_mask_1215;
    bit<16> domain_specific_id;
    bit<16> ds_instruction;
    bit<16> ds_flags;
}

const bit<16> INT_HEADER_SIZE = 12;
const bit<16> INT_TOTAL_HEADER_SIZE = INT_HEADER_SIZE + INT_SHIM_HEADER_SIZE;
header int_switch_id_t {
    bit<32> switch_id;
}

header int_level1_port_ids_t {
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
    bit<32> ingress_port_id;
    bit<32> egress_port_id;
}

header int_egress_port_tx_util_t {
    bit<32> egress_port_tx_util;
}

header int_buffer_t {
    bit<8>  buffer_id;
    bit<24> buffer_occupancy;
}

header int_data_t {
    varbit<2560> data;
}

header report_group_header_t {
    bit<4>  ver;
    bit<6>  hw_id;
    bit<22> seq_no;
    bit<32> node_id;
}

const bit<8> REPORT_GROUP_HEADER_LEN = 8;
header report_individual_header_t {
    bit<4>  rep_type;
    bit<4>  in_type;
    bit<8>  len;
    bit<8>  rep_md_len;
    bit<1>  d;
    bit<1>  q;
    bit<1>  f;
    bit<1>  i;
    bit<4>  rsvd;
    bit<16> rep_md_bits;
    bit<16> domain_specific_id;
    bit<16> domain_specific_md_bits;
    bit<16> domain_specific_md_status;
}

const bit<8> REPORT_INDIVIDUAL_HEADER_LEN = 12;
header drop_report_header_t {
    bit<32> switch_id;
    bit<16> ingress_port_id;
    bit<16> egress_port_id;
    bit<8>  queue_id;
    bit<8>  drop_reason;
    bit<16> pad;
}

const bit<8> DROP_REPORT_HEADER_LEN = 12;
header local_report_header_t {
    bit<16> ingress_port_id;
    bit<16> egress_port_id;
    bit<8>  queue_id;
    bit<8>  pad;
    bit<64> ingress_global_tstamp;
}

const bit<8> LOCAL_REPORT_HEADER_LEN = 16;
header mirror_h {
    pkt_type_t pkt_type;
    bit<16>    ingress_port_id;
    bit<8>     queue_id;
    bit<64>    ingress_global_tstamp;
}

struct headers {
    packet_out_header_t        packet_out;
    packet_in_header_t         packet_in;
    ethernet_t                 ethernet;
    ipv4_t                     ipv4;
    udp_t                      udp;
    tcp_t                      tcp;
    ethernet_t                 report_ethernet;
    ipv4_t                     report_ipv4;
    udp_t                      report_udp;
    intl4_shim_t               intl4_shim;
    int_header_t               int_header;
    int_data_t                 int_data;
    int_switch_id_t            int_switch_id;
    int_level1_port_ids_t      int_level1_port_ids;
    int_hop_latency_t          int_hop_latency;
    int_q_occupancy_t          int_q_occupancy;
    int_ingress_tstamp_t       int_ingress_tstamp;
    int_egress_tstamp_t        int_egress_tstamp;
    int_level2_port_ids_t      int_level2_port_ids;
    int_egress_port_tx_util_t  int_egress_tx_util;
    report_group_header_t      report_group_header;
    report_individual_header_t report_individual_header;
    local_report_header_t      local_report_header;
    mirror_h                   mirror_header;
}

struct int_metadata_t {
    switch_id_t switch_id;
    bit<16>     new_bytes;
    bit<8>      new_words;
    bool        source;
    bool        sink;
    bool        transit;
    bit<8>      intl4_shim_len;
    bit<16>     int_shim_len;
}

struct local_metadata_t {
    bit<16>        l4_src_port;
    bit<16>        l4_dst_port;
    next_hop_id_t  next_hop_id;
    int_metadata_t int_meta;
    bool           mirror;
    pkt_type_t     pkt_type;
}

parser MyIngressParser(packet_in packet, out headers hdr, inout local_metadata_t local_metadata, inout standard_metadata_t standard_metadata) {
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
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_UDP: parse_udp;
            IP_PROTO_TCP: parse_tcp;
            default: accept;
        }
    }
    state parse_udp {
        packet.extract(hdr.udp);
        local_metadata.l4_src_port = hdr.udp.srcPort;
        local_metadata.l4_dst_port = hdr.udp.dstPort;
        transition select(hdr.ipv4.dscp) {
            DSCP_INT &&& DSCP_MASK: parse_intl4_shim;
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        local_metadata.l4_src_port = hdr.tcp.srcPort;
        local_metadata.l4_dst_port = hdr.tcp.dstPort;
        transition select(hdr.ipv4.dscp) {
            DSCP_INT &&& DSCP_MASK: parse_intl4_shim;
            default: accept;
        }
    }
    state parse_intl4_shim {
        packet.extract(hdr.intl4_shim);
        transition select(hdr.intl4_shim.int_type) {
            1: parse_int_header;
            default: accept;
        }
    }
    state parse_int_header {
        packet.extract(hdr.int_header);
        transition parse_int_data;
    }
    state parse_int_data {
        packet.extract(hdr.int_data, (bit<32>)(local_metadata.int_meta.intl4_shim_len - INT_HEADER_LEN_WORD) << 5);
        transition accept;
    }
}

control MyEgressDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.packet_in);
        packet.emit(hdr.report_ethernet);
        packet.emit(hdr.report_ipv4);
        packet.emit(hdr.report_udp);
        packet.emit(hdr.report_group_header);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
        packet.emit(hdr.intl4_shim);
        packet.emit(hdr.int_header);
        packet.emit(hdr.int_switch_id);
        packet.emit(hdr.int_level1_port_ids);
        packet.emit(hdr.int_hop_latency);
        packet.emit(hdr.int_q_occupancy);
        packet.emit(hdr.int_ingress_tstamp);
        packet.emit(hdr.int_egress_tstamp);
        packet.emit(hdr.int_level2_port_ids);
        packet.emit(hdr.int_egress_tx_util);
        packet.emit(hdr.int_data);
    }
}

control process_int_transit(inout headers hdr, inout local_metadata_t local_metadata, inout standard_metadata_t standard_metadata) {
    action init_metadata(switch_id_t switch_id) {
        local_metadata.int_meta.transit = true;
        local_metadata.int_meta.switch_id = switch_id;
    }
    action int_set_header_0() {
        hdr.int_switch_id.setValid();
        hdr.int_switch_id.switch_id = local_metadata.int_meta.switch_id;
    }
    action int_set_header_1() {
        hdr.int_level1_port_ids.setValid();
        hdr.int_level1_port_ids.ingress_port_id = (bit<16>)standard_metadata.ingress_port;
        hdr.int_level1_port_ids.egress_port_id = (bit<16>)standard_metadata.egress_port;
    }
    action int_set_header_2() {
        hdr.int_hop_latency.setValid();
        hdr.int_hop_latency.hop_latency = (bit<32>)standard_metadata.egress_global_timestamp - (bit<32>)standard_metadata.ingress_global_timestamp;
    }
    action int_set_header_3() {
        hdr.int_q_occupancy.setValid();
        hdr.int_q_occupancy.q_id = 0;
        hdr.int_q_occupancy.q_occupancy = (bit<24>)standard_metadata.deq_qdepth;
    }
    action int_set_header_4() {
        hdr.int_ingress_tstamp.setValid();
        hdr.int_ingress_tstamp.ingress_tstamp = (bit<64>)standard_metadata.ingress_global_timestamp;
    }
    action int_set_header_5() {
        hdr.int_egress_tstamp.setValid();
        hdr.int_egress_tstamp.egress_tstamp = (bit<64>)standard_metadata.egress_global_timestamp;
    }
    action int_set_header_6() {
        hdr.int_level2_port_ids.setValid();
        hdr.int_level2_port_ids.ingress_port_id = (bit<32>)standard_metadata.ingress_port;
        hdr.int_level2_port_ids.egress_port_id = (bit<32>)standard_metadata.egress_port;
    }
    action int_set_header_7() {
        hdr.int_egress_tx_util.setValid();
        hdr.int_egress_tx_util.egress_port_tx_util = 0;
    }
    action add_1() {
        local_metadata.int_meta.new_words = local_metadata.int_meta.new_words + 1;
        local_metadata.int_meta.new_bytes = local_metadata.int_meta.new_bytes + 4;
    }
    action add_2() {
        local_metadata.int_meta.new_words = local_metadata.int_meta.new_words + 2;
        local_metadata.int_meta.new_bytes = local_metadata.int_meta.new_bytes + 8;
    }
    action add_3() {
        local_metadata.int_meta.new_words = local_metadata.int_meta.new_words + 3;
        local_metadata.int_meta.new_bytes = local_metadata.int_meta.new_bytes + 12;
    }
    action add_4() {
        local_metadata.int_meta.new_words = local_metadata.int_meta.new_words + 4;
        local_metadata.int_meta.new_bytes = local_metadata.int_meta.new_bytes + 16;
    }
    action add_5() {
        local_metadata.int_meta.new_words = local_metadata.int_meta.new_words + 5;
        local_metadata.int_meta.new_bytes = local_metadata.int_meta.new_bytes + 20;
    }
    action int_set_header_0003_i0() {
    }
    action int_set_header_0003_i1() {
        int_set_header_3();
        add_1();
    }
    action int_set_header_0003_i2() {
        int_set_header_2();
        add_1();
    }
    action int_set_header_0003_i3() {
        int_set_header_3();
        int_set_header_2();
        add_2();
    }
    action int_set_header_0003_i4() {
        int_set_header_1();
        add_1();
    }
    action int_set_header_0003_i5() {
        int_set_header_3();
        int_set_header_1();
        add_2();
    }
    action int_set_header_0003_i6() {
        int_set_header_2();
        int_set_header_1();
        add_2();
    }
    action int_set_header_0003_i7() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_1();
        add_3();
    }
    action int_set_header_0003_i8() {
        int_set_header_0();
        add_1();
    }
    action int_set_header_0003_i9() {
        int_set_header_3();
        int_set_header_0();
        add_2();
    }
    action int_set_header_0003_i10() {
        int_set_header_2();
        int_set_header_0();
        add_2();
    }
    action int_set_header_0003_i11() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_0();
        add_3();
    }
    action int_set_header_0003_i12() {
        int_set_header_1();
        int_set_header_0();
        add_2();
    }
    action int_set_header_0003_i13() {
        int_set_header_3();
        int_set_header_1();
        int_set_header_0();
        add_3();
    }
    action int_set_header_0003_i14() {
        int_set_header_2();
        int_set_header_1();
        int_set_header_0();
        add_3();
    }
    action int_set_header_0003_i15() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_1();
        int_set_header_0();
        add_4();
    }
    action int_set_header_0407_i0() {
    }
    action int_set_header_0407_i1() {
        int_set_header_7();
        add_1();
    }
    action int_set_header_0407_i2() {
        int_set_header_6();
        add_2();
    }
    action int_set_header_0407_i3() {
        int_set_header_7();
        int_set_header_6();
        add_3();
    }
    action int_set_header_0407_i4() {
        int_set_header_5();
        add_1();
    }
    action int_set_header_0407_i5() {
        int_set_header_7();
        int_set_header_5();
        add_2();
    }
    action int_set_header_0407_i6() {
        int_set_header_6();
        int_set_header_5();
        add_3();
    }
    action int_set_header_0407_i7() {
        int_set_header_7();
        int_set_header_6();
        int_set_header_5();
        add_4();
    }
    action int_set_header_0407_i8() {
        int_set_header_4();
        add_1();
    }
    action int_set_header_0407_i9() {
        int_set_header_7();
        int_set_header_4();
        add_2();
    }
    action int_set_header_0407_i10() {
        int_set_header_6();
        int_set_header_4();
        add_3();
    }
    action int_set_header_0407_i11() {
        int_set_header_7();
        int_set_header_6();
        int_set_header_4();
        add_4();
    }
    action int_set_header_0407_i12() {
        int_set_header_5();
        int_set_header_4();
        add_2();
    }
    action int_set_header_0407_i13() {
        int_set_header_7();
        int_set_header_5();
        int_set_header_4();
        add_3();
    }
    action int_set_header_0407_i14() {
        int_set_header_6();
        int_set_header_5();
        int_set_header_4();
        add_4();
    }
    action int_set_header_0407_i15() {
        int_set_header_7();
        int_set_header_6();
        int_set_header_5();
        int_set_header_4();
        add_5();
    }
    table tb_int_insert {
        key = {
            hdr.int_header.isValid(): exact @name("int_is_valid") ;
        }
        actions = {
            init_metadata;
            NoAction;
        }
        default_action = NoAction();
        size = 1;
    }
    table tb_int_inst_0003 {
        key = {
            hdr.int_header.instruction_mask_0003: exact;
        }
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
        const entries = {
                        0x0 : int_set_header_0003_i0();

                        0x1 : int_set_header_0003_i1();

                        0x2 : int_set_header_0003_i2();

                        0x3 : int_set_header_0003_i3();

                        0x4 : int_set_header_0003_i4();

                        0x5 : int_set_header_0003_i5();

                        0x6 : int_set_header_0003_i6();

                        0x7 : int_set_header_0003_i7();

                        0x8 : int_set_header_0003_i8();

                        0x9 : int_set_header_0003_i9();

                        0xa : int_set_header_0003_i10();

                        0xb : int_set_header_0003_i11();

                        0xc : int_set_header_0003_i12();

                        0xd : int_set_header_0003_i13();

                        0xe : int_set_header_0003_i14();

                        0xf : int_set_header_0003_i15();

        }

        size = 16;
    }
    table tb_int_inst_0407 {
        key = {
            hdr.int_header.instruction_mask_0407: exact;
        }
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
        const entries = {
                        0x0 : int_set_header_0407_i0();

                        0x1 : int_set_header_0407_i1();

                        0x2 : int_set_header_0407_i2();

                        0x3 : int_set_header_0407_i3();

                        0x4 : int_set_header_0407_i4();

                        0x5 : int_set_header_0407_i5();

                        0x6 : int_set_header_0407_i6();

                        0x7 : int_set_header_0407_i7();

                        0x8 : int_set_header_0407_i8();

                        0x9 : int_set_header_0407_i9();

                        0xa : int_set_header_0407_i10();

                        0xb : int_set_header_0407_i11();

                        0xc : int_set_header_0407_i12();

                        0xd : int_set_header_0407_i13();

                        0xe : int_set_header_0407_i14();

                        0xf : int_set_header_0407_i15();

        }

        size = 16;
    }
    apply {
        tb_int_insert.apply();
        if (local_metadata.int_meta.transit == false) {
            return;
        }
        tb_int_inst_0003.apply();
        tb_int_inst_0407.apply();
        hdr.int_header.remaining_hop_cnt = hdr.int_header.remaining_hop_cnt - 1;
        if (hdr.ipv4.isValid()) {
            hdr.ipv4.totalLen = hdr.ipv4.totalLen + local_metadata.int_meta.new_bytes;
        }
        if (hdr.udp.isValid()) {
            hdr.udp.length_ = hdr.udp.length_ + local_metadata.int_meta.new_bytes;
        }
        if (hdr.intl4_shim.isValid()) {
            hdr.intl4_shim.len = hdr.intl4_shim.len + local_metadata.int_meta.new_words;
        }
    }
}

control process_int_source_sink(inout headers hdr, inout local_metadata_t local_metadata, inout standard_metadata_t standard_metadata) {
    direct_counter(CounterType.packets_and_bytes) counter_set_source;
    direct_counter(CounterType.packets_and_bytes) counter_set_sink;
    action int_set_source() {
        local_metadata.int_meta.source = true;
        counter_set_source.count();
    }
    action int_set_sink() {
        local_metadata.int_meta.sink = true;
        counter_set_sink.count();
    }
    table tb_set_source {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            int_set_source;
            NoAction();
        }
        counters = counter_set_source;
        const default_action = NoAction();
        size = 511;
    }
    table tb_set_sink {
        key = {
            standard_metadata.egress_spec: exact;
        }
        actions = {
            int_set_sink;
            NoAction();
        }
        counters = counter_set_sink;
        const default_action = NoAction();
        size = 511;
    }
    apply {
        tb_set_source.apply();
        tb_set_sink.apply();
    }
}

control process_int_source(inout headers hdr, inout local_metadata_t local_metadata, inout standard_metadata_t standard_metadata) {
    direct_counter(CounterType.packets_and_bytes) counter_int_source;
    action int_source(bit<5> hop_metadata_len, bit<8> remaining_hop_cnt, bit<4> ins_mask0003, bit<4> ins_mask0407) {
        hdr.intl4_shim.setValid();
        hdr.intl4_shim.int_type = 1;
        hdr.intl4_shim.npt = 0;
        hdr.intl4_shim.len = INT_HEADER_LEN_WORD;
        hdr.intl4_shim.udp_ip_dscp = hdr.ipv4.dscp;
        hdr.intl4_shim.udp_ip = 0;
        hdr.int_header.setValid();
        hdr.int_header.ver = 2;
        hdr.int_header.d = 0;
        hdr.int_header.e = 0;
        hdr.int_header.m = 0;
        hdr.int_header.rsvd1 = 0;
        hdr.int_header.hop_metadata_len = hop_metadata_len;
        hdr.int_header.remaining_hop_cnt = remaining_hop_cnt;
        hdr.int_header.instruction_mask_0003 = ins_mask0003;
        hdr.int_header.instruction_mask_0407 = ins_mask0407;
        hdr.int_header.instruction_mask_0811 = 0;
        hdr.int_header.instruction_mask_1215 = 0;
        hdr.int_header.domain_specific_id = 0;
        hdr.int_header.ds_instruction = 0;
        hdr.int_header.ds_flags = 0;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + INT_TOTAL_HEADER_SIZE;
        hdr.udp.length_ = hdr.udp.length_ + INT_TOTAL_HEADER_SIZE;
        hdr.ipv4.dscp = DSCP_INT;
        counter_int_source.count();
    }
    table tb_int_source {
        key = {
            hdr.ipv4.srcAddr          : ternary;
            hdr.ipv4.dstAddr          : ternary;
            hdr.ipv4.protocol         : ternary;
            local_metadata.l4_src_port: ternary;
            local_metadata.l4_dst_port: ternary;
        }
        actions = {
            int_source;
            NoAction;
        }
        counters = counter_int_source;
        const default_action = NoAction();
    }
    apply {
        tb_int_source.apply();
    }
}

control process_int_sink(inout headers hdr, inout local_metadata_t local_metadata) {
    action restore_header() {
        hdr.ipv4.dscp = hdr.intl4_shim.udp_ip_dscp;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - SHIM_LEN;
        hdr.udp.length_ = hdr.udp.length_ - SHIM_LEN;
    }
    action int_sink() {
        hdr.int_header.setInvalid();
        hdr.int_data.setInvalid();
        hdr.intl4_shim.setInvalid();
    }
    apply {
        restore_header();
        int_sink();
    }
}

control process_int_report(inout headers hdr, inout local_metadata_t local_metadata, inout standard_metadata_t standard_metadata) {
    action do_report_encapsulation(mac_t src_mac, mac_t mon_mac, ip_address_t src_ip, ip_address_t mon_ip, l4_port_t mon_port) {
        hdr.report_ethernet.setValid();
        hdr.report_ethernet.dstAddr = mon_mac;
        hdr.report_ethernet.srcAddr = src_mac;
        hdr.report_ethernet.etherType = 0x800;
        hdr.report_ipv4.setValid();
        hdr.report_ipv4.version = 4w4;
        hdr.report_ipv4.ihl = 4w5;
        hdr.report_ipv4.dscp = 6w0;
        hdr.report_ipv4.ecn = 2w0;
        hdr.report_ipv4.totalLen = (bit<16>)IPV4_MIN_HEAD_LEN + (bit<16>)UDP_HEADER_LEN + (bit<16>)REPORT_GROUP_HEADER_LEN + (bit<16>)ETH_HEADER_LEN + (bit<16>)IPV4_MIN_HEAD_LEN + (bit<16>)UDP_HEADER_LEN + INT_DATA_LEN;
        hdr.report_ipv4.identification = 0;
        hdr.report_ipv4.flags = 0;
        hdr.report_ipv4.fragOffset = 0;
        hdr.report_ipv4.ttl = REPORT_HDR_TTL;
        hdr.report_ipv4.protocol = IP_PROTO_UDP;
        hdr.report_ipv4.srcAddr = src_ip;
        hdr.report_ipv4.dstAddr = mon_ip;
        hdr.report_udp.setValid();
        hdr.report_udp.srcPort = 1234;
        hdr.report_udp.dstPort = mon_port;
        hdr.report_udp.length_ = (bit<16>)UDP_HEADER_LEN + (bit<16>)REPORT_GROUP_HEADER_LEN + (bit<16>)ETH_HEADER_LEN + (bit<16>)IPV4_MIN_HEAD_LEN + (bit<16>)UDP_HEADER_LEN + INT_DATA_LEN;
        hdr.report_group_header.setValid();
        hdr.report_group_header.ver = 2;
        hdr.report_group_header.hw_id = HW_ID;
        hdr.report_group_header.seq_no = 0;
        hdr.report_group_header.node_id = local_metadata.int_meta.switch_id;
        hdr.report_individual_header.setValid();
        hdr.report_individual_header.rep_type = 1;
        hdr.report_individual_header.in_type = 4;
        hdr.report_individual_header.len = 0;
        hdr.report_individual_header.rep_md_len = 0;
        hdr.report_individual_header.d = 0;
        hdr.report_individual_header.q = 0;
        hdr.report_individual_header.f = 1;
        hdr.report_individual_header.i = 1;
        hdr.report_individual_header.rsvd = 0;
        hdr.report_individual_header.rep_md_bits = 0;
        hdr.report_individual_header.domain_specific_id = 0;
        hdr.report_individual_header.domain_specific_md_bits = 0;
        hdr.report_individual_header.domain_specific_md_status = 0;
    }
    table tb_generate_report {
        key = {
            hdr.int_header.isValid(): exact @name("int_is_valid") ;
        }
        actions = {
            do_report_encapsulation;
            NoAction();
        }
        default_action = NoAction();
    }
    apply {
        tb_generate_report.apply();
    }
}

control port_counters_ingress(inout headers hdr, inout standard_metadata_t standard_metadata) {
    counter(511, CounterType.packets) ingress_port_counter;
    apply {
        ingress_port_counter.count((bit<32>)standard_metadata.ingress_port);
    }
}

control port_counters_egress(inout headers hdr, inout standard_metadata_t standard_metadata) {
    counter(511, CounterType.packets) egress_port_counter;
    apply {
        egress_port_counter.count((bit<32>)standard_metadata.egress_port);
    }
}

control port_meters_ingress(inout headers hdr, inout standard_metadata_t standard_metadata) {
    meter(511, MeterType.bytes) ingress_port_meter;
    MeterColor ingress_color = MeterColor_GREEN;
    apply {
        ingress_port_meter.execute_meter<MeterColor>((bit<32>)standard_metadata.ingress_port, ingress_color);
        if (ingress_color == MeterColor_RED) {
            mark_to_drop(standard_metadata);
        }
    }
}

control port_meters_egress(inout headers hdr, inout standard_metadata_t standard_metadata) {
    meter(511, MeterType.bytes) egress_port_meter;
    MeterColor egress_color = MeterColor_GREEN;
    apply {
        egress_port_meter.execute_meter<MeterColor>((bit<32>)standard_metadata.egress_port, egress_color);
        if (egress_color == MeterColor_RED) {
            mark_to_drop(standard_metadata);
        }
    }
}

control packetio_ingress(inout headers hdr, inout standard_metadata_t standard_metadata) {
    apply {
        if (standard_metadata.ingress_port == CPU_PORT) {
            standard_metadata.egress_spec = hdr.packet_out.egress_port;
            hdr.packet_out.setInvalid();
            exit;
        }
    }
}

control packetio_egress(inout headers hdr, inout standard_metadata_t standard_metadata) {
    apply {
        if (standard_metadata.egress_port == CPU_PORT) {
            hdr.packet_in.setValid();
            hdr.packet_in.ingress_port = standard_metadata.ingress_port;
        }
    }
}

control table0_portforward_control(inout headers hdr, inout local_metadata_t local_metadata, inout standard_metadata_t standard_metadata) {
    direct_counter(CounterType.packets_and_bytes) table0_counter;
    action set_next_hop_id(next_hop_id_t next_hop_id) {
        local_metadata.next_hop_id = next_hop_id;
    }
    action send_to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
    }
    action set_egress_port(port_t port) {
        standard_metadata.egress_spec = port;
    }
    action drop() {
        mark_to_drop(standard_metadata);
    }
    table table0 {
        key = {
            standard_metadata.ingress_port: ternary;
            hdr.ethernet.srcAddr          : ternary;
            hdr.ethernet.dstAddr          : ternary;
            hdr.ethernet.etherType        : ternary;
            hdr.ipv4.srcAddr              : ternary;
            hdr.ipv4.dstAddr              : ternary;
            hdr.ipv4.protocol             : ternary;
            local_metadata.l4_src_port    : ternary;
            local_metadata.l4_dst_port    : ternary;
        }
        actions = {
            set_egress_port;
            send_to_cpu;
            set_next_hop_id;
            drop;
        }
        const default_action = drop();
        counters = table0_counter;
    }
    apply {
        table0.apply();
    }
}

control verify_checksum_control(inout headers hdr, inout local_metadata_t local_metadata) {
    apply {
    }
}

control compute_checksum_control(inout headers hdr, inout local_metadata_t local_metadata) {
    apply {
        update_checksum(hdr.ipv4.isValid(), { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.dscp, hdr.ipv4.ecn, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
        update_checksum(hdr.report_ipv4.isValid(), { hdr.report_ipv4.version, hdr.report_ipv4.ihl, hdr.report_ipv4.dscp, hdr.report_ipv4.ecn, hdr.report_ipv4.totalLen, hdr.report_ipv4.identification, hdr.report_ipv4.flags, hdr.report_ipv4.fragOffset, hdr.report_ipv4.ttl, hdr.report_ipv4.protocol, hdr.report_ipv4.srcAddr, hdr.report_ipv4.dstAddr }, hdr.report_ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

control MyIngress(inout headers hdr, inout local_metadata_t meta, inout standard_metadata_t standard_metadata) {
    apply {
        port_counters_ingress.apply(hdr, standard_metadata);
        port_meters_ingress.apply(hdr, standard_metadata);
        packetio_ingress.apply(hdr, standard_metadata);
        table0_portforward_control.apply(hdr, meta, standard_metadata);
        process_int_source_sink.apply(hdr, meta, standard_metadata);
        if (meta.int_meta.source == true) {
            process_int_source.apply(hdr, meta, standard_metadata);
        }
        if (meta.int_meta.sink == true && hdr.int_header.isValid()) {
            meta.pkt_type = PKT_TYPE_MIRROR;
            clone3(CloneType.I2E, REPORT_MIRROR_SESSION_ID, standard_metadata);
        }
    }
}

control MyEgress(inout headers hdr, inout local_metadata_t meta, inout standard_metadata_t standard_metadata) {
    apply {
        if (hdr.int_header.isValid()) {
            process_int_transit.apply(hdr, meta, standard_metadata);
            if (standard_metadata.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE) {
                process_int_report.apply(hdr, meta, standard_metadata);
            }
            if (meta.int_meta.sink == true && !(standard_metadata.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE)) {
                process_int_sink.apply(hdr, meta);
            }
        }
        port_counters_egress.apply(hdr, standard_metadata);
        port_meters_egress.apply(hdr, standard_metadata);
        packetio_egress.apply(hdr, standard_metadata);
        hdr.local_report_header.setInvalid();
    }
}

V1Switch(MyIngressParser(), verify_checksum_control(), MyIngress(), MyEgress(), compute_checksum_control(), MyEgressDeparser()) main;

