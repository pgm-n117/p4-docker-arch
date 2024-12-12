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
const mirror_type_t MIRROR_TYPE_I2E = 1;
const pkt_type_t PKT_TYPE_MIRROR = 2;
typedef bit<32> switch_id_t;
typedef bit<48> timestamp_t;
typedef bit<6> output_port_t;
typedef bit<8> MeterColor;
const MeterColor MeterColor_GREEN = 8w0;
const MeterColor MeterColor_YELLOW = 8w1;
const MeterColor MeterColor_RED = 8w2;
@controller_header("packet_in") header packet_in_header_t {
    bit<9> ingress_port;
    bit<7> _padding;
}

@controller_header("packet_out") header packet_out_header_t {
    bit<9> egress_port;
    bit<7> _padding;
}

header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

const bit<8> ETH_HEADER_LEN = 14;
header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<6>  dscp;
    bit<2>  ecn;
    bit<16> len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

const bit<8> IPV4_MIN_HEAD_LEN = 20;
header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length_;
    bit<16> checksum;
}

const bit<8> UDP_HEADER_LEN = 8;
header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
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
    bit<704> data;
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
    int_header_t               int_header;
    intl4_shim_t               intl4_shim;
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
        transition select(hdr.ethernet.ether_type) {
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
        local_metadata.l4_src_port = hdr.udp.src_port;
        local_metadata.l4_dst_port = hdr.udp.dst_port;
        transition select(hdr.ipv4.dscp) {
            DSCP_INT &&& DSCP_MASK: parse_shim;
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        local_metadata.l4_src_port = hdr.tcp.src_port;
        local_metadata.l4_dst_port = hdr.tcp.dst_port;
        transition select(hdr.ipv4.dscp) {
            DSCP_INT &&& DSCP_MASK: parse_shim;
            default: accept;
        }
    }
    state parse_shim {
        packet.extract(hdr.intl4_shim);
        transition parse_int_hdr;
    }
    state parse_int_hdr {
        packet.extract(hdr.int_header);
        transition parse_int_data;
    }
    state parse_int_data {
        transition accept;
    }
}

control MyEgressDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.packet_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
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
            hdr.ethernet.src_addr         : ternary;
            hdr.ethernet.dst_addr         : ternary;
            hdr.ethernet.ether_type       : ternary;
            hdr.ipv4.src_addr             : ternary;
            hdr.ipv4.dst_addr             : ternary;
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
        update_checksum(hdr.ipv4.isValid(), { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.dscp, hdr.ipv4.ecn, hdr.ipv4.len, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.frag_offset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.src_addr, hdr.ipv4.dst_addr }, hdr.ipv4.hdr_checksum, HashAlgorithm.csum16);
        update_checksum(hdr.report_ipv4.isValid(), { hdr.report_ipv4.version, hdr.report_ipv4.ihl, hdr.report_ipv4.dscp, hdr.report_ipv4.ecn, hdr.report_ipv4.len, hdr.report_ipv4.identification, hdr.report_ipv4.flags, hdr.report_ipv4.frag_offset, hdr.report_ipv4.ttl, hdr.report_ipv4.protocol, hdr.report_ipv4.src_addr, hdr.report_ipv4.dst_addr }, hdr.report_ipv4.hdr_checksum, HashAlgorithm.csum16);
    }
}

control MyIngress(inout headers hdr, inout local_metadata_t meta, inout standard_metadata_t standard_metadata) {
    apply {
        port_counters_ingress.apply(hdr, standard_metadata);
        port_meters_ingress.apply(hdr, standard_metadata);
        packetio_ingress.apply(hdr, standard_metadata);
        table0_portforward_control.apply(hdr, meta, standard_metadata);
    }
}

control MyEgress(inout headers hdr, inout local_metadata_t meta, inout standard_metadata_t standard_metadata) {
    apply {
        port_counters_egress.apply(hdr, standard_metadata);
        port_meters_egress.apply(hdr, standard_metadata);
        packetio_egress.apply(hdr, standard_metadata);
    }
}

V1Switch(MyIngressParser(), verify_checksum_control(), MyIngress(), MyEgress(), compute_checksum_control(), MyEgressDeparser()) main;

