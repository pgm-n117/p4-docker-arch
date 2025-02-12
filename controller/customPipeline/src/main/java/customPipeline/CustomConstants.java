package customPipeline;

import org.onosproject.net.pi.model.*;


public class CustomConstants {
    //Header fields for match in tables
    public static final PiMatchFieldId HDR_STANDARD_METADATA_INGRESS_PORT =
            PiMatchFieldId.of("standard_metadata.ingress_port");

    public static final PiMatchFieldId HDR_STANDARD_METADATA_EGRESS_SPEC =
            PiMatchFieldId.of("standard_metadata.egress_spec");

    public static final PiMatchFieldId HDR_ETHERNET_SRC_ADDR =
            PiMatchFieldId.of("hdr.ethernet.srcAddr");
    public static final PiMatchFieldId HDR_ETHERNET_DST_ADDR =
            PiMatchFieldId.of("hdr.ethernet.dstAddr");
    public static final PiMatchFieldId HDR_ETHERNET_ETHER_TYPE =
            PiMatchFieldId.of("hdr.ethernet.etherType");
    public static final PiMatchFieldId HDR_IPV4_SRC_ADDR =
            PiMatchFieldId.of("hdr.ipv4.srcAddr");
    public static final PiMatchFieldId HDR_IPV4_DST_ADDR =
            PiMatchFieldId.of("hdr.ipv4.dstAddr");
    public static final PiMatchFieldId HDR_IPV4_PROTOCOL =
            PiMatchFieldId.of("hdr.ipv4.protocol");
    public static final PiMatchFieldId HDR_LOCAL_METADATA_L4_SRC_PORT =
            PiMatchFieldId.of("local_metadata.l4_src_port");
    public static final PiMatchFieldId HDR_LOCAL_METADATA_L4_DST_PORT =
            PiMatchFieldId.of("local_metadata.l4_dst_port");
    //we do not use next hop id?

    //Table IDs
    public static final PiTableId TABLE0 =
            PiTableId.of("MyIngress.table0_portforward_control.table0");

    //Table Actions IDs
    public static final PiActionId INGRESS_TABLE0_SET_EGRESS_PORT =
            PiActionId.of("MyIngress.table0_portforward_control.set_egress_port");
    public static final PiActionId INGRESS_TABLE0_SEND_TO_CPU =
            PiActionId.of("MyIngress.table0_portforward_control.send_to_cpu");
    public static final PiActionId INGRESS_TABLE0_SET_NEXT_HOP_ID =
            PiActionId.of("MyIngress.table0_portforward_control.set_next_hop_id");
    public static final PiActionId INGRESS_TABLE0_DROP =
            PiActionId.of("MyIngress.table0_portforward_control.drop");

    //This should correspond to default NoAction on v1model, no need to implement it on our code.
    public static final PiActionId NO_ACTION = PiActionId.of("NoAction");



    //INT-MD constants
    //Table IDs
    public static final PiTableId INGRESS_SOURCESINK_SET_SOURCE =
            PiTableId.of("MyIngress.process_int_source_sink.tb_set_source");
    public static final PiTableId INGRESS_SOURCESINK_SET_SINK =
            PiTableId.of("MyIngress.process_int_source_sink.tb_set_sink");
    public static final PiTableId INGRESS_PROCESS_INT_SOURCE =
            PiTableId.of("MyIngress.process_int_source.tb_int_source");

    public static final PiTableId EGRESS_PROCESS_INT_SINK =
            PiTableId.of("MyEgress.process_int_sink.tb_int_sink");

    public static final PiTableId EGRESS_PROCESS_TRANSIT_INT_TB_INSERT =
            PiTableId.of("MyEgress.process_int_transit.tb_int_insert");

    public static final PiTableId EGRESS_PROCESS_INT_REPORT_GENERATE_REPORT =
            PiTableId.of("MyEgress.process_int_report.tb_generate_report");

    //Table match fields
    public static final PiMatchFieldId HDR_INT_IS_VALID =
            PiMatchFieldId.of("int_is_valid");
    public static final PiMatchFieldId INT_IS_SINK =
            PiMatchFieldId.of("int_is_sink");

    //Action IDs
    public static final PiActionId INGRESS_SOURCESINK_INT_SET_SOURCE =
            PiActionId.of("MyIngress.process_int_source_sink.int_set_source");
    public static final PiActionId INGRESS_SOURCESINK_INT_SET_SINK =
            PiActionId.of("MyIngress.process_int_source_sink.int_set_sink");
    public static final PiActionId INGRESS_SOURCE_INT_SOURCE_META = //EQUIVALENT TO INT_SOURCE_DSCP ACTION IN ONOS CODE
            PiActionId.of("MyIngress.process_int_source.int_source");
    public static final PiActionId EGRESS_SINK_INT_SINK_REMOVE_META =
            PiActionId.of("MyEgress.process_int_sink.int_sink");
    public static final PiActionId EGRESS_TRANSIT_INT_TRANSIT_INIT_META =
            PiActionId.of("MyEgress.process_int_transit.init_metadata");
    public static final PiActionId EGRESS_SINK_INT_DO_REPORT =
            PiActionId.of("MyEgress.process_int_report.do_report_encapsulation");

    //Action Param IDs
    //action int_source(bit<5> hop_metadata_len, bit<8> remaining_hop_cnt, bit<4> ins_mask0003, bit<4> ins_mask0407)
    public static final PiActionParamId INS_MASK0407 =
            PiActionParamId.of("ins_mask0407");
    public static final PiActionParamId INS_MASK0003 =
            PiActionParamId.of("ins_mask0003");
    public static final PiActionParamId REMAINING_HOP_CNT =
            PiActionParamId.of("remaining_hop_cnt");
    public static final PiActionParamId HOP_METADATA_LEN =
            PiActionParamId.of("hop_metadata_len");

    //action set_next_hop_id(netx_hop_id_t next_hop_id) -> this action is on table 0, but it is not used right now
    public static final PiActionParamId NEXT_HOP_ID =
            PiActionParamId.of("next_hop_id");

    //action do_report_encapsulation(mac_t src_mac, mac_t mon_mac, ip_address_t src_ip,
    //                               ip_address_t mon_ip, l4_port_t mon_port)
    public static final PiActionParamId SRC_MAC = PiActionParamId.of("src_mac");
    public static final PiActionParamId MON_MAC = PiActionParamId.of("mon_mac");
    public static final PiActionParamId SRC_IP = PiActionParamId.of("src_ip");
    public static final PiActionParamId MON_IP = PiActionParamId.of("mon_ip");
    public static final PiActionParamId MON_PORT = PiActionParamId.of("mon_port");

    //action init_metadata(switch_id_t switch_id)
    public static final PiActionParamId SWITCH_ID = PiActionParamId.of("switch_id");


    //Table Action Parameters
    //This is the PORT parameter name for the set_egress_port action, which can be extracted from the compiled json, i.e:
    /*{
    *    "name" : "MyIngress.table0_portforward_control.set_egress_port",
    *        "id" : 2,
    *        "runtime_data" : [
    *    {
    *        "name" : "port",
    *            "bitwidth" : 9
    *    }
    *  ],
    * "primitives" : [
    * ...
    *  ]
    * }
    */
    //action: "MyIngress.table0_portforward_control.set_egress_port"
    public static final PiActionParamId PORT =
            PiActionParamId.of("port");



    //Packet metadata
    public static final PiPacketMetadataId INGRESS_PORT =
            PiPacketMetadataId.of("ingress_port");
    public static final PiPacketMetadataId EGRESS_PORT =
            PiPacketMetadataId.of("egress_port");
}
