package org.mecp4.app;

/*
* Basic constants to work with the basic P4 pipeline that comes with ONOS.
* The following constants are extracted from the following ONOS repo path:
* onos/pipelines/basic/src/main/java/org/onosproject/pipelines/basic/BasicConstants.java
 */


import org.onosproject.net.pi.model.*;

public class BasicPipelineConstants {

    // Header field IDs
    public static final PiMatchFieldId HDR_HDR_IPV4_PROTOCOL =
            PiMatchFieldId.of("hdr.ipv4.protocol");
    public static final PiMatchFieldId HDR_HDR_IPV4_SRC_ADDR =
            PiMatchFieldId.of("hdr.ipv4.src_addr");
    public static final PiMatchFieldId HDR_HDR_ETHERNET_ETHER_TYPE =
            PiMatchFieldId.of("hdr.ethernet.ether_type");
    public static final PiMatchFieldId HDR_HDR_ETHERNET_SRC_ADDR =
            PiMatchFieldId.of("hdr.ethernet.src_addr");
    public static final PiMatchFieldId HDR_LOCAL_METADATA_L4_DST_PORT =
            PiMatchFieldId.of("local_metadata.l4_dst_port");
    public static final PiMatchFieldId HDR_LOCAL_METADATA_L4_SRC_PORT =
            PiMatchFieldId.of("local_metadata.l4_src_port");
    public static final PiMatchFieldId HDR_STANDARD_METADATA_INGRESS_PORT =
            PiMatchFieldId.of("standard_metadata.ingress_port");
    public static final PiMatchFieldId HDR_HDR_IPV4_DST_ADDR =
            PiMatchFieldId.of("hdr.ipv4.dst_addr");
    public static final PiMatchFieldId HDR_LOCAL_METADATA_NEXT_HOP_ID =
            PiMatchFieldId.of("local_metadata.next_hop_id");
    public static final PiMatchFieldId HDR_HDR_ETHERNET_DST_ADDR =
            PiMatchFieldId.of("hdr.ethernet.dst_addr");
    // Table IDs
    public static final PiTableId INGRESS_WCMP_CONTROL_WCMP_TABLE =
            PiTableId.of("ingress.wcmp_control.wcmp_table");
    public static final PiTableId INGRESS_HOST_METER_CONTROL_HOST_METER_TABLE =
            PiTableId.of("ingress.host_meter_control.host_meter_table");
    public static final PiTableId INGRESS_TABLE0_CONTROL_TABLE0 =
            PiTableId.of("ingress.table0_control.table0");
    // Indirect Counter IDs
    public static final PiCounterId EGRESS_PORT_COUNTERS_EGRESS_EGRESS_PORT_COUNTER =
            PiCounterId.of("egress.port_counters_egress.egress_port_counter");
    public static final PiCounterId INGRESS_PORT_COUNTERS_INGRESS_INGRESS_PORT_COUNTER =
            PiCounterId.of("ingress.port_counters_ingress.ingress_port_counter");
    // Direct Counter IDs
    public static final PiCounterId INGRESS_WCMP_CONTROL_WCMP_TABLE_COUNTER =
            PiCounterId.of("ingress.wcmp_control.wcmp_table_counter");
    public static final PiCounterId INGRESS_TABLE0_CONTROL_TABLE0_COUNTER =
            PiCounterId.of("ingress.table0_control.table0_counter");
    // Action IDs
    public static final PiActionId INGRESS_TABLE0_CONTROL_SEND_TO_CPU =
            PiActionId.of("ingress.table0_control.send_to_cpu");
    public static final PiActionId NO_ACTION = PiActionId.of("NoAction");
    public static final PiActionId INGRESS_WCMP_CONTROL_SET_EGRESS_PORT =
            PiActionId.of("ingress.wcmp_control.set_egress_port");
    public static final PiActionId INGRESS_TABLE0_CONTROL_SET_NEXT_HOP_ID =
            PiActionId.of("ingress.table0_control.set_next_hop_id");
    public static final PiActionId INGRESS_TABLE0_CONTROL_SET_EGRESS_PORT =
            PiActionId.of("ingress.table0_control.set_egress_port");
    public static final PiActionId INGRESS_TABLE0_CONTROL_DROP =
            PiActionId.of("ingress.table0_control.drop");
    public static final PiActionId INGRESS_HOST_METER_CONTROL_READ_METER =
            PiActionId.of("ingress.host_meter_control.read_meter");
    // Action Param IDs
    public static final PiActionParamId PORT = PiActionParamId.of("port");
    public static final PiActionParamId NEXT_HOP_ID =
            PiActionParamId.of("next_hop_id");
    // Action Profile IDs
    public static final PiActionProfileId INGRESS_WCMP_CONTROL_WCMP_SELECTOR =
            PiActionProfileId.of("ingress.wcmp_control.wcmp_selector");
    // Packet Metadata IDs
    public static final PiPacketMetadataId INGRESS_PORT =
            PiPacketMetadataId.of("ingress_port");
    public static final PiPacketMetadataId EGRESS_PORT =
            PiPacketMetadataId.of("egress_port");
    // Meter IDs
    public static final PiMeterId INGRESS_PORT_METERS_INGRESS_INGRESS_PORT_METER =
            PiMeterId.of("ingress.port_meters_ingress.ingress_port_meter");
    public static final PiMeterId EGRESS_PORT_METERS_EGRESS_EGRESS_PORT_METER =
            PiMeterId.of("egress.port_meters_egress.egress_port_meter");





}
