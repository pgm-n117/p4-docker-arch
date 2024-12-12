package customPipeline;

import org.onosproject.net.pi.model.*;


public class CustomConstants {
    //TODO: METERS AND COUNTERS IDS AND ACTIONS FOR TABLES.
    //Header fields for match in tables
    public static final PiMatchFieldId HDR_STANDARD_METADATA_INGRESS_PORT =
            PiMatchFieldId.of("standard_metadata.ingress_port");
    public static final PiMatchFieldId HDR_ETHERNET_SRC_ADDR =
            PiMatchFieldId.of("hdr.ethernet.src_addr");
    public static final PiMatchFieldId HDR_ETHERNET_DST_ADDR =
            PiMatchFieldId.of("hdr.ethernet.dst_addr");
    public static final PiMatchFieldId HDR_ETHERNET_ETHER_TYPE =
            PiMatchFieldId.of("hdr.ethernet.ether_type");
    public static final PiMatchFieldId HDR_IPV4_SRC_ADDR =
            PiMatchFieldId.of("hdr.ipv4.src_addr");
    public static final PiMatchFieldId HDR_IPV4_DST_ADDR =
            PiMatchFieldId.of("hdr.ipv4.dst_addr");
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
    public static final PiActionParamId PORT =
            PiActionParamId.of("port");



    //Packet metadata
    public static final PiPacketMetadataId INGRESS_PORT =
            PiPacketMetadataId.of("ingress_port");
    public static final PiPacketMetadataId EGRESS_PORT =
            PiPacketMetadataId.of("egress_port");
}
