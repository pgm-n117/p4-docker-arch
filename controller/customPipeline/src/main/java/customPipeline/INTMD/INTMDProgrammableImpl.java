package customPipeline.INTMD;

import com.google.common.collect.Sets;
import jdk.jfr.TransitionTo;
import org.onosproject.net.behaviour.inbandtelemetry.IntMetadataType;

import customPipeline.CustomConstants;
import org.glassfish.jersey.internal.inject.Custom;
import org.onlab.util.ImmutableByteSequence;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.behaviour.inbandtelemetry.IntDeviceConfig;
import org.onosproject.net.behaviour.inbandtelemetry.IntObjective;
import org.onosproject.net.behaviour.inbandtelemetry.IntProgrammable;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.driver.AbstractHandlerBehaviour;
import org.onosproject.net.edge.EdgePortService;
import org.onosproject.net.flow.*;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.IPCriterion;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.flow.criteria.TcpPortCriterion;
import org.onosproject.net.flow.criteria.UdpPortCriterion;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;



public class INTMDProgrammableImpl extends AbstractHandlerBehaviour implements IntProgrammable{




    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private EdgePortService edgePortService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private DeviceService deviceService;




    private final Logger log = LoggerFactory.getLogger(getClass());
    private static final String PIPELINE_APP_NAME =  "org.customPipeline.app";
    private ApplicationId appId;
    private DeviceId deviceId;
    private static final int DEFAULT_PRIORITY = 10000;

    private static final int MAXHOP = 64;  //although it is limited to the size of the int_data varbit header in the P4 file.
    private static final int PORTMASK = 0xffff;
    private static final int IDLE_TIMEOUT = 100;




    private static final Set<Criterion.Type> SUPPORTED_CRITERION = Sets.newHashSet(
            Criterion.Type.IPV4_DST, Criterion.Type.IPV4_SRC,
            Criterion.Type.UDP_SRC, Criterion.Type.UDP_DST,
            Criterion.Type.TCP_SRC, Criterion.Type.TCP_DST,
            Criterion.Type.IP_PROTO);

    private static final Set<PiTableId> TABLES_TO_CLEANUP = Sets.newHashSet(
            //CustomConstants.INGRESS_PROCESS_INT_SOURCE_TB_INT_SOURCE,
            CustomConstants.INGRESS_PROCESS_INT_SOURCE,

            //CustomConstants.INGRESS_PROCESS_INT_SOURCE_SINK_TB_SET_SOURCE,
            CustomConstants.INGRESS_SOURCESINK_SET_SOURCE,

            //CustomConstants.INGRESS_PROCESS_INT_SOURCE_SINK_TB_SET_SINK,
            CustomConstants.INGRESS_SOURCESINK_SET_SINK,

            //CustomConstants.EGRESS_PROCESS_INT_TRANSIT_TB_INT_INSERT,
            CustomConstants.EGRESS_PROCESS_TRANSIT_INT_TB_INSERT,

            //CustomConstants.EGRESS_PROCESS_INT_REPORT_TB_GENERATE_REPORT,
            CustomConstants.EGRESS_PROCESS_INT_REPORT_GENERATE_REPORT

    );




    private boolean setupBehaviour(){
        deviceId = this.data().deviceId();
        flowRuleService = handler().get(FlowRuleService.class);
        coreService = handler().get(CoreService.class);
        edgePortService = handler().get(EdgePortService.class);
        appId = coreService.getAppId(PIPELINE_APP_NAME);
        if (appId == null) {
            log.warn("Application ID is null. Cannot initialize behaviour.");
            return false;
        }
        return true;
    }




    @Override
    public boolean init() {
        if (!setupBehaviour()) {
            return false;
        }

        log.warn("Init INTMD programmable");
        //Inits every switch transit table procedures. The switch table executes init_metadata action, which inserts
        // switch ID and sets true the transit flag when the INT header is valid.




        //Insert traffic selector for packets with a valid int header
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchPi(PiCriterion.builder().matchExact(
                                CustomConstants.HDR_INT_IS_VALID, (byte) 0x01)
                        .build())
                .build();


        Object IntConstants;

        //This is the parameter that the init_metadata action needs, which is the switch_id
        PiActionParam transitIdParam = new PiActionParam(
                CustomConstants.SWITCH_ID, //p4 field name
                ImmutableByteSequence.copyFrom( //bytes of deviceid
                        Integer.parseInt(deviceId.toString().substring(
                                deviceId.toString().length() - 2)))); //deletes the first two characters of the ID, which are letters.



        PiAction.Builder transitActionBuilder = PiAction.builder();

        PiActionId transitActionId = CustomConstants.NO_ACTION;
        if(!edgePortService.getEdgePoints(deviceId).iterator().hasNext()){
            log.info("TRANSIT INIT: DEVICE "+ deviceId+" IS NOT AN EDGE DEVICE");
            transitActionId = CustomConstants.EGRESS_TRANSIT_INT_TRANSIT_INIT_META;

            transitActionBuilder.withParameter(transitIdParam)
                         .withId(transitActionId);

        }
        transitActionBuilder.withId(transitActionId);

        PiAction transitAction = transitActionBuilder.build();


        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .piTableAction(transitAction)
                .build();

        FlowRule transitFlowRule = DefaultFlowRule.builder()
                .withSelector(selector)
                .withTreatment(treatment)
                .fromApp(appId)
                .withPriority(DEFAULT_PRIORITY)
                .makePermanent()
                .forDevice(deviceId)
                .forTable(CustomConstants.EGRESS_PROCESS_TRANSIT_INT_TB_INSERT)
                .build();

        flowRuleService.applyFlowRules(transitFlowRule);

        return true;
    }

    @Override
    public boolean setSourcePort(PortNumber port) {
        if (!setupBehaviour()) {
            return false;
        }

        log.warn("Set Source Port INTMD programmable");

        // set source ports of each leaf switch, (connected to a host)
        PiCriterion ingressCriterion = PiCriterion.builder()
                .matchExact(CustomConstants.HDR_STANDARD_METADATA_INGRESS_PORT, port.toLong())
                .build();
        TrafficSelector srcSelector = DefaultTrafficSelector.builder()
                .matchPi(ingressCriterion)
                .build();
        PiAction setSourceAct = PiAction.builder()
                .withId(CustomConstants.INGRESS_SOURCESINK_INT_SET_SOURCE)
                .build();
        TrafficTreatment srcTreatment = DefaultTrafficTreatment.builder()
                .piTableAction(setSourceAct)
                .build();

        FlowRule srcFlowRule = DefaultFlowRule.builder()
                .withSelector(srcSelector)
                .withTreatment(srcTreatment)
                .fromApp(appId)
                .withPriority(DEFAULT_PRIORITY)
                .makePermanent()
                .forDevice(deviceId)
                .forTable(CustomConstants.INGRESS_SOURCESINK_SET_SOURCE)
                .build();
        flowRuleService.applyFlowRules(srcFlowRule);
        return true;
    }


    @Override
    public boolean setSinkPort(PortNumber port) {
        if (!setupBehaviour()) {
            return false;
        }

        log.warn("Set Sink Port INTMD programmable");


        // set source ports of each leaf switch, (connected to a host)
        PiCriterion egressCriterion = PiCriterion.builder()
                .matchExact(CustomConstants.HDR_STANDARD_METADATA_EGRESS_SPEC, port.toLong())
                .build();
        TrafficSelector sinkSelector = DefaultTrafficSelector.builder()
                .matchPi(egressCriterion)
                .build();
        PiAction setSinkAct = PiAction.builder()
                .withId(CustomConstants.INGRESS_SOURCESINK_INT_SET_SINK)
                .build();
        TrafficTreatment sinkTreatment = DefaultTrafficTreatment.builder()
                .piTableAction(setSinkAct)
                .build();
        FlowRule sinkFlowRule = DefaultFlowRule.builder()
                .withSelector(sinkSelector)
                .withTreatment(sinkTreatment)
                .fromApp(appId)
                .withPriority(DEFAULT_PRIORITY)
                .makePermanent()
                .forDevice(deviceId)
                .forTable(CustomConstants.INGRESS_SOURCESINK_SET_SINK)
                .build();
        flowRuleService.applyFlowRules(sinkFlowRule);

        //set default flowrule for sink header removal actions (a default table)

        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchPi(PiCriterion.builder().matchExact(
                                CustomConstants.HDR_INT_IS_VALID, (byte) 0x01)
                        .build())
                .build();

        PiAction sinkAction = PiAction.builder()
                .withId(CustomConstants.EGRESS_SINK_INT_SINK_REMOVE_META)
                .build();

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .piTableAction(sinkAction)
                .build();

        FlowRule transitFlowRule = DefaultFlowRule.builder()
                .withSelector(selector)
                .withTreatment(treatment)
                .fromApp(appId)
                .withPriority(DEFAULT_PRIORITY)
                .makePermanent()
                .forDevice(deviceId)
                .forTable(CustomConstants.EGRESS_PROCESS_INT_SINK)
                .build();

        flowRuleService.applyFlowRules(transitFlowRule);

        return true;
    }

    @Override
    public boolean addIntObjective(IntObjective obj) {
        log.warn("Add Objective INTMD programmable");

        return processIntObjective(obj, true);
    }



    @Override
    public boolean removeIntObjective(IntObjective obj) {
        log.warn("Remove Objective INTMD programmable");

        return processIntObjective(obj, false);
    }

    //Set up report related configuration
    @Override
    public boolean setupIntConfig(IntDeviceConfig config) {
        return setupIntReportInternal(config);
    }

    private boolean setupIntReportInternal(IntDeviceConfig cfg) {
        if (!setupBehaviour()) {
            return false;
        }

        FlowRule reportRule = buildReportEntry(cfg);
        if (reportRule != null) {
            flowRuleService.applyFlowRules(reportRule);
            log.info("Report entry {} has been added to {}", reportRule, this.data().deviceId());
            return true;
        } else {
            log.warn("Failed to add report entry on {}", this.data().deviceId());
            return false;
        }
    }


    private FlowRule buildReportEntry(IntDeviceConfig cfg) {
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchPi(PiCriterion.builder().matchExact(
                                CustomConstants.HDR_INT_IS_VALID, (byte) 0x01)
                        .build())
                .build();
        PiActionParam srcMacParam = new PiActionParam(
                CustomConstants.SRC_MAC,
                ImmutableByteSequence.copyFrom(cfg.sinkMac().toBytes()));
        PiActionParam nextHopMacParam = new PiActionParam(
                CustomConstants.MON_MAC,
                ImmutableByteSequence.copyFrom(cfg.collectorNextHopMac().toBytes()));
        PiActionParam srcIpParam = new PiActionParam(
                CustomConstants.SRC_IP,
                ImmutableByteSequence.copyFrom(cfg.sinkIp().toOctets()));
        PiActionParam monIpParam = new PiActionParam(
                CustomConstants.MON_IP,
                ImmutableByteSequence.copyFrom(cfg.collectorIp().toOctets()));
        PiActionParam monPortParam = new PiActionParam(
                CustomConstants.MON_PORT,
                ImmutableByteSequence.copyFrom(cfg.collectorPort().toInt()));
        PiAction reportAction = PiAction.builder()
                .withId(CustomConstants.EGRESS_SINK_INT_DO_REPORT)
                .withParameter(srcMacParam)
                .withParameter(nextHopMacParam)
                .withParameter(srcIpParam)
                .withParameter(monIpParam)
                .withParameter(monPortParam)
                .build();
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .piTableAction(reportAction)
                .build();

        return DefaultFlowRule.builder()
                .withSelector(selector)
                .withTreatment(treatment)
                .fromApp(appId)
                .withPriority(DEFAULT_PRIORITY)
                .makePermanent()
                .forDevice(this.data().deviceId())
                .forTable(CustomConstants.EGRESS_PROCESS_INT_REPORT_GENERATE_REPORT)
                .build();
    }


    @Override
    public void cleanup() {
        if (!setupBehaviour()) {
            return;
        }

        StreamSupport.stream(flowRuleService.getFlowEntries(
                        data().deviceId()).spliterator(), false)
                .filter(f -> f.table().type() == TableId.Type.PIPELINE_INDEPENDENT)
                .filter(f -> TABLES_TO_CLEANUP.contains((PiTableId) f.table()))
                .forEach(flowRuleService::removeFlowRules);
    }

    @Override
    public boolean supportsFunctionality(IntFunctionality functionality) {
        return false;
    }


    /**
     * Returns a subset of Criterion from given selector, which is unsupported
     * by this INT pipeline.
     *
     * @param selector a traffic selector
     * @return a subset of Criterion from given selector, unsupported by this
     * INT pipeline, empty if all criteria are supported.
     */
    private Set<Criterion> unsupportedSelectors(TrafficSelector selector) {
        return selector.criteria().stream()
                .filter(criterion -> !SUPPORTED_CRITERION.contains(criterion.type()))
                .collect(Collectors.toSet());
    }

    private boolean processIntObjective(IntObjective obj, boolean install) {

        log.warn("Processing Int Objective INTMD programmable");

        if (!setupBehaviour()) {
            return false;
        }
        if (install && !unsupportedSelectors(obj.selector()).isEmpty()) {
            log.warn("Device {} does not support criteria {} for INT.",
                    deviceId, unsupportedSelectors(obj.selector()));
            return false;
        }

        FlowRule flowRule = buildWatchlistEntry(obj);
        if (flowRule != null) {
            if (install) {
                flowRuleService.applyFlowRules(flowRule);
            } else {
                flowRuleService.removeFlowRules(flowRule);
            }
            log.debug("IntObjective {} has been {} {}",
                    obj, install ? "installed to" : "removed from", deviceId);
            return true;
        } else {
            log.warn("Failed to {} IntObjective {} on {}",
                    install ? "install" : "remove", obj, deviceId);
            return false;
        }
    }


    private FlowRule buildWatchlistEntry(IntObjective obj) {
        int instructionBitmap = buildInstructionBitmap(obj.metadataTypes());
        PiActionParam hopMetaLenParam = new PiActionParam(
                CustomConstants.HOP_METADATA_LEN,
                ImmutableByteSequence.copyFrom(Integer.bitCount(instructionBitmap)));
        PiActionParam hopCntParam = new PiActionParam(
                CustomConstants.REMAINING_HOP_CNT,
                ImmutableByteSequence.copyFrom(MAXHOP));
        PiActionParam inst0003Param = new PiActionParam(
                CustomConstants.INS_MASK0003,
                ImmutableByteSequence.copyFrom((instructionBitmap >> 12) & 0xF));
        PiActionParam inst0407Param = new PiActionParam(
                CustomConstants.INS_MASK0407,
                ImmutableByteSequence.copyFrom((instructionBitmap >> 8) & 0xF));

        PiAction intSourceAction = PiAction.builder()
                .withId(CustomConstants.INGRESS_SOURCE_INT_SOURCE_META)
                .withParameter(hopMetaLenParam)
                .withParameter(hopCntParam)
                .withParameter(inst0003Param)
                .withParameter(inst0407Param)
                .build();

        TrafficTreatment instTreatment = DefaultTrafficTreatment.builder()
                .piTableAction(intSourceAction)
                .build();

        TrafficSelector.Builder sBuilder = DefaultTrafficSelector.builder();
        for (Criterion criterion : obj.selector().criteria()) {
            switch (criterion.type()) {
                case IPV4_SRC:
                    sBuilder.matchIPSrc(((IPCriterion) criterion).ip());
                    break;
                case IPV4_DST:
                    sBuilder.matchIPDst(((IPCriterion) criterion).ip());
                    break;
                case TCP_SRC:
                    sBuilder.matchPi(
                            PiCriterion.builder().matchTernary(
                                            CustomConstants.HDR_LOCAL_METADATA_L4_SRC_PORT,
                                            ((TcpPortCriterion) criterion).tcpPort().toInt(), PORTMASK)
                                    .build());
                    break;
                case UDP_SRC:
                    sBuilder.matchPi(
                            PiCriterion.builder().matchTernary(
                                            CustomConstants.HDR_LOCAL_METADATA_L4_SRC_PORT,
                                            ((UdpPortCriterion) criterion).udpPort().toInt(), PORTMASK)
                                    .build());
                    break;
                case TCP_DST:
                    sBuilder.matchPi(
                            PiCriterion.builder().matchTernary(
                                            CustomConstants.HDR_LOCAL_METADATA_L4_DST_PORT,
                                            ((TcpPortCriterion) criterion).tcpPort().toInt(), PORTMASK)
                                    .build());
                    break;
                case UDP_DST:
                    sBuilder.matchPi(
                            PiCriterion.builder().matchTernary(
                                            CustomConstants.HDR_LOCAL_METADATA_L4_DST_PORT,
                                            ((UdpPortCriterion) criterion).udpPort().toInt(), PORTMASK)
                                    .build());
                    break;
                default:
                    log.warn("Unsupported criterion type: {}", criterion.type());
            }
        }

        return DefaultFlowRule.builder()
                .forDevice(this.data().deviceId())
                .withSelector(sBuilder.build())
                .withTreatment(instTreatment)
                .withPriority(DEFAULT_PRIORITY)
                .forTable(CustomConstants.INGRESS_PROCESS_INT_SOURCE)
                .fromApp(appId)
                .withIdleTimeout(IDLE_TIMEOUT)
                .build();
    }

    private int buildInstructionBitmap(Set<IntMetadataType> metadataTypes) {
        int instBitmap = 0;
        for (IntMetadataType metadataType : metadataTypes) {
            switch (metadataType) {
                case SWITCH_ID:
                    instBitmap |= (1 << 15);
                    break;
                case L1_PORT_ID:
                    instBitmap |= (1 << 14);
                    break;
                case HOP_LATENCY:
                    instBitmap |= (1 << 13);
                    break;
                case QUEUE_OCCUPANCY:
                    instBitmap |= (1 << 12);
                    break;
                case INGRESS_TIMESTAMP:
                    instBitmap |= (1 << 11);
                    break;
                case EGRESS_TIMESTAMP:
                    instBitmap |= (1 << 10);
                    break;
                case L2_PORT_ID:
                    instBitmap |= (1 << 9);
                    break;
                case EGRESS_TX_UTIL:
                    instBitmap |= (1 << 8);
                    break;
                default:
                    log.info("Unsupported metadata type {}. Ignoring...", metadataType);
                    break;
            }
        }
        return instBitmap;
    }



}
