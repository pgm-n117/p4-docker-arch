package org.mecp4.app;

import org.onlab.packet.IPv4;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.*;
import org.onosproject.net.behaviour.inbandtelemetry.IntDeviceConfig;
import org.onosproject.net.behaviour.inbandtelemetry.IntProgrammable;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.*;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.host.HostService;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.service.PiPipeconfService;
import org.onosproject.net.topology.TopologyService;

import java.text.CollationElementIterator;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import org.mecp4.app.Constants;

import static org.mecp4.app.Constants.DEFAULT_PRIORITY;

public class IntConfig {

    private DeviceService deviceService;
    private NetworkConfigService netcfgService;
    //private final NetworkConfigRegistry netcfgRegistry;
    //private final PiPipeconfService piPipeconfService;
    private HostService hostService;
    private TopologyService topologyService;
    private FlowRuleService flowRuleService;
    private ApplicationId appId;
    private Logger log;

    private ConcurrentMap<DeviceId, Boolean> IntSourceSinkPorts = new ConcurrentHashMap<>();
    private ConcurrentMap<DeviceId, FlowRule> CollectorFlowRules = new ConcurrentHashMap<>();


    /**
     * IntConfig class constructor. Starts Int report configuration at Source/Sink devices.
     * @param appId
     * @param deviceService
     * @param netcfgService
     * @param hostService
     * @param topologyService
     * @param flowRuleService
     */
    IntConfig(ApplicationId appId, Logger logger, DeviceService deviceService, NetworkConfigService netcfgService, HostService hostService, TopologyService topologyService, FlowRuleService flowRuleService ) {

        this.appId = appId;
        this.deviceService = deviceService;
        this.netcfgService = netcfgService;
        this.hostService = hostService;
        this.topologyService = topologyService;
        this.flowRuleService = flowRuleService;
        this.log = logger;

    }

    /**
    Tracks a new Source/Sink connect point.

    @param  dev     A Source/Sink device usually located at the edge of the topology.
    @param startup  Is this Source/Sink detected during application Activate() procedure?
                    True, else (i.e. an edge device event) False.
     */
    public void addIntSourceSinkPort(ConnectPoint dev, Boolean startup) {
        IntSourceSinkPorts.put(dev.deviceId(), true);
    }

    /**
     * Removes a previously registered Source/Sink connect point.
     * @param dev   A Source/Sink device to be removed
     */
    public void removeIntSourceSinkPort(ConnectPoint dev) {
        IntSourceSinkPorts.remove(dev.deviceId());
    }

    public Boolean isRegisteredIntSourceSink(ConnectPoint dev) {
        return IntSourceSinkPorts.containsKey(dev.deviceId());
    }


    public void IntEdgeNetCFGStartUp(ConnectPoint connectPoint, boolean startup){
        log.info("IntEdgeNetCFGStartUp - CONFIGURING INT/TELEMETRY REPORTS AT "+connectPoint);
        if (IntSourceSinkPorts.containsKey(connectPoint.deviceId())) {
            log.info("IntEdgeNetCFGStartUp: IntSourceSinkPorts already exists");
            return;
        }

        if (deviceService.getDevice(connectPoint.deviceId()).is(IntProgrammable.class)) {
            //Enable int source/sink devices

            IntProgrammable intdevice = deviceService.getDevice(connectPoint.deviceId()).as(IntProgrammable.class);
            intdevice.setSourcePort(connectPoint.port());
            intdevice.setSinkPort(connectPoint.port());

            P4Config intConfig = netcfgService.getConfig(deviceService.getDevice(connectPoint.deviceId()).id(), P4Config.class);

            IntDeviceConfig intReport = new IntDeviceConfig.Builder()
                    .withSinkMac(intConfig.sinkMacAddress())
                    .withCollectorNextHopMac(intConfig.collectorMacAddress())
                    .withSinkIp(intConfig.sinkIpAddress())
                    .withCollectorIp(intConfig.collectorIpAddress())
                    .withCollectorPort(intConfig.collectorPort())
                    .build();

            intdevice.setupIntConfig(intReport);

            IntSourceSinkPorts.put(connectPoint.deviceId(), startup);

            SetReportForwarding(connectPoint);

        }
    }

    private void SetReportForwarding(ConnectPoint connectPoint){

        P4Config intConfig = netcfgService.getConfig(deviceService.getDevice(connectPoint.deviceId()).id(), P4Config.class);

        //Configure report forwarding on sink devices
        Set<Host> availableCollector = hostService.getHostsByIp(intConfig.collectorIpAddress());

        if(availableCollector.isEmpty()) {
            log.info("INT Report Collector not available");
        }
        else{

            log.info(" >>> INT REPORT COLLECTOR ROUTE REQUESTED FROM "+connectPoint.deviceId()+": AVAIALBE ROUTES: "+CollectorFlowRules.keySet().toString());

            Host collectorHost = availableCollector.iterator().next();

            Set<Path> pathsToCollector = topologyService.getPaths(topologyService.currentTopology(), connectPoint.deviceId(), collectorHost.location().deviceId());

            if(!pathsToCollector.isEmpty()){

                Path path = pathsToCollector.iterator().next();

                path.links().forEach(link -> {
                    if (!CollectorFlowRules.containsKey(link.src().deviceId())) {
                        /*if (path.links().indexOf(link) == 0) {
                            ReportSourceFlowRule(intConfig, link.src().deviceId(), link.src().port());
                        } else {
                            ReportHopFlowRule(intConfig, link.src().deviceId(), link.src().port());
                        }*/
                        if (path.links().indexOf(link) != 0) {
                            ReportHopFlowRule(intConfig, link.src().deviceId(), link.src().port());
                        }
                    }
                });
                if (!CollectorFlowRules.containsKey(collectorHost.location().deviceId())) {
                    ReportLastHopFlowRule(intConfig, collectorHost.location().deviceId(), collectorHost.location().port());
                }
                /*path.links().forEach(link -> {

                    if (!CollectorFlowRules.containsKey(link.src().deviceId())){
                        PiActionParam reportOutPort = new PiActionParam(
                                IntConstants.PORT,
                                link.src().port().toLong()
                        );

                        PiAction reportAction = PiAction.builder()
                                .withId(IntConstants.SET_REPORT_FORWARDING_PORT)
                                .withParameter(reportOutPort)
                                .build();

                        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                                .piTableAction(reportAction)
                                .build();

                        FlowRule reportFlowrule = DefaultFlowRule.builder()
                                .withSelector(reportSelector)
                                .withTreatment(treatment)
                                .fromApp(appId)
                                .withPriority(FlowRule.MAX_PRIORITY)
                                .makePermanent()
                                .forDevice(link.src().deviceId())
                                .forTable(IntConstants.EGRESS_FORWARD_INT_REPORT)
                                .build();

                        FlowId reportFlowId = reportFlowrule.id();
                        flowRuleService.applyFlowRules(reportFlowrule);
                        log.info(" -- Report forwarding enabled at "+link.src().deviceId());

                        CollectorFlowRules.putIfAbsent(link.src().deviceId(), reportFlowrule);
                    }
                });

                if (!CollectorFlowRules.containsKey(collectorHost.location().deviceId())) {
                    //Last hop to collector
                    PiActionParam reportOutPort = new PiActionParam(
                            IntConstants.PORT,
                            collectorHost.location().port().toLong()
                    );

                    PiAction reportAction = PiAction.builder()
                            .withId(IntConstants.SET_REPORT_FORWARDING_PORT)
                            .withParameter(reportOutPort)
                            .build();

                    TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                            .piTableAction(reportAction)
                            .build();

                    FlowRule reportFlowrule = DefaultFlowRule.builder()
                            .withSelector(reportSelector)
                            .withTreatment(treatment)
                            .fromApp(appId)
                            .withPriority(FlowRule.MAX_PRIORITY)
                            .makePermanent()
                            .forDevice(collectorHost.location().deviceId())
                            .forTable(IntConstants.EGRESS_FORWARD_INT_REPORT)
                            .build();

                    FlowId reportFlowId = reportFlowrule.id();
                    flowRuleService.applyFlowRules(reportFlowrule);
                    log.info(" -- Report forwarding enabled at last hop "+collectorHost.location().deviceId());

                    CollectorFlowRules.putIfAbsent(collectorHost.location().deviceId(), reportFlowrule);

                }*/

            }
        }
    }

    private void RemoveReportForwarding(/*ConnectPoint connectPoint*/){
        try {
            CollectorFlowRules.forEach((dev, flow) -> CollectorFlowRules.remove(dev, flow));
            //flowRuleService.removeFlowRules(CollectorFlowRules.getOrDefault(connectPoint, null));
            //CollectorFlowRules.remove(connectPoint);
        }catch (Exception e){
            log.error("REMOVE REPORT FORWARDING FAILED: " + e.getMessage());
        }

    }

    public void IntEdgeNetCFGStop(ConnectPoint connectPoint){
        if (deviceService.getDevice(connectPoint.deviceId()).is(IntProgrammable.class)) {
            if(IntSourceSinkPorts.containsKey(connectPoint.deviceId())){
                IntProgrammable intdevice = deviceService.getDevice(connectPoint.deviceId()).as(IntProgrammable.class);
                intdevice.cleanup();

                IntSourceSinkPorts.remove(connectPoint.deviceId());
                RemoveReportForwarding(/*connectPoint*/);
            }

        }
    }


    //TODO: THIS MAY NOT BE NECESSARY IF CORRECTLY CONFIGURED ON INT REPORT CONFIG.
    private FlowRule ReportSourceFlowRule(P4Config intConfig, DeviceId deviceId, PortNumber port){
        PiCriterion reportCriterion = PiCriterion.builder()
                .matchExact(PiMatchFieldId.of("report_ipv4_proto"), IPv4.PROTOCOL_UDP)
                .matchExact(PiMatchFieldId.of("report_dst_ip"), intConfig.collectorIpAddress().toOctets())
                .matchExact(PiMatchFieldId.of("report_dst_port"), intConfig.collectorPort().toInt())
                .build();

        TrafficSelector reportSelector = DefaultTrafficSelector.builder()
                .matchPi(reportCriterion)
                .build();

        PiActionParam reportOutPort = new PiActionParam(
                IntConstants.PORT,
                port.toLong()
        );

        PiAction reportAction = PiAction.builder()
                .withId(IntConstants.SET_REPORT_FORWARDING_PORT)
                .withParameter(reportOutPort)
                .build();

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .piTableAction(reportAction)
                .build();

        FlowRule reportFlowrule = DefaultFlowRule.builder()
                .withSelector(reportSelector)
                .withTreatment(treatment)
                .fromApp(appId)
                .withPriority(FlowRule.MAX_PRIORITY)
                .makePermanent()
                .forDevice(deviceId)
                .forTable(IntConstants.EGRESS_FORWARD_INT_REPORT)
                .build();

        FlowId reportFlowId = reportFlowrule.id();
        flowRuleService.applyFlowRules(reportFlowrule);
        log.info(" -- Report forwarding enabled at source"+deviceId);

        CollectorFlowRules.putIfAbsent(deviceId, reportFlowrule);

        return reportFlowrule;
    }

    private FlowRule ReportHopFlowRule(P4Config intConfig, DeviceId deviceId, PortNumber port){
        TrafficSelector reportSelector = DefaultTrafficSelector.builder()
                .matchIPProtocol(IPv4.PROTOCOL_UDP)
                .matchIPDst(intConfig.collectorIpAddress().toIpPrefix())
                .matchUdpDst(intConfig.collectorPort())
                .build();

        TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder().setOutput(port);

        FlowRule reportFlowrule = DefaultFlowRule.builder()
                .withSelector(reportSelector)
                .withTreatment(treatment.build())
                .fromApp(appId)
                .withPriority(PacketPriority.MEDIUM.priorityValue())
                .makePermanent()
                .forDevice(deviceId)
                .forTable(0)
                .build();

        FlowId reportFlowId = reportFlowrule.id();
        flowRuleService.applyFlowRules(reportFlowrule);
        log.info(" -- Report forwarding enabled at "+deviceId);

        CollectorFlowRules.putIfAbsent(deviceId, reportFlowrule);

        return reportFlowrule;

    }

    private FlowRule ReportLastHopFlowRule(P4Config intConfig, DeviceId deviceId, PortNumber port){
        TrafficSelector reportSelector = DefaultTrafficSelector.builder()
                .matchIPProtocol(IPv4.PROTOCOL_UDP)
                .matchIPDst(intConfig.collectorIpAddress().toIpPrefix())
                .matchUdpDst(intConfig.collectorPort())
                .build();

        TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder().setOutput(port);

        FlowRule reportFlowrule = DefaultFlowRule.builder()
                .withSelector(reportSelector)
                .withTreatment(treatment.build())
                .fromApp(appId)
                .withPriority(PacketPriority.MEDIUM.priorityValue())
                .makePermanent()
                .forDevice(deviceId)
                .forTable(0)
                .build();

        FlowId reportFlowId = reportFlowrule.id();
        flowRuleService.applyFlowRules(reportFlowrule);
        log.info(" -- Report forwarding enabled at last hop "+deviceId);
        CollectorFlowRules.putIfAbsent(deviceId, reportFlowrule);

        return reportFlowrule;
    }

}
