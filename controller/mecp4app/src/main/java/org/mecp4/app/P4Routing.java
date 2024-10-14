/*
 * Copyright 2024-present Open Networking Foundation
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

package org.mecp4.app;



import com.fasterxml.jackson.databind.introspect.TypeResolutionContext;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.onlab.graph.ScalarWeight;
import org.onlab.graph.Weight;
import org.onlab.packet.*;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.net.*;
import org.onosproject.net.flow.*;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import org.onlab.packet.*;
import org.onlab.graph.Weight;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.host.HostEvent;
import org.onosproject.net.host.HostListener;
import org.onosproject.net.host.HostService;
import org.onosproject.net.edge.EdgePortService;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.topology.Topology;
import org.onosproject.net.topology.TopologyService;

import org.onosproject.net.packet.*;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.onosproject.net.pi.service.*;
import org.onosproject.net.pi.model.*;
import org.onosproject.net.pi.runtime.*;


import java.util.Optional;

import org.mecp4.app.BasicPipelineConstants.*;
import static java.nio.ByteBuffer.wrap;


/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true,
        service = {P4Routing.class},
        property = {
                "someProperty=Some Default String Value"
        })
public class P4Routing implements P4RoutingInterface{
    public final Logger log = LoggerFactory.getLogger(getClass());

    private String someProperty;

    //--------------------------------------------------------------------------
    // ONOS core services needed by this application.
    //--------------------------------------------------------------------------
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;



    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected EdgePortService edgePortService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PiPipeconfService piPipeconfService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PiTranslationService piTranslationService;


    //--------------------------------------------------------------------------
    //--------------------------------------------------------------------------

    private static final String APP_NAME = "org.mecp4.app";
    // Default priority used for flow rules installed by this app.
    private static final int FLOW_RULE_PRIORITY = 100;


    //Packet Processor
    private PacketProcessor mecP4packetProcessor;
    private ApplicationId appId;

    private ConcurrentMap<Link, Double> ActiveLinks = new ConcurrentHashMap<>(); //Links and their usage by active paths (times used by a flowrule) -> for load balancing
    private Object LinksMutex = new Object();
    private ConcurrentMap<FlowId, Link> ActiveFlowrules = new ConcurrentHashMap<>(); //Active flowrules (id) and the link its using
    private Object FlowRuleMutex = new Object();

    @Activate
    protected void activate() {
        try {
            log.info("MEC P4 APP -- ACTIVATING");

            cfgService.registerProperties(getClass());

            //Obtain app id
            appId = coreService.getAppId("org.mecp4.app");
            //Packet Processor
            mecP4packetProcessor = new appPacketProcessor();
            packetService.addProcessor(mecP4packetProcessor, PacketProcessor.director(3));

            //log.info(edgePortService.getEdgePoints().toString());

            edgePortService.getEdgePoints().forEach(connectPoint -> {
                log.info("EDGE DEVICE: " + connectPoint.deviceId());

                packetService.requestPackets(DefaultTrafficSelector.builder().matchEthType(Ethernet.TYPE_ARP).build(), PacketPriority.REACTIVE, appId, Optional.of(connectPoint.deviceId()));
                //IPV4
                packetService.requestPackets(DefaultTrafficSelector.builder().matchEthType(Ethernet.TYPE_IPV4).build(), PacketPriority.REACTIVE, appId, Optional.of(connectPoint.deviceId()));
            });

            log.info(APP_NAME + " Started");

        }catch (Exception ex) {
            log.info("------------ERROR EN ACTIVATE------------" + ex);
        }
    }

    @Deactivate
    protected void deactivate() {

        try {
            cfgService.unregisterProperties(getClass(), false);
            log.info("Stopped");

            //Remove everything initialized on activate
            edgePortService.getEdgePoints().forEach(connectPoint -> {
                //ARP
                packetService.cancelPackets(DefaultTrafficSelector.builder().matchEthType(Ethernet.TYPE_ARP).build(), PacketPriority.REACTIVE, appId, Optional.of(connectPoint.deviceId()));
                //IPV4
                packetService.cancelPackets(DefaultTrafficSelector.builder().matchEthType(Ethernet.TYPE_IPV4).build(), PacketPriority.REACTIVE, appId, Optional.of(connectPoint.deviceId()));
                //packetService.cancelPackets(DefaultTrafficSelector.builder().matchUdpDst(TpPort.tpPort(7777)).build(), PacketPriority.HIGH, appId, Optional.of(connectPoint.deviceId()));
            });

            flowRuleService.removeFlowRulesById(appId);
            packetService.removeProcessor(mecP4packetProcessor);
            log.info(APP_NAME + " Stopped");
        } catch (Exception ex) {
            log.info("------------ERROR DEACTIVATE------------" + ex);
        }
    }

    @Modified
    public void modified(ComponentContext context) {
        /**
         Dictionary<?, ?> properties = context != null ? context.getProperties() : new Properties();
         if (context != null) {
         someProperty = get(properties, "someProperty");
         }
         */

        log.info("Reconfigured");
    }

    private class appPacketProcessor implements PacketProcessor {


        @Override
        public void process(PacketContext context) {


            InboundPacket packet = context.inPacket();
            Ethernet ethPacket = packet.parsed();
            log.debug("PACKET HANDLED IN MEC P4 PACKET PROCESSOR: "+ethPacket.toString());


            //If we want to treat LLDP or ARP, do not return under this condition.
            if (context.isHandled()) {
                return;
            }

            switch (EthType.EtherType.lookup(ethPacket.getEtherType())) {
                case LLDP:
                    break;
                case ARP:
                    ARP arpPacket = (ARP) ethPacket.getPayload();
                    log.debug("ARP Received at " + packet.receivedFrom().toString() + "; ["+arpPacket.toString()+"]");

                    //Obtain Ip address of the source device
                    Ip4Address sourceIpAddress = Ip4Address.valueOf(arpPacket.getSenderProtocolAddress());
                    //Obtain Ip address of the target if it is an ARP REQUEST packet
                    Ip4Address targetIpAddress = Ip4Address.valueOf(arpPacket.getTargetProtocolAddress());

                    //ARP REQUEST
                    if (arpPacket.getOpCode() == ARP.OP_REQUEST) {

                        //Destination device connection point
                        ConnectPoint dstConnectionPoint;

                        //Get host from target ip address at ARP REQUEST packet
                        Set<Host> hosts = hostService.getHostsByIp(targetIpAddress);
                        //If hosts found on the network, send it the ARP REQUEST packet
                        if (!hosts.isEmpty()) {
                            for (Host host : hosts) {
                                if (host.mac() != null) { //ARP Request done over broadcast (FF:FF:FF:FF), nothing else to compare

                                    dstConnectionPoint = host.location();  //where is connected the host

                                    //Set up treatment: build it with output port on destination point
                                    TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder()
                                            .setOutput(dstConnectionPoint.port());

                                    //Set packet service: new OutBound packet, with destination point, treatment
                                    // and the received packet
                                    packetService.emit(new DefaultOutboundPacket(
                                            dstConnectionPoint.deviceId(),
                                            treatment.build(),
                                            context.inPacket().unparsed()));
                                    break;
                                }
                            }
                        }

                        //If no hosts found: dstMac will be null -> destination hosts could be inactive
                        break;
                    } else {
                        if (arpPacket.getOpCode() == ARP.OP_REPLY) {
                            //An ARP REQUEST has been received previously,
                            // so destination host of ARP REPLY (source of REQUEST) must be active

                            //Destination device connection point
                            ConnectPoint dstConnectionPoint;

                            //Get host from target ip address at ARP REPLAY packet
                            Set<Host> hosts = hostService.getHostsByIp(targetIpAddress);
                            if (!hosts.isEmpty()) {
                                for (Host host : hosts) {
                                    //If target host is found and equals eth packet destination MAC (it should)
                                    if (host.mac().equals(ethPacket.getDestinationMAC())) {

                                        dstConnectionPoint = host.location();

                                        //Set up treatment: build it with output por on destination point
                                        TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder()
                                                .setOutput(dstConnectionPoint.port());

                                        //Set packet service
                                        packetService.emit(new DefaultOutboundPacket(
                                                dstConnectionPoint.deviceId(),
                                                treatment.build(),
                                                context.inPacket().unparsed()));
                                        break;
                                    }
                                }
                            }
                            break;
                        }
                    }
                    break;
                case IPV4:
                    IPv4 ipv4Packet = (IPv4) ethPacket.getPayload();
                    log.debug("IPv4 Received at " + packet.receivedFrom().toString() + "; ["+ipv4Packet.toString()+"]");

                    //In case of error:
                    if (ipv4Packet == null) break;

                    //Get destination host ipv4 address
                    Ip4Address srcIpAddress = Ip4Address.valueOf(ipv4Packet.getSourceAddress());
                    Ip4Address dstIpAddress = Ip4Address.valueOf(ipv4Packet.getDestinationAddress());
                    int srcIpPort = 0;
                    int dstIpPort = 0;


                    //TCP or UDP
                    byte protocol = ipv4Packet.getProtocol();

                    //TCP TREATMENT
                    if (protocol == IPv4.PROTOCOL_TCP) {
                        TCP tcpHeader = (TCP) ipv4Packet.getPayload();
                        srcIpPort = tcpHeader.getSourcePort();
                        dstIpPort = tcpHeader.getDestinationPort();

                    }
                    //UDP TREATMENT
                    else if (protocol == IPv4.PROTOCOL_UDP) {
                        UDP udpHeader = (UDP) ipv4Packet.getPayload();

                        srcIpPort = udpHeader.getSourcePort();
                        dstIpPort = udpHeader.getDestinationPort();

                    }
                    //Actions for common TCP or UDP traffic
                    //Locate destination host and set a path:
                    for (Host host : hostService.getHostsByIp(dstIpAddress)) {
                        //if host up and found, set path flowrules on network devices

                        try {
                            setPath(context, host, protocol, srcIpAddress, srcIpPort,
                                    host.mac(), dstIpAddress, dstIpPort);

                        } catch (Exception e) {
                            log.error(e.toString());
                            e.printStackTrace();
                        }
                        //Packet to table: send packet to network device which came from. Will be redirected using the installed flowrule.
                        packetToTable(context);
                    }
                    break;
            }
            dropPacket(context);
        }




        //Set a new path on network device from packet source to destination
        private void setPath(PacketContext context, Host dstHost, byte protocol, /*MacAddress srcMac,*/
                             Ip4Address srcIp, int srcIpPort, MacAddress dstMac, Ip4Address dstIp, int dstIpPort) throws Exception {

            try {
                //Source and destination devices and ports
                DeviceId InputDeviceId = context.inPacket().receivedFrom().deviceId();
                PortNumber InputDevicePort = context.inPacket().receivedFrom().port();
                DeviceId OutputDeviceId = dstHost.location().deviceId();
                PortNumber OutputDevicePort = dstHost.location().port();

                //Source and destination hosts are under same network device
                if (InputDeviceId.equals(OutputDeviceId)) {
                    //log.info("      SOURCE AND DESTINATION UNDER SAME NETWORK DEVICE");
                    //Source and destination hosts are on different network device ports
                    if (!InputDevicePort.equals(OutputDevicePort)) {
                        //Install flowrule setting route on same device:
                        installPathFlowRule(dstHost.location(), protocol, srcIp, srcIpPort, dstIp, dstIpPort);
                        //Reverse path
                        installPathFlowRule(context.inPacket().receivedFrom(), protocol, dstIp, dstIpPort, srcIp, srcIpPort);

                    }
                    return;
                }
                log.info("      SOURCE AND DESTINATION ON DIFFERENT NETWORK DEVICES");
                //Source and destination hosts are under different network devices

                Set<Path> paths = topologyService.getPaths(topologyService.currentTopology(), InputDeviceId, OutputDeviceId);
                log.info("AVAILABLE PATHS: "+paths.size());


                Path path = selectBalancedPaths(paths, InputDevicePort);

                if (paths != null) {
                    path = paths.iterator().next();
                }


                if (path != null) {
                    log.info("FOUND PATHS FOR HOSTS: "+srcIp.toString()+" - "+dstIp.toString() + " PATH: "+path.links().toString());
                    //Install flowrules on each network device involved on the path. Installing for both initial and reverse paths.

                    path.links().forEach(l -> {
                        FlowRule flowrule = installPathFlowRule(l.src(), protocol, srcIp, srcIpPort, dstIp, dstIpPort);
                        if (flowrule != null) { //If path and flowrule installation success
                            registerFlow(dstIp, dstIpPort, flowrule, l);

                        }

                        //Reverse path
                        FlowRule reverseFlowrule = installPathFlowRule(l.dst(), protocol, dstIp, dstIpPort, srcIp, srcIpPort);
                        if (reverseFlowrule != null) { //If path and flowrule installation success
                            registerFlow(dstIp, dstIpPort, reverseFlowrule, l);
                        }
                    });

                    //Install flowrule on last device (redirect to host)
                    installPathFlowRule(dstHost.location(), OutputDevicePort, dstMac, protocol, srcIp, srcIpPort, dstIp, dstIpPort);

                    //Install flowrule on last device of reverse path
                    installPathFlowRule(context.inPacket().receivedFrom(), InputDevicePort, dstMac, protocol, dstIp, dstIpPort, srcIp, srcIpPort);


                } else {
                    //bad things
                    throw new Exception("Not found paths for hosts: " + srcIp.toString() + " - " + dstIp.toString());
                }

            }catch (Exception e){
                log.info("ERROR ON SET PATH "+ ExceptionUtils.getStackTrace(e));
            }
        }

        //Install path flowrule for specific device output -> for links from paths
        private FlowRule installPathFlowRule(ConnectPoint dstConnectionPoint, byte protocol, Ip4Address srcIp, int srcIpPort,
                                             Ip4Address dstIp, int dstIpPort) {


            PiCriterion.Builder piMatchCriterion = PiCriterion.builder();
            piMatchCriterion.
                    //match of exact ipv4 protocol
                    matchTernary(BasicPipelineConstants.HDR_HDR_ETHERNET_ETHER_TYPE, Ethernet.TYPE_IPV4, Ethernet.TYPE_IPV4).
                    //match of exact src and dst ip addresses
                    matchTernary(BasicPipelineConstants.HDR_HDR_IPV4_SRC_ADDR, srcIp.toOctets(), Ip4Address.valueOf("255.255.255.255").toOctets()).
                    matchTernary(BasicPipelineConstants.HDR_HDR_IPV4_DST_ADDR, dstIp.toOctets(), Ip4Address.valueOf("255.255.255.255").toOctets());




            if(protocol == IPv4.PROTOCOL_ICMP){
                piMatchCriterion.matchTernary(BasicPipelineConstants.HDR_HDR_IPV4_PROTOCOL, protocol, IPv4.PROTOCOL_ICMP);
            }else if (protocol == IPv4.PROTOCOL_TCP || protocol == IPv4.PROTOCOL_UDP){
                piMatchCriterion.
                        //match exact ports from UDP or TCP
                    matchTernary(BasicPipelineConstants.HDR_LOCAL_METADATA_L4_SRC_PORT, TpPort.tpPort(srcIpPort).toInt(), TpPort.MAX_PORT).
                    matchTernary(BasicPipelineConstants.HDR_LOCAL_METADATA_L4_DST_PORT, TpPort.tpPort(dstIpPort).toInt(), TpPort.MAX_PORT);
            }

            TrafficSelector.Builder piSelector = DefaultTrafficSelector.builder().
                    matchPi(piMatchCriterion.build());


            //Treatment rule
            log.info("Packet from "+srcIp.toString()+" goes through DEV "+dstConnectionPoint.toString()+", PORT "+dstConnectionPoint.port().toString());

            //TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder().setOutput(dstConnectionPoint.port());
            PiTableAction table0_drop = PiAction.builder().withId(PiActionId.of("ingress.table0_control.drop")).build();

            PiActionParamId PORT = PiActionParamId.of("port");
            PiTableAction table0_egress_port = PiAction.builder().withId(PiActionId.of("ingress.table0_control.set_egress_port")).withParameter(new PiActionParam(PORT, dstConnectionPoint.port().toLong())).build();

            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder().piTableAction(table0_egress_port);



            //FlowRule
            FlowRule.Builder flowrule = DefaultFlowRule.builder().
                    forTable(PiTableId.of("ingress.table0_control.table0")).
                    withSelector(piSelector.build()).
                    withTreatment(treatment.build()).
                    fromApp(appId).
                    forDevice(dstConnectionPoint.deviceId()).
                    withPriority(PacketPriority.MEDIUM.priorityValue()).withIdleTimeout(10);
                    //makeTemporary(10);


            //Apply rule - test this:
            FlowRule installFlowrule = flowrule.build();
            //Apply rule - test this:
            log.info("NEW FLOWRULE:" + installFlowrule.toString());
            flowRuleService.applyFlowRules(flowrule.build());
            return installFlowrule;
        }

        //Install path flowrule for specific device output port and destination mac -> for initial or destination devices
        private void installPathFlowRule(ConnectPoint dstConnectionPoint, PortNumber outputPort, MacAddress dstMac, byte protocol,
                                         Ip4Address srcIp, int srcIpPort, Ip4Address dstIp, int dstIpPort) {

            PiCriterion.Builder piMatchCriterion = PiCriterion.builder();
            piMatchCriterion.
                //match of exact ipv4 protocol
                matchTernary(BasicPipelineConstants.HDR_HDR_ETHERNET_ETHER_TYPE, Ethernet.TYPE_IPV4, Ethernet.TYPE_IPV4).
                //match of exact src and dst ip addresses
                matchTernary(BasicPipelineConstants.HDR_HDR_IPV4_SRC_ADDR, srcIp.toOctets(), Ip4Address.valueOf("255.255.255.255").toOctets()).
                matchTernary(BasicPipelineConstants.HDR_HDR_IPV4_DST_ADDR, dstIp.toOctets(), Ip4Address.valueOf("255.255.255.255").toOctets());




            if(protocol == IPv4.PROTOCOL_ICMP){
                piMatchCriterion.matchTernary(BasicPipelineConstants.HDR_HDR_IPV4_PROTOCOL, protocol, IPv4.PROTOCOL_ICMP);
            }else if (protocol == IPv4.PROTOCOL_TCP || protocol == IPv4.PROTOCOL_UDP){
                piMatchCriterion.
                    //match exact ports from UDP or TCP
                    matchTernary(BasicPipelineConstants.HDR_LOCAL_METADATA_L4_SRC_PORT, TpPort.tpPort(srcIpPort).toInt(), TpPort.MAX_PORT).
                    matchTernary(BasicPipelineConstants.HDR_LOCAL_METADATA_L4_DST_PORT, TpPort.tpPort(dstIpPort).toInt(), TpPort.MAX_PORT);
            }

            TrafficSelector.Builder piSelector = DefaultTrafficSelector.builder().
                    matchPi(piMatchCriterion.build());

            //Treatment rule
            log.info("Packet from "+srcIp.toString()+" goes through DEV "+dstConnectionPoint.toString()+", PORT "+outputPort.toString());
            //TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder().setOutput(outputPort).setEthDst(dstMac);
            PiTableAction table0_drop = PiAction.builder().withId(PiActionId.of("ingress.table0_control.drop")).build();

            PiActionParamId PORT = PiActionParamId.of("port");
            PiTableAction table0_egress_port = PiAction.builder().withId(PiActionId.of("ingress.table0_control.set_egress_port")).withParameter(new PiActionParam(PORT, outputPort.toLong())).build();

            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder().piTableAction(table0_egress_port);

            //FlowRule
            FlowRule.Builder flowrule = DefaultFlowRule.builder().
                    forTable(PiTableId.of("ingress.table0_control.table0")).
                    withSelector(piSelector.build()).
                    withTreatment(treatment.build()).
                    fromApp(appId).
                    forDevice(dstConnectionPoint.deviceId()).
                    withPriority(PacketPriority.MEDIUM.priorityValue()).withIdleTimeout(10);
                    //makeTemporary(10);


            //Apply rule - test this:
            FlowRule installFlowrule = flowrule.build();
            //Apply rule - test this:
            log.info("NEW FLOWRULE:" + installFlowrule.toString());
            flowRuleService.applyFlowRules(flowrule.build());
        }

        private Path selectLinkBalancedPaths(Set<Path> paths, PortNumber inputDevicePort) {
            Path defPath = null;
            Path auxPath = null;

            double pathScore = Double.MAX_VALUE;


            for (Path p : paths) {
                double auxScore = 0;
                auxPath = p;

                if (!p.src().port().equals(inputDevicePort)) {
                    //For each link in the path, if links are not used, or are the less used, we took that path (load balancing)
                    for (Link link : p.links()) {
                        //Build temp path with links weights
                        synchronized (LinksMutex) {
                            auxScore += ActiveLinks.getOrDefault(link, 0.0);
                        }
                    }

                    //If links are less used, path score will be lower
                    if (auxScore < pathScore) {
                        defPath = auxPath;
                        pathScore = auxScore;
                    }
                }
            }

            if (defPath == null) {
                return auxPath;
            } else {
                return defPath;
            }


        }

        private Path selectBalancedPaths(Set<Path> paths, PortNumber inputDevicePort) {
            Path defPath = null;
            Path auxPath = null;

            ScalarWeight pathScore = ScalarWeight.NON_VIABLE_WEIGHT;


            for (Path p : paths) {
                ScalarWeight auxScore = new ScalarWeight(0.0);
                auxPath = p;

                if (!p.src().port().equals(inputDevicePort)) {
                    //For each link in the path, if links are not used, or are the less used, we took that path (load balancing)
                    auxScore.merge(p.weight());

                    //If links are less used, path score will be lower
                    if (auxScore.compareTo(pathScore) < 0) {
                        defPath = auxPath;
                        pathScore = auxScore;
                    }
                }
            }

            if (defPath == null) {
                return auxPath;
            } else {
                return defPath;
            }


        }

        private void registerFlow(Ip4Address dstIpAddress, int dstPort, FlowRule flowrule, Link l) {
            synchronized (FlowRuleMutex) {
                ActiveFlowrules.putIfAbsent(flowrule.id(), l);
            }
            synchronized (LinksMutex) {
                ActiveLinks.merge(l, 1.0, Double::sum);
            }
        }


        private void dropPacket(PacketContext context) {
            context.treatmentBuilder().drop();
        }


        //Send the packet to the table which came from. The new flowrule should take care of it.
        //This functions causes problems with high number of flows. Maybe because it returns too many packets
        //to the table before the flowrules for each traffic path are installed. For the moment we will not use it

        private void packetToTable(PacketContext context) {
            //Wait for flowrule to activate (milliseconds)
            try {
                Thread.sleep(100);
            } catch (InterruptedException ignored) {
            }

            ConnectPoint receivedFrom = context.inPacket().receivedFrom();
            PiActionParamId PORT = PiActionParamId.of("port");
            PiTableAction table0_egress_port = PiAction.builder().withId(PiActionId.of("ingress.table0_control.set_egress_port")).withParameter(new PiActionParam(PORT, context.inPacket().receivedFrom().port().toLong())).build();

            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder().setOutput(receivedFrom.port());



            packetService.emit(new DefaultOutboundPacket(
                    context.inPacket().receivedFrom().deviceId(),
                    treatment.build(),
                    context.inPacket().unparsed()));
        }
    }

}

