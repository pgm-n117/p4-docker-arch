package customPipeline.INTMD;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

import org.onlab.packet.DeserializationException;
import org.onlab.packet.Ethernet;
import org.onlab.util.ImmutableByteSequence;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;

import static org.onlab.util.ImmutableByteSequence.copyFrom;
import static org.onosproject.net.PortNumber.Logical.FLOOD;

import org.onosproject.net.device.DeviceService;
import org.onosproject.net.driver.AbstractHandlerBehaviour;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.instructions.Instruction;

import static java.util.stream.Collectors.toList;

import static org.onosproject.net.flow.instructions.Instruction.Type.OUTPUT;
import static org.onosproject.net.flow.instructions.Instructions.OutputInstruction;

import org.onosproject.net.packet.DefaultInboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiPipelineInterpreter;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static customPipeline.CustomConstants.*;
import static java.lang.String.format;
import static org.onosproject.net.PortNumber.CONTROLLER;
import static org.onosproject.net.pi.model.PiPacketOperationType.PACKET_OUT;



public class INTMDInterpreterImpl extends AbstractHandlerBehaviour
        implements PiPipelineInterpreter{

    private final Logger log = LoggerFactory.getLogger(getClass());

    private static final int PORT_BITWIDTH = 9;

    private static final Map<Integer, PiTableId> TABLE_MAP =
            new ImmutableMap.Builder<Integer, PiTableId>()
                    .put(0, TABLE0)
                    .build();
    private static final Map<Criterion.Type, PiMatchFieldId> CRITERION_MAP =
            new ImmutableMap.Builder<Criterion.Type, PiMatchFieldId>()
                    .put(Criterion.Type.IN_PORT, HDR_STANDARD_METADATA_INGRESS_PORT)
                    .put(Criterion.Type.ETH_DST, HDR_ETHERNET_DST_ADDR)
                    .put(Criterion.Type.ETH_SRC, HDR_ETHERNET_SRC_ADDR)
                    .put(Criterion.Type.ETH_TYPE, HDR_ETHERNET_ETHER_TYPE)
                    .put(Criterion.Type.IP_PROTO, HDR_IPV4_PROTOCOL)
                    .put(Criterion.Type.IPV4_SRC, HDR_IPV4_SRC_ADDR)
                    .put(Criterion.Type.IPV4_DST, HDR_IPV4_DST_ADDR)
                    .put(Criterion.Type.TCP_SRC, HDR_LOCAL_METADATA_L4_SRC_PORT)
                    .put(Criterion.Type.TCP_DST, HDR_LOCAL_METADATA_L4_DST_PORT)
                    .put(Criterion.Type.UDP_SRC, HDR_LOCAL_METADATA_L4_SRC_PORT)
                    .put(Criterion.Type.UDP_DST, HDR_LOCAL_METADATA_L4_DST_PORT)
                    .build();


    @Override
    public Optional<PiMatchFieldId> mapCriterionType(Criterion.Type type) {
        log.debug("Mapping criterion type: "+type+" on INTMDInterpreter");
        return Optional.ofNullable(CRITERION_MAP.get(type));
    }

    @Override
    public Optional<PiTableId> mapFlowRuleTableId(int flowRuleTableId) {
        return Optional.ofNullable(TABLE_MAP.get(flowRuleTableId));
    }








    @Override
    public PiAction mapTreatment(TrafficTreatment treatment, PiTableId piTableId) throws PiInterpreterException {
        log.debug("Mapping traffic treatment: "+treatment.toString()+" for table "+ piTableId +" on INTMDInterpreter");
        if (treatment.allInstructions().isEmpty()){
            //No actions on treatment: drop
            //Don't get why use table0 drop action if no table is specified (no instructions)
            return PiAction.builder().withId(INGRESS_TABLE0_DROP).build();
        } else if (treatment.allInstructions().size() > 1) {
            throw new PiInterpreterException("Only one instruction is allowed.");
        }

        Instruction instruction = treatment.allInstructions().get(0);
        switch (instruction.type()) {
            case OUTPUT:
                if (piTableId.equals(TABLE0)){
                    log.debug("Mapping OUTPUT instruction: "+instruction.toString()+" on INTMDInterpreter");
                    return outputPiAction((OutputInstruction) instruction, INGRESS_TABLE0_SET_EGRESS_PORT);
                } //else if piTableId corresponds to another implemented table, set action
                else {
                    throw new PiInterpreterException("Output instruction not supported in table "+piTableId);
                }
            case NOACTION:
                return PiAction.builder().withId(NO_ACTION).build();
            default:
                throw new PiInterpreterException(format("Instruction type '%s' not supported in INTMDInterpreter", instruction.type()));
        }
    }

    private PiAction outputPiAction(OutputInstruction outInstruction, PiActionId piActionId)
            throws PiInterpreterException {
        PortNumber port = outInstruction.port();
        if (!port.isLogical()) {
            return PiAction.builder()
                    .withId(piActionId)
                    .withParameter(new PiActionParam(PORT, port.toLong()))
                    .build();
        } else if (port.equals(CONTROLLER)) {
            return PiAction.builder().withId(INGRESS_TABLE0_SEND_TO_CPU).build();
        } else {
            throw new PiInterpreterException(format(
                    "Egress on logical port '%s' not supported", port));
        }
    }









    @Override
    public Collection<PiPacketOperation> mapOutboundPacket(OutboundPacket packet) throws PiInterpreterException {
        TrafficTreatment treatment = packet.treatment();

        // basic.p4 supports only OUTPUT instructions.
        List<OutputInstruction> outInstructions = treatment
                .allInstructions()
                .stream()
                .filter(i -> i.type().equals(OUTPUT))
                .map(i -> (OutputInstruction) i)
                .collect(toList());

        if (treatment.allInstructions().size() != outInstructions.size()) {
            // There are other instructions that are not of type OUTPUT.
            throw new PiInterpreterException("Treatment not supported: " + treatment);
        }

        ImmutableList.Builder<PiPacketOperation> builder = ImmutableList.builder();
        for (OutputInstruction outInst : outInstructions) {
            if (outInst.port().isLogical() && !outInst.port().equals(FLOOD)) {
                throw new PiInterpreterException(format(
                        "Output on logical port '%s' not supported", outInst.port()));
            } else if (outInst.port().equals(FLOOD)) {
                // Since basic.p4 does not support flooding, we create a packet
                // operation for each switch port.
                final DeviceService deviceService = handler().get(DeviceService.class);
                for (Port port : deviceService.getPorts(packet.sendThrough())) {
                    builder.add(createPiPacketOperation(packet.data(), port.number().toLong()));
                }
            } else {
                builder.add(createPiPacketOperation(packet.data(), outInst.port().toLong()));
            }
        }
        return builder.build();
    }

    private PiPacketOperation createPiPacketOperation(ByteBuffer data, long portNumber)
            throws PiInterpreterException {
        PiPacketMetadata metadata = createPacketMetadata(portNumber);
        return PiPacketOperation.builder()
                .withType(PACKET_OUT)
                .withData(copyFrom(data))
                .withMetadatas(ImmutableList.of(metadata))
                .build();
    }

    private PiPacketMetadata createPacketMetadata(long portNumber) throws PiInterpreterException {
        try {
            return PiPacketMetadata.builder()
                    .withId(EGRESS_PORT)
                    .withValue(copyFrom(portNumber).fit(PORT_BITWIDTH))
                    .build();
        } catch (ImmutableByteSequence.ByteSequenceTrimException e) {
            throw new PiInterpreterException(format(
                    "Port number %d too big, %s", portNumber, e.getMessage()));
        }
    }


    @Override
    public InboundPacket mapInboundPacket(PiPacketOperation packetOperation, DeviceId deviceId) throws PiPipelineInterpreter.PiInterpreterException {
        // Assuming that the packet is ethernet, which is fine since basic.p4
        // can deparse only ethernet packets.
        log.debug("MAPPING INBOUND PACKET __");
        Ethernet ethPkt;
        try {

            ethPkt = Ethernet.deserializer().deserialize(packetOperation.data().asArray(), 0,
                    packetOperation.data().size());
        } catch (DeserializationException dex) {
            log.error("Deserialization error", dex);
            throw new PiInterpreterException(dex.getMessage());
        }
        //log.info("GETTING PACKET METADATA");
        //log.info(ethPkt.toString());
        // Returns the ingress port packet metadata.
        Optional<PiPacketMetadata> packetMetadata = packetOperation.metadatas()
                .stream().filter(m -> m.id().equals(INGRESS_PORT))
                .findFirst();

        if (packetMetadata.isPresent()) {
            ImmutableByteSequence portByteSequence = packetMetadata.get().value();
            short s = portByteSequence.asReadOnlyBuffer().getShort();
            ConnectPoint receivedFrom = new ConnectPoint(deviceId, PortNumber.portNumber(s));
            ByteBuffer rawData = ByteBuffer.wrap(packetOperation.data().asArray());
            return new DefaultInboundPacket(receivedFrom, ethPkt, rawData);
        } else {
            throw new PiInterpreterException(format(
                    "Missing metadata '%s' in packet-in received from '%s': %s",
                    INGRESS_PORT, deviceId, packetOperation));
        }
    }


    /* Not necessary functions at this moment

    @Override
    public Optional<Integer> mapLogicalPortNumber(PortNumber port) {
        return PiPipelineInterpreter.super.mapLogicalPortNumber(port);
    }

    @Override
    public Optional<PiAction> getOriginalDefaultAction(PiTableId tableId) {
        return PiPipelineInterpreter.super.getOriginalDefaultAction(tableId);
    }

    */
}
