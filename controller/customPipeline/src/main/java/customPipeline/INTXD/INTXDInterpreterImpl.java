package customPipeline.INTXD;

import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.driver.AbstractHandlerBehaviour;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiPipelineInterpreter;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiPacketOperation;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

public class INTXDInterpreterImpl extends AbstractHandlerBehaviour
        implements PiPipelineInterpreter {
    @Override
    public Optional<PiMatchFieldId> mapCriterionType(Criterion.Type type) {
        return Optional.empty();
    }

    @Override
    public Optional<PiTableId> mapFlowRuleTableId(int flowRuleTableId) {
        return Optional.empty();
    }

    @Override
    public PiAction mapTreatment(TrafficTreatment treatment, PiTableId piTableId) throws PiInterpreterException {
        return null;
    }

    @Override
    public Collection<PiPacketOperation> mapOutboundPacket(OutboundPacket packet) throws PiInterpreterException {
        return List.of();
    }

    @Override
    public InboundPacket mapInboundPacket(PiPacketOperation packetOperation, DeviceId deviceId) throws PiInterpreterException {
        return null;
    }

    @Override
    public Optional<Integer> mapLogicalPortNumber(PortNumber port) {
        return PiPipelineInterpreter.super.mapLogicalPortNumber(port);
    }

    @Override
    public Optional<PiAction> getOriginalDefaultAction(PiTableId tableId) {
        return PiPipelineInterpreter.super.getOriginalDefaultAction(tableId);
    }
}
