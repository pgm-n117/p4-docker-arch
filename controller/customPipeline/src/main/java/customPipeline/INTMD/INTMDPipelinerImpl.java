package customPipeline.INTMD;

import org.onosproject.core.ApplicationId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.behaviour.NextGroup;
import org.onosproject.net.behaviour.Pipeliner;
import org.onosproject.net.behaviour.PipelinerContext;
import org.onosproject.net.driver.AbstractHandlerBehaviour;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flowobjective.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import java.util.Collection;
import java.util.Collections;
import java.util.List;

import static customPipeline.CustomConstants.*;

public class INTMDPipelinerImpl extends AbstractHandlerBehaviour implements Pipeliner {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private FlowRuleService flowRuleService;
    private DeviceId deviceId;


    @Override
    public void init(DeviceId deviceId, PipelinerContext context) {
        this.deviceId = deviceId;
        this.flowRuleService = context.directory().get(FlowRuleService.class);
    }

    @Override
    public void filter(FilteringObjective filterObjective) {
        //At this moment only support forwarding rules, no filtering (which I suppose it means PERMIT or DENY flowrules).
        filterObjective.context().ifPresent(c -> c.onError(filterObjective, ObjectiveError.UNSUPPORTED));
    }

    @Override
    public void forward(ForwardingObjective forwardObjective) {
        //Forwarding objective flowrules that do not have a corresponding traffic treatment are unsupported.
        //
        if(forwardObjective.treatment()==null){
            forwardObjective.context().ifPresent(c -> c.onError(forwardObjective, ObjectiveError.UNSUPPORTED));
        }

        //Create flowrule for the main control table implementation in P4 (TABLE0)
        // Simply create an equivalent FlowRule for table 0.
        final FlowRule.Builder ruleBuilder = DefaultFlowRule.builder()
                .forTable(TABLE0)
                .forDevice(deviceId)
                .withSelector(forwardObjective.selector())
                .fromApp(forwardObjective.appId())
                .withPriority(forwardObjective.priority())
                .withTreatment(forwardObjective.treatment());

        if (forwardObjective.permanent()) {
            ruleBuilder.makePermanent();
        } else {
            ruleBuilder.makeTemporary(forwardObjective.timeout());
        }

        switch (forwardObjective.op()) {
            case ADD:
                flowRuleService.applyFlowRules(ruleBuilder.build());
                break;
            case REMOVE:
                flowRuleService.removeFlowRules(ruleBuilder.build());
                break;
            default:
                log.warn("Unknown operation {}", forwardObjective.op());
        }

        forwardObjective.context().ifPresent(c -> c.onSuccess(forwardObjective));
    }

    @Override
    public void next(NextObjective nextObjective) {
        nextObjective.context().ifPresent(c -> c.onError(nextObjective, ObjectiveError.UNSUPPORTED));
    }

    @Override
    public void purgeAll(ApplicationId appId) {
        flowRuleService.purgeFlowRules(deviceId, appId);
    }

    @Override
    public List<String> getNextMappings(NextGroup nextGroup) {
        //Not using nextObjectives as in ONOS implementation of basic pipeline
        return Collections.emptyList();
    }
}
