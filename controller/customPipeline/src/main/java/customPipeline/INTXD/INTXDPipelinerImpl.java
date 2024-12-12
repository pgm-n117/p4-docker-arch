package customPipeline.INTXD;

import org.onosproject.core.ApplicationId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.behaviour.NextGroup;
import org.onosproject.net.behaviour.Pipeliner;
import org.onosproject.net.behaviour.PipelinerContext;
import org.onosproject.net.driver.AbstractHandlerBehaviour;
import org.onosproject.net.flowobjective.FilteringObjective;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.flowobjective.NextObjective;

import java.util.List;

public class INTXDPipelinerImpl extends AbstractHandlerBehaviour implements Pipeliner {
    @Override
    public void init(DeviceId deviceId, PipelinerContext context) {

    }

    @Override
    public void filter(FilteringObjective filterObjective) {

    }

    @Override
    public void forward(ForwardingObjective forwardObjective) {

    }

    @Override
    public void next(NextObjective nextObjective) {

    }

    @Override
    public void purgeAll(ApplicationId appId) {

    }

    @Override
    public List<String> getNextMappings(NextGroup nextGroup) {
        return List.of();
    }
}
