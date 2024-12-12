package customPipeline;

import org.onosproject.net.device.PortStatistics;
import org.onosproject.net.device.PortStatisticsDiscovery;
import org.onosproject.net.driver.AbstractHandlerBehaviour;

import java.util.Collection;
import java.util.List;

public class PortStatisticsDiscoveryImpl extends AbstractHandlerBehaviour implements PortStatisticsDiscovery {
    @Override
    public Collection<PortStatistics> discoverPortStatistics() {
        return List.of();
    }
}
