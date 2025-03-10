package org.mecp4.app;

import org.onlab.packet.IpAddress;
import org.onlab.packet.TpPort;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
import org.onosproject.net.config.Config;
import org.onosproject.ui.JsonUtils;
import org.onlab.packet.MacAddress;


public final class P4Config extends Config<DeviceId> {

    private static final String SINK_MAC = "sinkMAC";
    private static final String COLLECTOR_MAC = "collectorMAC";
    private static final String MINFLOWHOPLATENCYCHANGENS = "minFlowHopLatencyChangeNs";
    private static final String SINK_IP = "sinkIP";
    private static final String COLLECTOR_IP = "collectorIP";
    private static final String COLLECTOR_PORT = "collectorPort";

    //private static final String DEVICES = "devices";



    public IpAddress sinkIpAddress(){
        if (object.hasNonNull(SINK_IP)) {
            return IpAddress.valueOf(JsonUtils.string(object, SINK_IP));
        }else {
            return null;
        }
    }

    public IpAddress collectorIpAddress(){
        if (object.hasNonNull(COLLECTOR_IP)) {
            return IpAddress.valueOf(JsonUtils.string(object, COLLECTOR_IP));
        }else {
            return null;
        }
    }

    public MacAddress sinkMacAddress(){
        if (object.hasNonNull(SINK_MAC)) {
            return MacAddress.valueOf(JsonUtils.string(object, SINK_MAC));
        }else {
            return null;
        }
    }

    public MacAddress collectorMacAddress(){
        if (object.hasNonNull(COLLECTOR_MAC)) {
            return MacAddress.valueOf(JsonUtils.string(object, COLLECTOR_MAC));
        }else {
            return null;
        }
    }

    public int minFlowHopLatencyChangeNs(){
        if (object.hasNonNull(MINFLOWHOPLATENCYCHANGENS)) {
            return (int) JsonUtils.number(object, MINFLOWHOPLATENCYCHANGENS);
        } else {
            return 0;
        }
    }

    public TpPort collectorPort(){
        if (object.hasNonNull(COLLECTOR_PORT)) {
            return TpPort.tpPort((int) JsonUtils.number(object, COLLECTOR_PORT));
        } else {
            return null;
        }
    }
}

