package customPipeline;

import com.google.common.collect.ImmutableList;
import com.google.errorprone.annotations.Immutable;
import customPipeline.INTMD.INTMDInterpreterImpl;
import customPipeline.INTMD.INTMDPipelinerImpl;
import customPipeline.INTMX.INTMXInterpreterImpl;
import customPipeline.INTMX.INTMXPipelinerImpl;
import customPipeline.INTXD.INTXDInterpreterImpl;
import customPipeline.INTXD.INTXDPipelinerImpl;
import org.onosproject.core.CoreService;
import org.onosproject.net.behaviour.Pipeliner;
import org.onosproject.p4runtime.model.P4InfoParser;
import org.onosproject.p4runtime.model.P4InfoParserException;
import org.onosproject.net.behaviour.inbandtelemetry.IntProgrammable;
import org.onosproject.net.device.PortStatisticsDiscovery;
import org.onosproject.net.pi.model.*;
import org.onosproject.net.pi.service.PiPipeconfService;
import org.osgi.service.component.annotations.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.util.Collection;
import java.util.List;


import static org.onosproject.net.pi.model.PiPipeconf.ExtensionType.BMV2_JSON;
import static org.onosproject.net.pi.model.PiPipeconf.ExtensionType.P4_INFO_TEXT;

@Component(immediate = true)
public final class PipeconfLoader {
    public static final Logger log = LoggerFactory.getLogger(PipeconfLoader.class);
    private static final String APP_NAME = "org.customPipeline.app";

    //Different INT variation pipelines from github: https://github.com/mandaryoshi/p4-int

    //INT-MD
    private static final PiPipeconfId INTMD_PIPECONF_ID = new PiPipeconfId("org.onosproject.pipelines.intmd"); //TODO:complete name of the pipeline
    private static final String INTMD_JSON_PATH = "/p4c-out/bmv2/int_md_2_1_stratum.json";
    private static final String INTMD_P4INFO_PATH = "/p4c-out/bmv2/int_md_2_1_stratum_p4info.txt";
    private static final PiPipeconf INTMD_PIPECONF =buildIntMDPipeconf();


    //INT-XD
    private static final PiPipeconfId INTXD_PIPECONF_ID = new PiPipeconfId("org.onosproject.pipelines.intxd"); //TODO:complete name of the pipeline
    private static final String INTXD_JSON_PATH = "xxx.json";
    private static final String INTXD_P4INFO_PATH = "xxx_p4info.txt";
    private static final PiPipeconf INTXD_PIPECONF = buildIntXDPipeconf();



    //INT-MX
    private static final PiPipeconfId INTMX_PIPECONF_ID = new PiPipeconfId("org.onosproject.pipelines.intmx"); //TODO:complete name of the pipeline
    private static final String INTMX_JSON_PATH = "xxx.json";
    private static final String INTMX_P4INFO_PATH = "xxx_p4info.txt";
    private static final PiPipeconf INTMX_PIPECONF = buildIntMXPipeconf();



    private static final Collection<PiPipeconf> ALL_PIPECONFS = listOfPipelines();

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private PiPipeconfService piPipeconfService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private CoreService coreService;

    @Activate
    public void activate() {
        coreService.registerApplication(APP_NAME);
        // Registers all pipeconf at component activation.
        ALL_PIPECONFS.forEach(piPipeconfService::register);

    }
    @Deactivate
    public void deactivate() {
        ALL_PIPECONFS.stream().map(PiPipeconf::id).forEach(piPipeconfService::unregister);
    }


    private static PiPipeconf buildIntMDPipeconf() {
        final URL jsonUrl = PipeconfLoader.class.getResource(INTMD_JSON_PATH);
        final URL p4InfoUrl = PipeconfLoader.class.getResource(INTMD_P4INFO_PATH);

        try {
            PiPipeconf pipeconf = DefaultPiPipeconf.builder()
                    .withId(INTMD_PIPECONF_ID)
                    .withPipelineModel(parseP4Info(p4InfoUrl))
                    //TODO: CHECK THE FOLLOWING BEHAVIOURS ACCORDING TO THE P4 PROGRAMS
                    .addBehaviour(PiPipelineInterpreter.class, INTMDInterpreterImpl.class)
                    .addBehaviour(Pipeliner.class, INTMDPipelinerImpl.class)
                    .addBehaviour(PortStatisticsDiscovery.class, PortStatisticsDiscoveryImpl.class)
                    //.addBehaviour(IntProgrammable.class, IntProgrammableImpl.class) TODO: DONT KNOW YET ABOUT THIS BEHAVIOUR
                    .addExtension(P4_INFO_TEXT, p4InfoUrl)
                    .addExtension(BMV2_JSON, jsonUrl)
                    .build();
            return pipeconf;

        } catch (Exception e){
            log.info("INT MD pipeline could not be loaded.");
            e.printStackTrace();
            return null;
        }

    }

    private static PiPipeconf buildIntXDPipeconf() {
        final URL jsonUrl = PipeconfLoader.class.getResource(INTXD_JSON_PATH);
        final URL p4InfoUrl = PipeconfLoader.class.getResource(INTXD_P4INFO_PATH);
        try {
        PiPipeconf pipeconf = DefaultPiPipeconf.builder()
                .withId(INTXD_PIPECONF_ID)
                .withPipelineModel(parseP4Info(p4InfoUrl))
                //TODO: CHECK THE FOLLOWING BEHAVIOURS ACCORDING TO THE P4 PROGRAMS
                .addBehaviour(PiPipelineInterpreter.class, INTXDInterpreterImpl.class)
                .addBehaviour(Pipeliner.class, INTXDPipelinerImpl.class)
                .addBehaviour(PortStatisticsDiscovery.class, PortStatisticsDiscoveryImpl.class)
                //.addBehaviour(IntProgrammable.class, IntProgrammableImpl.class) TODO: DONT KNOW YET ABOUT THIS BEHAVIOUR
                .addExtension(P4_INFO_TEXT, p4InfoUrl)
                .addExtension(BMV2_JSON, jsonUrl)
                .build();

            return pipeconf;
        } catch (Exception e){
            log.info("INT XD pipeline could not be loaded.");
            e.printStackTrace();
            return null;
        }
    }


    private static PiPipeconf buildIntMXPipeconf() {
        final URL jsonUrl = PipeconfLoader.class.getResource(INTMX_JSON_PATH);
        final URL p4InfoUrl = PipeconfLoader.class.getResource(INTMX_P4INFO_PATH);

        try {
            PiPipeconf pipeconf = DefaultPiPipeconf.builder()
                    .withId(INTMX_PIPECONF_ID)
                    .withPipelineModel(parseP4Info(p4InfoUrl))
                    //TODO: CHECK THE FOLLOWING BEHAVIOURS ACCORDING TO THE P4 PROGRAMS
                    .addBehaviour(PiPipelineInterpreter.class, INTMXInterpreterImpl.class)
                    .addBehaviour(Pipeliner.class, INTMXPipelinerImpl.class)
                    .addBehaviour(PortStatisticsDiscovery.class, PortStatisticsDiscoveryImpl.class)
                    //.addBehaviour(IntProgrammable.class, IntProgrammableImpl.class) TODO: DONT KNOW YET ABOUT THIS BEHAVIOUR
                    .addExtension(P4_INFO_TEXT, p4InfoUrl)
                    .addExtension(BMV2_JSON, jsonUrl)
                    .build();
            return pipeconf;
        } catch (Exception e){
            log.info("INT MX pipeline could not be loaded");
            e.printStackTrace();
            return null;
        }
    }

private static ImmutableList listOfPipelines(){
        ImmutableList.Builder<PiPipeconf> pipeconfs = ImmutableList.builder();
        if (INTMD_PIPECONF != null) pipeconfs.add(INTMD_PIPECONF);
        if (INTMX_PIPECONF != null) pipeconfs.add(INTMX_PIPECONF);
        if (INTXD_PIPECONF != null)pipeconfs.add(INTXD_PIPECONF);
        return pipeconfs.build();
}

    private static PiPipelineModel parseP4Info(URL p4InfoUrl) {
        try {
            return P4InfoParser.parse(p4InfoUrl);
        } catch (P4InfoParserException e) {
            throw new IllegalStateException(e);
        }
    }
}


