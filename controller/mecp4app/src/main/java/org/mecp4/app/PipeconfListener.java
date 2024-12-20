package org.mecp4.app;

import org.onosproject.net.pi.service.PiPipeconfEvent;
import org.onosproject.net.pi.service.PiPipeconfListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PipeconfListener implements PiPipeconfListener {


    private static final Logger log = LoggerFactory.getLogger(PipeconfListener.class);

    @Override
    public void event(PiPipeconfEvent event) {
    log.info("Received Pipeconf event: {}", event);
    }

    @Override
    public boolean isRelevant(PiPipeconfEvent event) {
        log.info("PipeconfListener::isRelevant - event: {}", event);
        return PiPipeconfListener.super.isRelevant(event);
    }
}
