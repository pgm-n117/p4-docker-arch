package org.<app_package>.app;

import org.junit.Test;
import org.junit.After;
import org.junit.Before;

import org.onosproject.cfg.ComponentConfigAdapter;

/**
 * Set of tests of the ONOS application component.
 */
public class CLASS_NAME_TEST {

    //private P4Routing component;
    CLASS_NAME component = new CLASS_NAME();
    
    @Before
    public void setUp() {

        component.cfgService = new ComponentConfigAdapter();
        component.activate();

        //----------------------------
        // Your tests here for @Activate
        //----------------------------
    

    }

    @After
    public void tearDown() {
        //----------------------------
        // Your tests here for @Deactivate
        //----------------------------
        component.deactivate();
    }

    @Test
    public void basics() {
        //----------------------------
        // Your tests here
        //----------------------------
    }

}
