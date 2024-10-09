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

 package org.<app_package>.app;



 import org.onlab.packet.*;
 import org.onosproject.cfg.ComponentConfigService;
 import org.osgi.service.component.ComponentContext;
 import org.osgi.service.component.annotations.*;
 import org.slf4j.*;
 import org.onlab.packet.*;
 import org.onosproject.core.*;
 import org.onosproject.net.*;
 import org.onosproject.net.packet.*;
 import java.util.concurrent.atomic.AtomicInteger;
 import java.util.Optional;
 
 
 /**
  * Skeletal ONOS application component.
  */
 @Component(immediate = true,
         service = {<CLASS_NAME>.class},
         property = {
                 "someProperty=Some Default String Value"
         })
 public class CLASS_NAME{
     public final Logger log = LoggerFactory.getLogger(getClass());
 
     private String someProperty; //From @Component properties to be loaded
 
     //--------------------------------------------------------------------------
     // ONOS core services needed by this application.
     //--------------------------------------------------------------------------
     @Reference(cardinality = ReferenceCardinality.MANDATORY)
     protected ComponentConfigService cfgService;
 
     @Reference(cardinality = ReferenceCardinality.MANDATORY)
     protected CoreService coreService;

     //--------------------------------------------------------------------------
     // ONOS alternative services used by applications, depending on your project.
     //--------------------------------------------------------------------------
     @Reference(cardinality = ReferenceCardinality.MANDATORY)
     protected PacketService packetService;
  
     @Reference(cardinality = ReferenceCardinality.MANDATORY)
     protected TopologyService topologyService;

     @Reference(cardinality = ReferenceCardinality.MANDATORY)
     protected FlowRuleService flowRuleService;
 
     @Reference(cardinality = ReferenceCardinality.MANDATORY)
     protected EdgePortService edgePortService;
 
     @Reference(cardinality = ReferenceCardinality.MANDATORY)
     protected HostService hostService;
 
     // And many other possible services
 
 
     //--------------------------------------------------------------------------
     // Application specific variables
     //--------------------------------------------------------------------------
 
     private static final String APP_NAME = "org.<your_app_name>.app";
     //...
 
 
     //Packet Processor
     private PacketProcessor myPacketProcessor;

     //Application ID
     private ApplicationId appId;
 
 
     // @Activate, @Deactivate and @Modified annotations are used to manage the life cycle of the application. 
     // The three methods MUST be implemented in the class in order to correctly manage the life cycle of the application,
     // even if the methods are not doing anything, for example, maybe you don't need to do enything on @Modified.
    
     @Activate
     protected void activate() {
         try {
 
             cfgService.registerProperties(getClass());
 
             //Obtain app id
             appId = coreService.getAppId("org.<your_app_name>.app");

             //Packet Processor
             myPacketProcessor = new myPacketProcessor();
             packetService.addProcessor(myPacketProcessor, PacketProcessor.director(3));
 
             //--------------------------------------------------------------------------------
             // Your code here
             //--------------------------------------------------------------------------------


             log.info(APP_NAME + " Started");
             return;
         }catch (Exception ex) {
             log.info("Error activating "+ APP_NAME +": "+ ex);
         }
     }
 
     @Deactivate
     protected void deactivate() {
 
         try {
             cfgService.unregisterProperties(getClass(), false);
  
             //--------------------------------------------------------------------------------
             // Your code here, Remove everything initialized on activate
             //--------------------------------------------------------------------------------

             packetService.removeProcessor(myPacketProcessor);
             log.info(APP_NAME + " Stopped");


         } catch (Exception ex) {
            log.info("Error deactivating "+ APP_NAME +": "+ ex);
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
 
     private class myPacketProcessor implements PacketProcessor {
 
 
         @Override
         public void process(PacketContext context) {
 
 
             InboundPacket packet = context.inPacket();

             //--------------------------------------------------------------------------------
             // Your code here, process the packet
             //--------------------------------------------------------------------------------
             Ethernet ethPacket = packet.parsed();
             
             // Example of how to drop a packet
             context.treatmentBuilder().drop();
         }
     }
 
 }
 
 