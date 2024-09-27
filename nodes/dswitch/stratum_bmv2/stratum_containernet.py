#TODO: ADAPT THE FOLLOWING ORIGINAL INTRO AND USAGE HELP

# coding=utf-8
# Copyright 2018-present Open Networking Foundation
# SPDX-License-Identifier: Apache-2.0

'''
This module contains a switch class for Mininet: StratumBmv2Switch

Prerequisites
-------------
1. Docker- mininet+stratum_bmv2 image:
$ cd stratum
$ docker build -t <some tag> -f tools/mininet/Dockerfile .

Usage
-----
From withing the Docker container, you can run Mininet using the following:
$ mn --custom /root/stratum.py --switch stratum-bmv2 --controller none

Advanced Usage
--------------
You can use this class in a Mininet topology script by including:

from stratum import ONOSStratumBmv2Switch

You will probably need to update your Python path. From within the Docker image:

PYTHONPATH=$PYTHONPATH:/root ./<your script>.py

Notes
-----
This code has been adapted from the ONOSBmv2Switch class defined in the ONOS project
(tools/dev/mininet/bmv2.py).

'''

import urllib.error
import urllib.request
import urllib.response
from mininet.net import Mininet, Containernet
import docker
from mininet.node import Switch, Host, Docker
from mininet.log import setLogLevel, info, error, debug, warn
from mininet.moduledeps import pathCheck
from sys import exit
import os
from os import environ
import tempfile
import socket
import json
import multiprocessing
import threading
import time

from ..DockerSwitch.DockerSwitch import DockerSwitch

import urllib


#TODO Check how the rules are configured in the switch with the runtime_cli app. L2 mode do not work with the provided stress test configuration,
    #    #    so, check how the L2 configuration must be to provide an alternative
    #    #TODO Check how to connect to ONOS  controller? maybe with the p4runtime or something - DONE




DEFAULT_NODE_ID = 1
DEFAULT_CPU_PORT = 255
DEFAULT_PIPECONF = "org.onosproject.pipelines.basic"

STRATUM_BMV2 = 'stratum_bmv2'
STRATUM_INIT_PIPELINE = '/root/dummy.json'
MAX_CONTROLLERS_PER_NODE = 10
BMV2_LOG_LINES = 5

ONOS_WEB_USER = "onos"
ONOS_WEB_PASS = "rocks"
CONTROLLER_STRATUM_PORT = 50001


#TODO finnish docker implementation
class StratumBmv2DockerSwitch(DockerSwitch):
    """Stratum BMv2 Dockerized software switch
    Parameters to be passed to the constructor:
    - name: name for the switch
    - json: BMv2 JSON file, from P4 compiled code. Suggestion: Start with compiled main.p4 file from NGSDN-Tutorial.
    - loglevel: log level for the switch
    - cpuport: CPU port for the switch. default port of stratum_bmv2 binary is 64. Default on this script is 255.
    - pipeconf: pipeconf for the switch
    - onosdevid: ONOS device ID for the switch
    - adminstate: admin state for the switch
    - grpcPort: gRPC port for the switch

    Docker Parameters:
    - dimage: Docker image to use
    - dcmd: Docker command to use
    - build_params: Docker build parameters

    Other Parameters through kwargs:
    - longitude: longitude for the switch
    - latitude: latitude for the switch

    **Stratum ngsdn-tutorial P4 files are compatible with version 1.1.0rc1 of p4c-bm2-ss compiler. It is available using the P4C docker command:**
    
    docker run --rm -v {working_directory}:/workdir -w /workdir opennetworking/p4c:stable \
        p4c-bm2-ss --arch v1model -o {compiled_file}.json \
        --p4runtime-files {protobuf_info_file}.p4info.txt --Wdisable=unsupported \
        {p4_file}.p4

    """





    # Shared value used to notify to all instances of this class that a Mininet
    # exception occurred. Mininet exception handling doesn't call the stop()
    # method, so the mn process would hang after clean-up since Bmv2 would still
    # be running.
    mininet_exception = multiprocessing.Value('i', 0)

    #TODO UPdating this value when using containers is not necessary, the port can be the same in every container
    nextGrpcPort = 50001

    def __init__(self, name, json=STRATUM_INIT_PIPELINE, loglevel="warn",
                 cpuport=DEFAULT_CPU_PORT, 
                 pipeconf=DEFAULT_PIPECONF,
                 onosdevid=None, 
                 adminstate=True, 
                 grpcPort=CONTROLLER_STRATUM_PORT,
                 dimage="pgmconreg/stratum_bmv2:latest",
                 dcmd=None, 
                 build_params={},
                 controllerAddress=None,
                 **kwargs):
        
        #Initialize the DockerSwitch class
        DockerSwitch.__init__(self, name, dimage=dimage, dcmd=dcmd, build_params=build_params, **kwargs)
                
        #Stratum Switch specific initialization


        self.grpcPort = grpcPort
        self.cpuPort = cpuport
        self.json = json
        self.loglevel = loglevel
        self.tmpDir = '/tmp/%s' % self.name
        self.logfile = '%s/stratum_bmv2.log' % self.tmpDir
        self.netcfgFile = '%s/onos-netcfg.json' % self.tmpDir
        self.chassisConfigFile = '%s/chassis-config.txt' % self.tmpDir
        self.pipeconfId = pipeconf
        self.longitude = kwargs['longitude'] if 'longitude' in kwargs else None
        self.latitude = kwargs['latitude'] if 'latitude' in kwargs else None
        if onosdevid is not None and len(onosdevid) > 0:
            self.onosDeviceId = onosdevid
        else:
            # The "device:" prefix is required by ONOS.
            self.onosDeviceId = "device:%s" % self.name
        self.nodeId = DEFAULT_NODE_ID
        self.logfd = None
        self.bmv2popen = None
        self.bmv2pid = None
        self.stopped = True
        # In case of exceptions, mininet removes *.out files from /tmp. We use
        # this as a signal to terminate the switch instance (if active).
        self.keepaliveFile = '/tmp/%s-watchdog.out' % self.name
        self.adminState = "ENABLED" if adminstate else "DISABLED"
        
        self.controllerAddress = controllerAddress

        # Make a tmp directory for this switch
        self.cmd("mkdir -p %s" % self.tmpDir)
        #os.mkdir(self.tmpDir)

    

    def getDeviceConfig(self, srcIP):
        """
         From ONOS BMV2 switch example. https://github.com/opennetworkinglab/onos/blob/dd5172e5a6e1ba5c7e17e2f497aa8c27a1ed33e9/tools/dev/mininet/bmv2.py"""
        basicCfg = {
            "managementAddress": "grpc://%s:%d?device_id=%d" % (
                srcIP, self.grpcPort, self.nodeId),
            "driver": "stratum-bmv2",
            "pipeconf": self.pipeconfId
        }

        if self.longitude and self.latitude:
            basicCfg["longitude"] = self.longitude
            basicCfg["latitude"] = self.latitude

        cfgData = {
            "basic": basicCfg
        }

        
        portData = {}
        portId = 1
        for intfName in self.intfNames():
            if intfName == 'lo':
                continue
            portData[str(portId)] = {
                "number": portId,
                "name": intfName,
                "enabled": True,
                "removed": False,
                "type": "copper",
                "speed": 10000
            }
            portId += 1

        cfgData['ports'] = portData

        return cfgData
    
    def doOnosNetcfg(self, controllerIP):
        """
        From ONOS BMV2 switch example. https://github.com/opennetworkinglab/onos/blob/dd5172e5a6e1ba5c7e17e2f497aa8c27a1ed33e9/tools/dev/mininet/bmv2.py

        Notifies ONOS about the new device via Netcfg.
        """

        if self.controllerAddress is None:
            # Do not push config to ONOS.
            return
    
        srcIP = self.getSourceIp(controllerIP)
        if not srcIP:
            warn("*** WARN: unable to get switch IP address, won't do netcfg\n")
            return

        cfgData = {
            "devices": {
                self.onosDeviceId: self.getDeviceConfig(srcIP)
            }
        }

        self.cmd("echo '"+json.dumps(cfgData, indent=4)+"' > "+self.netcfgFile)


        # Build netcfg URL
        url = 'http://%s:8181/onos/v1/network/configuration/' % controllerIP
        # Instantiate password manager for HTTP auth
        pm = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        pm.add_password(None, url, ONOS_WEB_USER, ONOS_WEB_PASS)
        urllib.request.install_opener(urllib.request.build_opener(
            urllib.request.HTTPBasicAuthHandler(pm)))
        # Push config data to controller
        req = urllib.request.Request(url, json.dumps(cfgData),
                              {'Content-Type': 'application/json'})
        try:

            f = urllib.request.urlopen(req, data=json.dumps(cfgData).encode('utf-8'))
            #print(f.read())
            f.close()
        except urllib.error.URLError as e:
            warn("*** WARN: unable to push config to ONOS (%s)\n" % e.reason)
    


#TODO: Check utility of this function on the containerized version
    def getChassisConfig(self):
        config = """description: "stratum_bmv2 {name}"
chassis {{
  platform: PLT_P4_SOFT_SWITCH
  name: "{name}"
}}
nodes {{
  id: {nodeId}
  name: "{name} node {nodeId}"
  slot: 1
  index: 1
}}\n""".format(name=self.name, nodeId=self.nodeId)

        for port_num, intf in sorted(self.intfs.items()):
            if intf.name == "lo":
                continue
            config = config + """singleton_ports {{
  id: {intfNumber}
  name: "{intfName}"
  slot: 1
  port: {intfNumber}
  channel: 1
  speed_bps: 10000000000
  config_params {{
    admin_state: ADMIN_STATE_{adminState}
  }}
  node: {nodeId}
}}\n""".format(intfName=intf.name, intfNumber=port_num, nodeId=self.nodeId, adminState=self.adminState)

        return config





    def start(self, controllers):
        if not self.stopped:
            warn("*** %s is already running!\n" % self.name)
            return
        try:

            ##INTERFACES MUST DEFINITELY BE UP, AS THEY ARE NOT ADDED TO THE SWITCH CONFIGURATION
            ## This is necessary, because the interfaces are not active on containers even 
            ## if they are added on the mininet script
            self.set_up_interfaces()
            #links = self.intfList()
            #for intf in links:
            #    #check if interfaces are up, and if they are not, bring them up
            #    if not self.cmd("ip link show {}".format(intf.name)).split()[8] == "UP":
            #        self.cmd("ip link set {} up".format(intf.name))


            #writeToFile("%s/grpc-port.txt" % self.tmpDir, self.grpcPort)
            self.cmd("echo '"+str(self.grpcPort) + "' > "+self.tmpDir+"/grpc-port.txt")

            #with open(self.chassisConfigFile, 'w') as fp:
            #    fp.write(self.getChassisConfig())
            self.cmd("echo '"+self.getChassisConfig()+"' > "+self.chassisConfigFile)

            #with open(self.netcfgFile, 'w') as fp:
            #    json.dump(self.getOnosNetcfg(), fp, indent=2)
            ##self.cmd("echo '"+json.dumps(self.getOnosNetcfg(), indent=2)+"' > "+self.netcfgFile)

            




            args = [
                STRATUM_BMV2,
                '-device_id=%d' % self.nodeId,
                '-chassis_config_file=%s' % self.chassisConfigFile,
                '-forwarding_pipeline_configs_file=%s/pipe.txt' % self.tmpDir,
                '-persistent_config_dir=%s' % self.tmpDir,
                #'-initial_pipeline=%s' % self.json,
                '-cpu_port=%s' % self.cpuPort,
                '-external_stratum_urls=0.0.0.0:%d' % self.grpcPort,
                '-max_num_controllers_per_node=%d' % MAX_CONTROLLERS_PER_NODE,
                '-write_req_log_file=%s/write-reqs.txt' % self.tmpDir,
                '-bmv2_log_level=%s' % self.loglevel,
            ]

            cmd_string = " ".join(args)

        

            # Write cmd_string to log for debugging.
            #self.logfd = open(self.logfile, "w")
            #self.logfd.write(cmd_string + "\n\n" + "-" * 80 + "\n\n")
            #self.logfd.flush()
            self.cmd("echo '"+cmd_string + "\n\n" + "-" * 80 + "\n\n' > "+self.logfile)
            

            #self.bmv2popen = self.popen(cmd_string, stdout=self.logfd, stderr=self.logfd)
            #launch cmd_string command in the container and save the process id
            self.cmd(cmd_string + " > "+self.logfile+" 2>&1 & echo $! > "+self.tmpDir+"/bmv2popen.pid")
            self.bmv2pid = int(self.cmd("cat "+self.tmpDir+"/bmv2popen.pid"))
            print("⚡️ %s @ %d, PID: %d" % (STRATUM_BMV2, self.grpcPort, self.bmv2pid))

            # We want to be notified if stratum_bmv2 quits prematurely...
            self.check_docker_switch_started(self.bmv2pid, [self.grpcPort])
            self.stopped = False
            #threading.Thread(target=watchdog, args=[self]).start()

            #this is specific for ONOS controller.
            self.doOnosNetcfg(self.controllerAddress)

        except Exception:
            StratumBmv2DockerSwitch.mininet_exception = 1
            self.stop()
            self.printLog()
            raise

                
            
#TODO: Check utility of this function on the containerized version
    def printLog(self):
        if os.path.isfile(self.logfile):
            print("-" * 80)
            print("%s log (from %s):" % (self.name, self.logfile))
            with open(self.logfile, 'r') as f:
                lines = f.readlines()
                if len(lines) > BMV2_LOG_LINES:
                    print("...")
                for line in lines[-BMV2_LOG_LINES:]:
                    print(line.rstrip())



#TODO: Check utility of this function on the containerized version
    def stop(self, deleteIntfs=True):
        """Terminate switch."""
        self.stopped = True
        if self.bmv2popen is not None:
            if self.bmv2popen.poll() is None:
                self.bmv2popen.terminate()
                self.bmv2popen.wait()
            self.bmv2popen = None
        if self.logfd is not None:
            self.logfd.close()
            self.logfd = None
        Switch.stop(self, deleteIntfs)


# Exports for bin/mn
switches = {'stratum-bmv2-docker': StratumBmv2DockerSwitch}

#hosts = {
#    'no-offload-host': NoOffloadHost,
#    'no-ipv6-host': NoIpv6OffloadHost
#}
