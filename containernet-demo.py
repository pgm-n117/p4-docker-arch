#!/usr/bin/env python3
# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from mininet.net import Mininet, Containernet, Docker

from mininet.node import Host, RemoteController
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.link import TCLink

import os
from nodes.p4_mininet import P4Switch, P4Host
from nodes.dswitch.bmv2.BMV2_containernet import BMV2DockerSwitch
from nodes.dswitch.stratum_bmv2.stratum_containernet import StratumBmv2DockerSwitch
from nodes.dcontroller.DockerOnos import DockerOnos as dockerOnos
#from nodes.dhosts.dcollector.DockerReportCollector import DockerReportCollector as dockerReportCollector
from nodes.mecTopo import MECTopo
#from nodes.bmv2 import ONOSBmv2Switch
import networkx as nx

import argparse
from time import sleep

STRATUM=StratumBmv2DockerSwitch
BMV2=BMV2DockerSwitch
CONTROLLER_ADDRESS="172.17.0.2"
ONOS_DOCKER_APPS_DIRECTORY="/root/onos/apps/"
ONOS_LOCAL_APPS_DIRECTORY=os.getcwd()+"/controller/"

#TODO: Rethink input parameters for building the topology, in order to be generic for different switches.
parser = argparse.ArgumentParser(description='Containernet demo')
parser.add_argument('--switch-model', help='The switch model to use, BMV2 or STRATUM', type=str, default='STRATUM',
                    choices=['BMV2', 'STRATUM'], required=True, action="store")

parser.add_argument('--topo-file', help='Path to NetworkX topology file', type=str, action="store", required=True)

#TODO: Not tested feature
parser.add_argument('--thrift-port', help='Thrift server port for table updates',
                    type=int, action="store", default=9090)

#TODO: Not tested feature
parser.add_argument('--num-hosts', help='Number of hosts to connect to switch',
                    type=int, action="store", default=2)

#TODO: Not tested feature
parser.add_argument('--mode', choices=['l2', 'l3'], type=str, default='l3')

#TODO: Not tested feature
parser.add_argument('--json', help='Path to JSON config file',
                    type=str, action="store", required=True)

#TODO: Not tested feature
parser.add_argument('--pcap-dump', help='Dump packets on interfaces to pcap files',
                    type=str, action="store", required=False, default=False)

#TODO: Not tested feature
parser.add_argument('--enable-debugger', help='Enable behavioral model debugger (Please ensure debugger support is enabled in behavioral exe, as it is disabled by default)',
                    action="store_true", required=False, default=False)

parser.add_argument('--controller', help='Controller to use, only ONOS tested', type=str,
                    choices=['onos', 'external'], required=False, action="store")

parser.add_argument('--controler-debug', help='Enable debugger for controller',
                    action="store_true", required=False, default=False)

parser.add_argument('--reports', help='Report collector IP:PORT',
                    type=str, action="store", required=False)

args = parser.parse_args()












def getFileTopology(File):
    """
    Reads a file containing the topology and extracts the data.

    TODO: Right now it is a file with lists containing nodes, switches and links.
    It may be better to use a JSON file format to add specific parameters to each node,
        such as IP, MAC, etc.
    """
    hosts = []
    leaf_switches = []
    spine_switches = []
    leaf_links = []
    spine_links = []
    containers = []

    # Open and read the file
    with open(File, 'r') as file:
        for line in file:
            # Remove whitespace and newline characters
            line = line.strip()

            # Skip comments and empty lines
            if line.startswith('#') or not line:
                continue
            
            # Extract data based on the prefix
            if line.startswith('H='):
                hosts = eval(line[2:])
            elif line.startswith('LS='):
                leaf_switches = eval(line[3:])
            elif line.startswith('SS='):
                spine_switches = eval(line[3:])
            elif line.startswith('LL='):
                leaf_links = eval(line[3:])
            elif line.startswith('SL='):
                spine_links = eval(line[3:])
            elif line.startswith('C'):
                containers = eval(line[2:])
                #break

    # Print the extracted data
    print("Hosts:", hosts)
    print("Containers:", containers)
    print("Leaf Switches:", leaf_switches)
    print("Spine Switches:", spine_switches)
    print("Leaf Links:", leaf_links)
    print("Spine Links:", spine_links)

    return {'hosts': hosts, 'containers': containers, 'leaf_switches': leaf_switches, 'spine_switches': spine_switches, 'leaf_links': leaf_links, 'spine_links': spine_links}



def main():
    num_hosts = args.num_hosts
    mode = args.mode
    controller=args.controller
    reportCollector=args.reports



    #old topology call
    #topo = SingleSwitchTopo(args.behavioral_exe,
    #                        args.json,
    #                        args.thrift_port,
    #                        args.pcap_dump,
    #                        args.enable_debugger,
    #                        num_hosts)
    #topo = Containernet(
    #    host = P4Host,
    #    switch = StratumBmv2DockerSwitch,
    #    controller=None)


    topo = None
    
    try:
        #Limited to 65534 hosts
        topology_config = getFileTopology(args.topo_file)
        if len(topology_config['hosts']) > pow(2,16)-2:
            raise AssertionError(f"Can't launch more than {pow(2,16)-2} hosts")
    except AssertionError as e:
        print(e) 
        exit(0)

    
    

    if controller is not None:
        if controller == "onos":
            print("Controller ONOS selected")
            launchController = dockerOnos(name="onos_controller", 
                                  dimage="onosproject/onos:2.7.0", 
                                  ports=[6640, 6653, 8101, 8181, 9876, 5005],
                                  port_bindings={'6640/tcp':'6640','6653/tcp':'6653','8101/tcp':'8101','8181/tcp':'8181','9876/tcp':'9876','5005/tcp':'5005'}, 
                                  environment={"ONOS_APPS": "org.onosproject.drivers.bmv2,org.onosproject.pipelines.basic,org.onosproject.hostprovider,\
                                               org.onosproject.lldpprovider,org.onosproject.linkdiscovery,org.onosproject.proxyarp,\
                                               org.onosproject.hostprobingprovider,org.onosproject.drivers.p4runtime,org.onosproject.drivers.stratum,\
                                               org.onosproject.drivers,org.onosproject.gui2,org.customPipeline.app,org.mecp4.app", 
                                               "JAVA_DEBUG_PORT":"0.0.0.0:5005",
                                               "debug":"true"},
                                 
                                  privileged=True, 
                                  cgroup_parent="docker.slice", 
                                  volumes=[
                                            #Mount ONOS applications. app.xml and oar file is needed for each application
                                            #mecp4 for forwarding
                                            ONOS_LOCAL_APPS_DIRECTORY+"mecp4app"+"/target/oar/app.xml"+":"+ONOS_DOCKER_APPS_DIRECTORY+"org.mecp4.app/app.xml"+":rw",
                                            ONOS_LOCAL_APPS_DIRECTORY+"mecp4app"+"/target/mecp4-1.0-SNAPSHOT.oar"+":"+ONOS_DOCKER_APPS_DIRECTORY+"org.mecp4.app/mecp4-1.0-SNAPSHOT.oar"+":rw",
                                            os.getcwd()+"/controller/mecp4app/target/oar/m2/mecp4:/root/onos/apache-karaf-4.2.9/system/mecp4"+":rw",

                                            #customPipeline for integration with controller, and INT
                                            ONOS_LOCAL_APPS_DIRECTORY+"customPipeline"+"/target/oar/app.xml"+":"+ONOS_DOCKER_APPS_DIRECTORY+"org.customPipeline.app/app.xml"+":rw",
                                            ONOS_LOCAL_APPS_DIRECTORY+"customPipeline"+"/target/customPipeline-1.0-SNAPSHOT.oar"+":"+ONOS_DOCKER_APPS_DIRECTORY+"org.customPipeline.app/customPipeline-1.0-SNAPSHOT.oar"+":rw",
                                            os.getcwd()+"/controller/customPipeline/target/oar/m2/customPipeline:/root/onos/apache-karaf-4.2.9/system/customPipeline"+":rw",
                                            
                                            ONOS_LOCAL_APPS_DIRECTORY+"org.apache.karaf.features.cfg"+":/root/onos/apache-karaf-4.2.9/etc/org.apache.karaf.features.cfg:rw"
                                        ])
            
            launchController.start()
            if(launchController.isStarted(8181)):
                pass
            else:
                print("Controller not started")
                return
                           

    topo = MECTopo(topology=topology_config, 
                    controllerAddress=(CONTROLLER_ADDRESS if controller is not None else None),
                    collectorAddress=reportCollector,
                    switch=StratumBmv2DockerSwitch,
                    HostCls=Host)

    topo.addController('c0', controller=RemoteController, ip=CONTROLLER_ADDRESS, port=8181)
    
    try:
        topo.start()

        sleep(1)

        if reportCollector:
            topo.collector.start()

        for host in topo.hosts:
            print(" " + host.name)
            host.cmd("hostname")
            host.cmd("arping -c 10 -A -I eth0 $(hostname -I) &") #Gratuitous ARP for host detection by network topology
            #host.start()



        print("Ready !")

        CLI( topo )


    except Exception as e:
        print(e)
    finally:
        topo.stop()


    if controller != None and controller != "external":
        launchController.stop()


    '''
    sw_mac = ["00:aa:bb:00:00:%02x" % n for n in range(num_hosts)]

    sw_addr = ["10.0.%d.1" % n for n in range(num_hosts)]

    for n in range(num_hosts):
        h = net.get('h%d' % (n + 1))
        if mode == "l2":
            h.setDefaultRoute("dev eth0")
        else:
            h.setARP(sw_addr[n], sw_mac[n])
            h.setDefaultRoute("dev eth0 via %s" % sw_addr[n])

    for n in range(num_hosts):
        h = net.get('h%d' % (n + 1))
        h.describe()
    '''

if __name__ == '__main__':
    setLogLevel( 'info' )

    main()

   

