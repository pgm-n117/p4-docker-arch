from mininet.topo import Topo
from mininet.node import RemoteController
from mininet.link import TCLink, Link, Intf
from mininet.net import Containernet, Docker
from .p4_mininet import P4Host

import os


class MECTopo(Containernet):
    "A MEC test topology of N network nodes (docker P4 containers) and M host nodes (i.e.: P4Host nodes)"
    def __init__(self, topology=None, controllerAddress=None, N=None, M=None, sw_path=None, json_path=None, **opts):
        """Parameters
        - sw_path: path to the behavioral executable, --behavioral-exe. Default location of binaries on the container is /usr/local/bin, where i.e. simple_switch is located.
        - json_path: path to the JSON P4 compiled file, --json
        - N: number of network nodes
        - M: number of host (MEC) nodes
        """
        Containernet.__init__(self, **opts)

        self.topology = topology
        self.controllerAddress = controllerAddress
        self.N = N
        self.M = M
        self.sw_path = sw_path
        self.json_path = json_path



        if topology is not None:
            self.buildFileTopology(topology)
            return
        
        #TODO: Implement the other methods to build the topology with N switches and M hosts
        # Maybe a "spiral" topology, where N = M-1, and there is 1 central switch. Think about it


    def buildFileTopology(self,topology):
        """
        Build the topology extracted from a file, in a dictionary format:
        {
            'hosts': [hosts], 
            'leaf_switches': [leaf_switches], 
            'spine_switches': [spine_switches], 
            'leaf_links': [leaf_links], 
            'spine_links': [spine_links]
        }
        """
        for index,host in enumerate(topology['hosts']):
            #same subnet
            h = self.addHost(host,
                        ip = "10.0.0.1%d/24" % index,
                        mac = '00:04:00:00:00:%02x' %index,
                        cls=P4Host)
            #.setDefaultRoute("dev eth0")
            
        for index,container in enumerate(topology['containers']):
            #Add host containers
            c = self.addDocker(container,
                            dcmd="/bin/sh",
                            privileged=True, 
                            cgroup_parent="docker.slice",
                            dimage="ubuntu:latest",
                            ip = "10.0.0.10%d/24" % index,
                            mac = '00:05:00:00:00:%02x' %index,
                            defaultRoute = "dev eth0")
               
        for index,switch in enumerate(topology['leaf_switches']):
            #Add stratum_containernet switch
            switch = self.addSwitch(switch,
                                    dcmd="/bin/bash", 
                                    volumes=[f"{os.getcwd()}:/bmv2"], 
                                    privileged=True, 
                                    cgroup_parent="docker.slice",
                                    controllerAddress=self.controllerAddress,
                                    #use 2 cpus from a total of 12, and the next 2 cpus for the next switch
                                    cpuset_cpus=str(index*2)+","+str(index*2+1))
                                    #cpuset_cpus=str(index)) #TODO: CHECK AND QUIT THIS
            
        for index,switch in enumerate(topology['spine_switches']):
            #Add stratum_containernet switch
            switch = self.addSwitch(switch,
                                    dcmd="/bin/bash", 
                                    volumes=[f"{os.getcwd()}:/bmv2"], 
                                    privileged=True, 
                                    cgroup_parent="docker.slice",
                                    controllerAddress=self.controllerAddress)
        
        for link in topology['leaf_links']:
            self.addLink(link[0], link[1], cls=Link)

        for link in topology['spine_links']:
            self.addLink(link[0], link[1], cls=Link)


    def newStratumSwitch():
        #return necessary parameters for addSwitch: switch,dcmd,volumes,privileged,cgroup_parent,controllerAddress
        pass

    def newBMV2Switch():
        #return necessary parameters for addSwitch
        pass

