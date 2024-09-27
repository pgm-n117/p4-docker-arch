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

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
import os
from nodes.p4_mininet import P4Switch, P4Host
from nodes.dswitch.bmv2.BMV2_containernet import BMV2DockerSwitch
from nodes.dswitch.stratum_bmv2.stratum_containernet import StratumBmv2DockerSwitch

import argparse
from time import sleep


#TODO: Rethink input parameters for building the topology, in order to be generic for different switches.
parser = argparse.ArgumentParser(description='Mininet demo')
parser.add_argument('--behavioral-exe', help='Path to behavioral executable',
                    type=str, action="store", required=True)
parser.add_argument('--thrift-port', help='Thrift server port for table updates',
                    type=int, action="store", default=9090)
parser.add_argument('--num-hosts', help='Number of hosts to connect to switch',
                    type=int, action="store", default=2)
parser.add_argument('--mode', choices=['l2', 'l3'], type=str, default='l3')
parser.add_argument('--json', help='Path to JSON config file',
                    type=str, action="store", required=True)
parser.add_argument('--pcap-dump', help='Dump packets on interfaces to pcap files',
                    type=str, action="store", required=False, default=False)
parser.add_argument('--enable-debugger', help='Enable debugger (Please ensure debugger support is enabled in behavioral exe, as it is disabled by default)',
                    action="store_true", required=False, default=False)

args = parser.parse_args()


class SingleSwitchTopo(Topo):
    "Single switch connected to n (< 256) hosts."

    def __init__(self, sw_path, json_path, thrift_port, pcap_dump, enable_debugger, n, **opts):
        """Parameters
        - sw_path: path to the behavioral executable, --behavioral-exe. Default location of binaries on the container is /usr/local/bin, where i.e. simple_switch is located.
        - json_path: path to the JSON P4 compiled file, --json
        - thrift_port: thrift server port for table updates, --thrift-port
        - pcap_dump: dump packets on interfaces to pcap files, --pcap-dump
        - enable_debugger: enable debugger, --enable-debugger
        - n: number of hosts to connect to switch, --num-hosts
        
        IMPORTANT: Keep in mind that paths to executables and JSON files are relative to the container, not the host.
        """

        # Initialize topology and default options
        Topo.__init__(self, **opts)

        bmv2_opts={'sw_path': sw_path,
                   'thrift_port': thrift_port,
                   'pcap_dump': pcap_dump,
                   'enable_debugger': enable_debugger}
        
        rootsw = self.addSwitch('s01',
                                #opts=bmv2_opts, 
                                json_path=json_path,
                                #Docker parameters
                                dcmd="/bin/bash", 
                                volumes=[f"{os.getcwd()}:/bmv2"], 
                                privileged=True, 
                                cgroup_parent="docker.slice",
                                controllerAddress = "172.17.0.2")
        
        #s1 = self.addSwitch('s1',
        #                        #opts=bmv2_opts, 
        #                        json_path=json_path,
        #                        #Docker parameters
        #                        dcmd="/bin/bash", 
        #                        volumes=[f"{os.getcwd()}:/bmv2"], 
        #                        privileged=True, 
        #                        cgroup_parent="docker.slice")
        
        #s2 = self.addSwitch('s2',
        #                #opts=bmv2_opts, 
        #                json_path=json_path,
        #                #Docker parameters
        #                dcmd="/bin/bash", 
        #                volumes=[f"{os.getcwd()}:/bmv2"], 
        #                privileged=True, 
        #                cgroup_parent="docker.slice")

        #Add stratum_containernet switch
        #switch = self.addSwitch('s1',
        #                        dcmd="/bin/bash", 
        #                        volumes=[f"{os.getcwd()}:/bmv2"], 
        #                        privileged=True, 
        #                        cgroup_parent="docker.slice",
        #                        json=json_path)


        for h in range(n):
            host = self.addHost('h%d' % (h + 1),
                                ip = "10.0.%d.10/24" % h,
                                mac = '00:04:00:00:00:%02x' %h)
            
            switch = self.addSwitch('s%d' % (h + 1),
                                #opts=bmv2_opts, 
                                json_path=json_path,
                                #Docker parameters
                                dcmd="/bin/bash", 
                                volumes=[f"{os.getcwd()}:/bmv2"], 
                                privileged=True, 
                                cgroup_parent="docker.slice",
                                controllerAddress = "172.17.0.2")


            self.addLink(host, switch)
            self.addLink(switch, rootsw)

def main():
    num_hosts = args.num_hosts
    mode = args.mode

    topo = SingleSwitchTopo(args.behavioral_exe,
                            args.json,
                            args.thrift_port,
                            args.pcap_dump,
                            args.enable_debugger,
                            num_hosts)
    

    net = Mininet(topo = topo,
                  host = P4Host,
                  switch = StratumBmv2DockerSwitch,
                  controller = None)
    net.start()


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

    sleep(1)

    print("Ready !")

    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    main()

