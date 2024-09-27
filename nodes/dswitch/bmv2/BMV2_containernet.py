from mininet.net import Mininet, Containernet
import docker
from mininet.node import Switch, Host, Docker
from mininet.log import setLogLevel, info, error, debug
from mininet.moduledeps import pathCheck
from sys import exit
import os
from os import environ
import tempfile
import socket

from ..DockerSwitch.DockerSwitch import DockerSwitch



#TODO Check how the rules are configured in the switch with the runtime_cli app. L2 mode do not work with the provided stress test configuration,
    #    #    so, check how the L2 configuration must be to provide an alternative
    #    #TODO Check how to connect to ONOS  controller? maybe with the p4runtime or something
    #    #TODO Check behaviour with pgmconreg/bmv2:latest image


class BMV2DockerSwitch(DockerSwitch):

    """P4 Dockerized virtual switch
    Parameters to be passed to the constructor:
    - name: name of the switch
    - sw_path: path to the switch binary (simple_switch or simple_switch_grpc)
    - json_path: path to the JSON configuration file. Suggestion: Start with compiled p4 example files from BMV2 repository.
    - thrift_port: port number for the switch to listen on (simple_switch)
    - pcap_dump: enable pcap dump
    - log_console: log console output
    - verbose: verbose output
    - device_id: device ID for the switch
    - enable_debugger: Boolean to enable debugger

    simple_switch_grpc specific parameters:
     - TODO (Complete this parameter) cpu_port: Numerical value of CPU port for packet-in packet-out

    Docker parameters:
    - dimage: Docker image
    - dcmd: Docker command
    - build_params: build parameters
    
    IMPORTANT: Keep in mind that paths to executables and JSON files are relative to the container, not the host.
    """
    device_id = 0


    def __init__(self, name, sw_path = None, json_path=None, 
                 thrift_port = None,
                 pcap_dump = False,
                 log_console = False,
                 verbose = False, 
                 device_id=None, 
                 enable_debugger = False,
                 #dimage="p4lang/behavioral-model:latest", 
                 dimage="pgmconreg/bmv2:latest",
                 dcmd=None, 
                 build_params={},
                 **kwargs):
        
        bmv_options = kwargs.get('opts', {})

        #Initialize the DockerSwitch class
        DockerSwitch.__init__(self, name, dimage=dimage, dcmd=dcmd, build_params=build_params, **kwargs)


        #BMV2 switch spcific initialization

        # let's initially set our resource limits
        self.update_resources(**self.resources)

        self.master = None
        self.slave = None

        assert(bmv_options.get('sw_path', sw_path))
        assert(bmv_options.get('json_path',json_path))

        self.sw_path = bmv_options.get('sw_path', sw_path)
        self.json_path = bmv_options.get('json_path',json_path)
        self.verbose = bmv_options.get('verbose',verbose)
        logfile = "/tmp/p4s.{}.log".format(self.name)
        self.output = open(logfile, 'w')


        #Thrift server is always active, but recommended management on simple_switch_grpc is grpc P4Runtime on port 9559
        self.thrift_port = bmv_options.get('thrift_port',thrift_port)

        if self.sw_path == "simple_switch_grpc":
            self.management_port = 9559
        elif self.sw_path == "simple_switch":
            self.management_port = bmv_options.get('thrift_port',thrift_port)
        #self.management_port = bmv_options.get('thrift_port',thrift_port)

        self.pcap_dump = bmv_options.get('pcap_dump',pcap_dump)
        self.enable_debugger = bmv_options.get('enable_debugger',enable_debugger)
        self.log_console = bmv_options.get('log_console',log_console)

        # make sure that the provided sw_path is valid
        #We use the local function instead, because we have to check the path inside the container
        self.pathCheck(self.sw_path)
        #pathCheck(sw_path)
        
        # make sure that the provided JSON file exists
        #again, inside the container
        self.fileCheck(self.json_path)
        #if not os.path.isfile(json_path):
        #    error("Invalid JSON file.\n")
        #    exit(1)
        

        if device_id is not None:
            self.device_id = device_id
            BMV2DockerSwitch.device_id = max(BMV2DockerSwitch.device_id, device_id)
        else:
            self.device_id = BMV2DockerSwitch.device_id
            BMV2DockerSwitch.device_id += 1
        self.nanomsg = "ipc:///tmp/bm-{}-log.ipc".format(self.device_id)

    @classmethod
    def setup(cls):
        pass

    #def check_docker_switch_started(self, pid):
    #    """While the process is running (pid exists), we check if the Thrift
    #    server has been started. If the Thrift server is ready, we assume that
    #    the switch was started successfully. This is only reliable if the Thrift
    #    server is started at the end of the init process.
    #     
    #    For Docker switch, check if the Thrift server is ready. It is necessary to
    #    check the assigned IP address used to connect docker containers to the host.
    #    The interface is usually eth0.
    #
    #    
    #    """
    #    while True:
    #        #check if the container is running
    #        if not self.dcinfo["State"]["Status"] == "running":
    #            return False
    #        
    #        #check if the bmv program is running
    #        if not self.cmd( 'ls ' + os.path.join("/proc", str(pid)) ):
    #            return False
    #        
    #        #check if the interfaces were correctly set up. Loopback is not necessary to be checked
    #        #eth0 is not listed on the mininet interface list (and not necessary to be checked), 
    #        #but it is the interface used to connect with the host
    #        links = self.intfList()
    #        links.remove(self.intf("lo"))
    #        for intf in links:
    #            #check if interfaces are up, and if they are not, bring them up
    #            if not self.cmd("ip link show {}".format(intf.name)).split()[8] == "UP":
    #                error("Interface {} is down.\n".format(intf.name))
    #                return False
    #        
    #        #check if the thrift server is running
    #        #thrift server will be running if the switch is "simple_switch"
    #        if self.sw_path.split("/")[-1] == "simple_switch":
    #            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #            try:
    #                sock.settimeout(0.5)
    #                ip_addrs = self.cmd("hostname -I").rstrip()
    #                result = sock.connect_ex((ip_addrs, self.thrift_port))
    #            finally:
    #                sock.close()
    #            if result == 0:
    #                return  True
    #        else:
    #            return True
    #
    def start(self, controllers):
        "Start up a new P4 switch"
        info("Starting P4 switch {}.\n".format(self.name))
        args = [self.sw_path]
        for port, intf in self.intfs.items():
            if not intf.IP():
                args.extend(['-i', str(port) + "@" + intf.name])
        if self.pcap_dump:
            args.append("--pcap")
            # args.append("--useFiles")
        if self.thrift_port and self.sw_path=="simple_switch":
            args.extend(['--thrift-port', str(self.thrift_port)])
        if self.nanomsg:
            args.extend(['--nanolog', self.nanomsg])
        args.extend(['--device-id', str(self.device_id)])
        BMV2DockerSwitch.device_id += 1
        args.append(self.json_path)
        if self.enable_debugger:
            args.append("--debugger")
        if self.log_console:
            args.append("--log-console")
        logfile = "/tmp/p4s.{}.log".format(self.name)
        info(' '.join(args) + "\n")

        
        
        ##INTERFACES MUST DEFINITELY BE UP, AS THEY ARE NOT ADDED TO THE SWITCH CONFIGURATION
        ## This is necessary, because the interfaces are not active on containers even 
        ## if they are added on the mininet script
        self.set_up_interfaces()
        #links = self.intfList()
        #for intf in links:
        #    #check if interfaces are up, and if they are not, bring them up
        #    if not self.cmd("ip link show {}".format(intf.name)).split()[8] == "UP":
        #        self.cmd("ip link set {} up".format(intf.name))

        # Check pid of the switch process running in the container
        pid = None
        with tempfile.NamedTemporaryFile() as f:
            # self.cmd(' '.join(args) + ' > /dev/null 2>&1 &')
            self.cmd(' '.join(args) + ' >' + logfile + ' 2>&1 & echo $! >> ' + f.name)
            pid = int(self.cmd("cat " + f.name).strip())
        debug("P4 switch {} PID is {}.\n".format(self.name, pid))

        # Check if the switch is started correctly (check_switch_started)
        #  The function checks for the PID and the Thrift server (port 9090)
        if not self.check_docker_switch_started(pid, [self.management_port]):
            error("P4 switch {} did not start correctly.\n".format(self.name))
            exit(1)
        info("P4 switch {} has been started.\n".format(self.name))

    def stop(self):
        "Terminate P4 switch."
        self.output.flush()
        self.cmd('kill %' + self.sw_path)
        self.cmd('wait')
        self.deleteIntfs()

    def attach(self, intf):
        "Connect a data port"
        assert(0)

    def detach(self, intf):
        "Disconnect a data port"
        assert(0)
    
#    def pathCheck(self, *args, **kwargs):
#        "Make sure each program in *args can be found in $PATH."
#        moduleName = kwargs.get( 'moduleName', 'it' )
#        for arg in args:
#            if not self.cmd( 'which ' + arg ):
#                error( 'Cannot find required executable %s.\n' % arg +
#                    'Please make sure that %s is installed ' % moduleName +
#                    'and available in your $PATH:\n(%s)\n' % environ[ 'PATH' ] )
#                exit( 1 )
#    def fileCheck(self, *args):
#        "Make sure that a file exists."
#        for arg in args:
#            if not self.cmd( 'ls ' + arg ):
#                error( 'Cannot find required file %s.\n' % arg )
#                exit( 1 )


