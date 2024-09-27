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
from time import sleep
import re



class DockerSwitch(Docker, Switch):
    """

    """

    def __init__(self, name,
                 dimage=None,
                 dcmd=None, 
                 build_params={},
                 **kwargs):
        

        """
        Check Docker from containernet node.py/Docker class for more information
        Necessary parameters:
            - dimage: Docker image
            - dcmd: Docker command (Default: None)
            - build_params: build parameters
        """
        self.dimage = dimage
        self.dnameprefix = "mn"
        self.dcmd = dcmd if dcmd is not None else "/bin/bash"
        self.dc = None  # pointer to the dict containing 'Id' and 'Warnings' keys of the container
        self.dcinfo = None
        self.did = None # Id of running container
        #  let's store our resource limits to have them available through the
        #  Mininet API later on
        defaults = { 'cpu_quota': None,
                     'cpu_period': None,
                     'cpu_shares': None,
                     'cpuset_cpus': None,
                     'mem_limit': None,
                     'memswap_limit': None,
                     'environment': {},
                     'volumes': [],  # use ["/home/user1/:/mnt/vol2:rw"]
                     'tmpfs': [], # use ["/home/vol1/:size=3G,uid=1000"]
                     'network_mode': None,
                     'publish_all_ports': True,
                     'port_bindings': {},
                     'ports': [],
                     'dns': [],
                     'ipc_mode': None,
                     'devices': [],
                     'cap_add': ['net_admin'],  # we need this to allow mininet network setup
                     'storage_opt': None,
                     'sysctls': {},
                     'shm_size': '64mb',
                     'cpus': None,
                     'device_requests': [],
                     'cgroup_parent':'/docker', #default cgroup parent ###NIKSS change needed
                     'privileged':True ###NIKSS change needed
                     }
        defaults.update( kwargs )

        if 'net_admin' not in defaults['cap_add']:
            defaults['cap_add'] += ['net_admin']  # adding net_admin if it's cleared out to allow mininet network setup

        # keep resource in a dict for easy update during container lifetime
        self.resources = dict(
            cpu_quota=defaults['cpu_quota'],
            cpu_period=defaults['cpu_period'],
            cpu_shares=defaults['cpu_shares'],
            cpuset_cpus=defaults['cpuset_cpus'],
            mem_limit=defaults['mem_limit'],
            memswap_limit=defaults['memswap_limit']
        )
        self.shm_size = defaults['shm_size']
        self.nano_cpus = defaults['cpus'] * 1_000_000_000 if defaults['cpus'] else None
        self.device_requests = defaults['device_requests']
        self.volumes = defaults['volumes']
        self.tmpfs = defaults['tmpfs']
        self.environment = {} if defaults['environment'] is None else defaults['environment']
        # setting PS1 at "docker run" may break the python docker api (update_container hangs...)
        # self.environment.update({"PS1": chr(127)})  # CLI support
        self.network_mode = defaults['network_mode']
        self.publish_all_ports = defaults['publish_all_ports']
        self.port_bindings = defaults['port_bindings']
        self.dns = defaults['dns']
        self.ipc_mode = defaults['ipc_mode']
        self.devices = defaults['devices']
        self.cap_add = defaults['cap_add']
        self.sysctls = defaults['sysctls']
        self.storage_opt = defaults['storage_opt']
        self.cgroup_parent = defaults['cgroup_parent'] ###NIKSS change needed
        self.privileged = defaults['privileged'] ###NIKSS change needed

        # setup docker client
        # self.dcli = docker.APIClient(base_url='unix://var/run/docker.sock')
        self.d_client = docker.from_env()
        self.dcli = self.d_client.api

        _id = None
        if build_params.get("path", None):
            if not build_params.get("tag", None):
                if dimage:
                    build_params["tag"] = dimage
            _id, output = self.build(**build_params)
            dimage = _id
            self.dimage = _id
            info("Docker image built: id: {},  {}. Output:\n".format(
                _id, build_params.get("tag", None)))
            info(output)

        # pull image if it does not exist
        self._check_image_exists(dimage, True, _id=None)

        # for DEBUG
        debug("Created docker container object %s\n" % name)
        debug("image: %s\n" % str(self.dimage))
        debug("dcmd: %s\n" % str(self.dcmd))
        info("%s: kwargs %s\n" % (name, str(kwargs)))

        # creats host config for container
        # see: https://docker-py.readthedocs.io/en/stable/api.html#docker.api.container.ContainerApiMixin.create_host_config
        hc = self.dcli.create_host_config(
            network_mode=self.network_mode,
            privileged=self.privileged, #NIKSS change needed, originally False
            binds=self.volumes,
            tmpfs=self.tmpfs,
            publish_all_ports=self.publish_all_ports,
            port_bindings=self.port_bindings,
            mem_limit=self.resources.get('mem_limit'),
            cpuset_cpus=self.resources.get('cpuset_cpus'),
            dns=self.dns,
            ipc_mode=self.ipc_mode,  # string
            devices=self.devices,  # see docker-py docu
            cap_add=self.cap_add,  # see docker-py docu
            sysctls=self.sysctls,   # see docker-py docu
            storage_opt=self.storage_opt,
            # Assuming Docker uses the cgroupfs driver, we set the parent to safely
            # access cgroups when modifying resource limits.
            cgroup_parent=self.cgroup_parent, ###NIKSS change needed
            #cgroup_parent='/docker',
            shm_size=self.shm_size,
            nano_cpus=self.nano_cpus,
            device_requests=self.device_requests,


        )

        if kwargs.get("rm", False):
            container_list = self.dcli.containers(all=True)
            for container in container_list:
                for container_name in container.get("Names", []):
                    if "%s.%s" % (self.dnameprefix, name) in container_name:
                        self.dcli.remove_container(container="%s.%s" % (self.dnameprefix, name), force=True)
                        break

        # create new docker container
        self.dc = self.dcli.create_container(
            name="%s.%s" % (self.dnameprefix, name),
            image=self.dimage,
            command=self.dcmd,
            entrypoint=list(),  # overwrite (will be executed manually at the end)
            stdin_open=True,  # keep container open
            tty=True,  # allocate pseudo tty
            environment=self.environment,
            #network_disabled=True,  # docker stats breaks if we disable the default network
            host_config=hc,
            ports=defaults['ports'],
            labels=['com.containernet'],
            volumes=[self._get_volume_mount_name(v) for v in self.volumes if self._get_volume_mount_name(v) is not None],
            hostname=name,
        )

        # start the container
        self.dcli.start(self.dc)
        debug("Docker container %s started\n" % name)

        # fetch information about new container
        self.dcinfo = self.dcli.inspect_container(self.dc)
        self.did = self.dcinfo.get("Id")

        # call original Switch.__init__
        Switch.__init__(self, name, **kwargs)


        self.managementAddress = None
        """Switch management IP address is the same as the container IP address, used to connect to controller or manage tables
        """
        self.dataLinks = None
        """List of interfaces that are used to connect to other switches or hosts
        """


    def check_docker_switch_started(self, pid, grpc_port=None):
        """Check if the Docker container is running. Check if the switch
        is running (pid exists). Finally, check if the interfaces are up.

        Args:
            pid (int): Process ID of the switch.
            grpc_port ([int]): List of Port number of the gRPC server or other services to be checked.
        """
        
        #check if the container is running
        if not self.dcinfo["State"]["Status"] == "running":
            raise Exception("Container {} is not running.\n".format(self.name))
            return False
        
        #check if the bmv program is running
        if not self.cmd( 'ls ' + os.path.join("/proc", str(pid)) ):
            raise Exception("BMV program or software switch binary is not running.\n")
            return False
        
        #check if the bmv program port is used (thrift server, P4Runtime, gRPC...)
        if grpc_port is not None:
            for port in grpc_port:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    sleep(3)
                    sock.settimeout(0.5)
                    ip_addrs = self.cmd("hostname -I").rstrip()
                    result = sock.connect_ex((ip_addrs, port))
                finally:
                    sock.close()
                if result != 0:
                    raise Exception("Remote control port {} is not open in {}.\n".format(port, self.name))
                    return  False
        
        #check if the interfaces were correctly set up. Loopback is not necessary to be checked
        #eth0 is not listed on the mininet interface list (and not necessary to be checked), 
        #but it is the interface used to connect with the host
        links = self.intfList()
        links.remove(self.intf("lo"))
        for intf in links:
            #check if interfaces are up, and if they are not, bring them up
            intfstate = self.cmd("ip link show {}".format(intf.name)).split()[8]
            if intfstate not in ('UP','LOWERLAYERDOWN'):
                raise Exception("Interface {} is down.\n".format(intf.name))
                return False 
        
        return True
    
    def getSourceIp(self, dstIP):
        """
        #TODO Check this function
        From ONOS BMV2 switch example. https://github.com/opennetworkinglab/onos/blob/dd5172e5a6e1ba5c7e17e2f497aa8c27a1ed33e9/tools/dev/mininet/bmv2.py

        Queries the Linux routing table to get the source IP that can talk with
        dstIP, and vice versa.
        """
        ipRouteOut = self.cmd('ip route get %s' % dstIP)
        r = re.search(r"src (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", ipRouteOut)
        return r.group(1) if r else None
            

    def set_up_interfaces(self):
        """Set up the interfaces of the Docker container.
        """
        #INTERFACES MUST DEFINITELY BE UP, AS THEY ARE NOT ADDED TO THE SWITCH CONFIGURATION
        # This is necessary, because the interfaces are not active on containers even 
        # if they are added on the mininet script
        links = self.intfList()
        links.remove(self.intf("lo"))
        self.dataLinks = links
        for intf in links:
            #bring interfaces up
            self.cmd("ip link set {} up".format(intf.name))

        #Try to obtain the IP address of the eth0 interface
        self.managementAddress = self.cmd("hostname -I").rstrip()



    def pathCheck(self, *args, **kwargs):
        "Make sure each program in *args can be found in $PATH."
        moduleName = kwargs.get( 'moduleName', 'it' )
        for arg in args:
            if not self.cmd( 'which ' + arg ):
                error( 'Cannot find required executable %s.\n' % arg +
                    'Please make sure that %s is installed ' % moduleName +
                    'and available in your $PATH:\n(%s)\n' % environ[ 'PATH' ] )
                exit( 1 )
    def fileCheck(self, *args):
        "Make sure that a file exists."
        for arg in args:
            if not self.cmd( 'ls ' + arg ):
                error( 'Cannot find required file %s.\n' % arg )
                exit( 1 )


    def start(self):
        """Override start method with specific code"""

    def stop(self):
        """Override stop method with specific code"""
                