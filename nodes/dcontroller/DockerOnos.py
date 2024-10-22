import docker
from sys import exit
import os
from os import environ
import tempfile
import socket
from time import sleep
import re

import urllib.error
import urllib.request
import urllib.response
import json


ONOS_WEB_USER = "onos"
ONOS_WEB_PASS = "rocks"



class DockerOnos():
    """

    """
    

    def __init__(self, name,
                 dimage=None,
                 dcmd=None, 
                 build_params={},
                 **kwargs):
        
        self.name=name
        self.dimage = dimage
        self.dnameprefix = ""
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
            print("Docker image built: id: {},  {}. Output:\n".format(
                _id, build_params.get("tag", None)))
            print(output)

        # pull image if it does not exist
        #self._check_image_exists(dimage, True, _id=None)
        
        self.dcli.pull(dimage)

        # for DEBUG
        print("Created docker container object %s\n" % name)
        print("image: %s\n" % str(self.dimage))
        print("dcmd: %s\n" % str(self.dcmd))
        print("%s: kwargs %s\n" % (name, str(kwargs)))






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
            name=name,
            image=self.dimage,
            #command=self.dcmd,
            #entrypoint=list(),  # overwrite (will be executed manually at the end)
            stdin_open=True,  # keep container open
            tty=True,  # allocate pseudo tty
            environment=self.environment,
            #network_disabled=True,  # docker stats breaks if we disable the default network
            host_config=hc,
            command="debug",
            ports=defaults['ports'],
            volumes=[self._get_volume_mount_name(v) for v in self.volumes if self._get_volume_mount_name(v) is not None],
            hostname=name,
        )



        # fetch information about new container
        #self.dcinfo = self.dcli.inspect_container(self.dc)
        #self.did = self.dcinfo.get("Id")





    def start(self):
        # start the container
        self.dcli.start(self.dc)

        #self.d_client.containers.run(*self.dc)
        print("Docker container %s started\n" % self.name)

    def isStarted(self, port):
        retries = 10
        socketResult=1
        connectionResult = False

        if port is not None:
            while (retries > 0 and (socketResult != 0 or connectionResult == False)):
                print("Waiting for controller to start. Retries left: %d\n" % retries)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    sleep(5)
                    sock.settimeout(0.5)
                    ip_addrs = self.d_client.containers.get(self.name).exec_run("hostname -I").output.decode().strip()
                    socketResult = sock.connect_ex((ip_addrs, port))
                    print("Socket Result: %d\n" % socketResult)


                    # Build netcfg URL
                    url = 'http://%s:8181/onos/v1/network/configuration/' % ip_addrs
                    # Instantiate password manager for HTTP auth
                    pm = urllib.request.HTTPPasswordMgrWithDefaultRealm()
                    pm.add_password(None, url, ONOS_WEB_USER, ONOS_WEB_PASS)
                    urllib.request.install_opener(urllib.request.build_opener(
                        urllib.request.HTTPBasicAuthHandler(pm)))
                    # Push config data to controller
                    #req = urllib.request.Request(url, {'Content-Type': 'application/json'})

                except Exception as e:
                    print(e.__str__())
                finally:
                    sock.close()

                #Test if web port is available (necessary to configure switches through REST API)
                f=None
                    
                try:
                    f = urllib.request.urlopen(url, data=None)
                except urllib.error.URLError as e:
                    print("Error connecting to controller port " + str(port) + ": " + "Status: "+ str(e.status) + " " +e.reason)
                finally:
                    print("Connection result: %s\n" % str(connectionResult))
                    if f is not None:
                        if f.getcode() == 200:
                            f.close()
                            connectionResult = True

                retries -= 1
                #if result != 0:
                #    raise Exception("Controller port {} is not open in {}.\n".format(port, self.name))
                #    return  False
                print("while conditions: Retries="+str(retries)+", Socket Result="+str(socketResult)+", Connection Result="+str(connectionResult))
        return bool(not socketResult) and connectionResult

    def stop(self):
        print("Stopping container %s\n" % self.name)
        self.dcli.remove_container(self.dc, force=True)
                