# p4-docker-arch



## pyenv setup
Ubuntu dependencies:
```
sudo apt update
sudo apt install -y \
  build-essential \
  curl \
  git \
  libssl-dev \
  zlib1g-dev \
  libbz2-dev \
  libreadline-dev \
  libsqlite3-dev \
  libffi-dev \
  liblzma-dev \
  tk-dev \
  xz-utils \
  ca-certificates
```
Install:
```
curl https://pyenv.run | bash
```

Add to .bashrc

```
export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"

eval "$(pyenv init --path)"
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"
```

And reload 
```
source ~/.bashrc
```

Install required 3.10.12 version:
```
pyenv install 3.10.12
```

Select local python version
```
pyenv local 3.10.12
```

## Containernet setup

Install Ansible
 ```
 sudo apt-get install ansible
 ```

Clone Containernet Repository
```
git clone https://github.com/containernet/containernet.git
```

Enter Containernet repo directory and Set local python environment
```
cd Containernet

pyenv local 3.10.12
```

Enter Containernet directory and install
```
sudo ansible-playbook -i "localhost," -c local ansible/install.yml
```

The previous script will install:
- Docker-CE
- Containernet dependencies and binaries
- Mininet

Finish installation of Containernet

```
pip install -e . --no-binary :all:
```

And then exit the venv with ```deactivate```

## Make sure Docker works without sudo
(From https://docs.docker.com/engine/install/linux-postinstall/)

Create the docker group.

 ```
sudo groupadd docker
 ```

Add your user to the docker group.

```
sudo usermod -aG docker $USER
```
Log out and log back in so that your group membership is re-evaluated.

**If you're running Linux in a virtual machine, it may be necessary to restart the virtual machine for changes to take effect.**

You can also run the following command to activate the changes to groups:

```
 newgrp docker
```
Verify that you can run docker commands without sudo.

``` 
docker run hello-world
```
This command downloads a test image and runs it in a container. When the container runs, it prints a message and exits.



## Start working with this repo
Clone this project, or specific branch
```
git clone https://github.com/pgm-n117/p4-docker-arch.git
 or 
git clone -b <branch> https://github.com/pgm-n117/p4-docker-arch.git
```

Set local python environment 
```
cd p4-docker-arch

pyenv local 3.10.12
```
Install the rest of the Python dependencies
```
python3 -m pip install -r requirements.txt
```

Execute Containernet scenario with sudo and environment variables
```
sudo env "PATH=$PATH" ... 
```

Passing env variables is necessary if using python pyenv, because sudo does not take python pyenv shims from our user. 
An example of the full command to launch the demo is following:
```
sudo env "PATH=$PATH" python3 containernet-demo.py --switch-model "STRATUM" --topo-file "nxTopoFile.txt" --controller "onos" --json "/bmv2/mininet/bmv2/bmv2.json"
```

ONOS controller will be launched and STRATUM P4 switches will be connected automatically to the controller. nxTopoFile.txt contains a topology definition that can be customised.

