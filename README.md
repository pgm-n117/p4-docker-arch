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

Finish installation of Containernet on a python virtual environment

```
python3 -m venv venv
source venv/bin/activate
pip install -e . --no-binary :all:
```

And then exit the venv with ```deactivate```

