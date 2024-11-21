ARG PARENT_VERSION=latest
FROM ubuntu:22.04
LABEL maintainer="pgmconreg"
#TODO Build stratum from source on a recent OS version.
ARG stratum_bmv2_repo="git@github.com:stratum/stratum.git"

ENV DEPS wget \
            git \
            lcov \
            libgmp-dev \
            libpcap-dev \
            libboost-dev \
            libboost-program-options-dev \
            libboost-system-dev \
            libboost-filesystem-dev \
            libboost-thread-dev \
            libtool \
            pkg-config \
            ca-certificates
ENV RUNTIME_DEPS libboost-program-options1.62.0 \
                    libboost-system1.62.0 \
                    libboost-filesystem1.62.0 \
                    libboost-thread1.62.0 \
                    libgmp10 \
                    libpcap0.8 \
                    libjudydebian1 \
                    python3 \
                    iproute2 \
                    curl

#COPY . /stratum/
#WORKDIR /stratum/
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends $DEPS $RUNTIME_DEPS && \
    update-ca-certificates
 
RUN git clone ${stratum_bmv2_repo} /stratum && \
    cd /stratum
    
WORKDIR /stratum/
RUN bazel build 

RUN wget ${stratum_bmv2_binary} -O stratum-bmv2.deb && \
    wget ${stratum_tools_binary} -O stratum-tools.deb && \
    dpkg -i ./stratum-bmv2.deb && \
    dpkg -i ./stratum-tools.deb && \
    ldconfig

RUN rm -rf /stratum /var/cache/apt/* /var/lib/apt/lists/* && \
    echo 'Stratum image ready'

