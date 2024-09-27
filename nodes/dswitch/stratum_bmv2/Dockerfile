ARG PARENT_VERSION=latest
FROM ubuntu:18.04
LABEL maintainer="pgmconreg"

ARG stratum_bmv2_binary="https://github.com/stratum/stratum/releases/download/2022-06-30/stratum-bmv2-22.06-amd64.deb"
ARG stratum_tools_binary="https://github.com/stratum/stratum/releases/download/2022-06-30/stratum-tools-22.06-amd64.deb"

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

COPY . /stratum/
WORKDIR /stratum/
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends $DEPS $RUNTIME_DEPS && \
    update-ca-certificates
    
RUN wget ${stratum_bmv2_binary} -O stratum-bmv2.deb && \
    wget ${stratum_tools_binary} -O stratum-tools.deb && \
    dpkg -i ./stratum-bmv2.deb && \
    dpkg -i ./stratum-tools.deb && \
    ldconfig

RUN rm -rf /stratum /var/cache/apt/* /var/lib/apt/lists/* && \
    echo 'Stratum image ready'

