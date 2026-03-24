FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y libpcap-dev gcc python3-dev iproute2 net-tools lldpd iputils-ping iputils-arping ethtool telnet socat psmisc&& \
    pip install scapy

COPY scapy_collector.py /app/scapy_collector.py
WORKDIR /app
CMD ["service lldpd start"]
#CMD ["python", "scapy_collector.py"]