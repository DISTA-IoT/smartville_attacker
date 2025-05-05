FROM ubuntu:focal

RUN     apt-get -y update && \
        apt-get -y upgrade

# dependencies of TCP Replay
RUN     apt-get -y --force-yes install \
        wget curl build-essential tcpdump tcpreplay

RUN apt-get install -y python3 python3-pip netcat wget\
    net-tools iputils-ping  tcpdump && \
    rm -rf /var/lib/apt/lists/*

RUN     apt-get clean && \
        rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*


RUN pip3 install --upgrade pip

RUN pip3 install -r requirements.txt

RUN apt-get update && apt-get install -y git && \
        rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/DISTA-IoT/smartville_attacker.git attacker

WORKDIR /attacker

RUN pip install -r requirements.txt

