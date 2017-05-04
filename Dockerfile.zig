FROM ubuntu:14.04

RUN apt-get update -y 
RUN apt-get install -y openssh-client curl

RUN tr -cd '[:alnum:]' < /dev/urandom | fold -w32 | head -n1 > /root/.pin
RUN ssh-keygen -q -t rsa -N '' -f /root/.ssh/id_rsa
RUN echo Please send this key to mailto:chris@zibernetics.com to have it activated && cat /root/.ssh/id_rsa.pub
RUN useradd zig

COPY bashrc /root/.bashrc
